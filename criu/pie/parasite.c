#include <sys/mman.h>
#include <errno.h>
#include <signal.h>
#include <linux/limits.h>
#include <linux/capability.h>
#include <stdarg.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <linux/idxd.h>
#include <linux/memfd.h>
#include <linux/mman.h>

#include "linux/rseq.h"

#include "common/config.h"
#include "int.h"
#include "types.h"
#include <compel/plugins/std/syscall.h>
#include "linux/mount.h"
#include "parasite.h"
#include "fcntl.h"
#include "prctl.h"
#include "common/lock.h"
#include "parasite-vdso.h"
#include "criu-log.h"
#include "tty.h"
#include "aio.h"

#include "asm/parasite.h"
#include "restorer.h"
#include "infect-pie.h"

/*
 * PARASITE_CMD_DUMPPAGES is called many times and the parasite args contains
 * an array of VMAs at this time, so VMAs can be unprotected in any moment
 */
static struct parasite_dump_pages_args *mprotect_args = NULL;
static void *dsa_cached_shared_map = (void *)-1;
static u32 dsa_cached_shared_size;
static u64 dsa_cached_shared_map_size;
static int dsa_cached_wq_inited;
static int dsa_cached_wq_fds[DSA_DUMP_MAX_WQ];
static void *dsa_cached_wq_portals[DSA_DUMP_MAX_WQ];
static unsigned long dsa_cached_wq_portal_off[DSA_DUMP_MAX_WQ];
static char dsa_cached_wq_paths[DSA_DUMP_MAX_WQ][64];
static struct dsa_hw_desc dsa_copy_hw_descs[DSA_DUMP_BATCH_SIZE] __attribute__((aligned(64)));
static volatile struct dsa_completion_record dsa_copy_comps[DSA_DUMP_BATCH_SIZE] __attribute__((aligned(32)));
static u32 dsa_copy_lpt_order[DSA_DUMP_BATCH_SIZE];
static u32 dsa_copy_submitted_idx[DSA_DUMP_BATCH_SIZE];
static u32 dsa_copy_wq_idx[DSA_DUMP_BATCH_SIZE];

#ifndef SPLICE_F_GIFT
#define SPLICE_F_GIFT 0x08
#endif

#ifndef PR_GET_PDEATHSIG
#define PR_GET_PDEATHSIG 2
#endif

#ifndef PR_GET_TIMERSLACK
#define PR_GET_TIMERSLACK 30
#endif

#ifndef PR_GET_CHILD_SUBREAPER
#define PR_GET_CHILD_SUBREAPER 37
#endif

#ifndef MAP_POPULATE
#define MAP_POPULATE 0
#endif

#ifndef MAP_HUGE_SHIFT
#define MAP_HUGE_SHIFT 26
#endif

#ifndef MFD_HUGE_2MB
#define MFD_HUGE_2MB (21 << MAP_HUGE_SHIFT)
#endif

#define DSA_PORTAL_MAP_SIZE 0x1000UL
#define DSA_MAX_ENQ_RETRY   1000000U
#define HUGEPAGE_2MB_SIZE   (2UL * 1024UL * 1024UL)
#define DSA_DESC_PER_WQ     128U
#define DSA_PAGE_SIZE       4096U
#define DSA_FAULT_ADDR_MASKED 0x1U
#define DSA_FAULT_OPERAND_SHIFT 1U
#define DSA_FAULT_OPERAND_MASK 0x7U
#define DSA_FAULT_OPERAND_SRC 1U
#define DSA_FAULT_OPERAND_DST 3U

static inline unsigned long dsa_align_up(unsigned long x, unsigned long align)
{
	return (x + align - 1UL) & ~(align - 1UL);
}

static inline void dsa_memzero(void *ptr, unsigned long len)
{
	unsigned char *p = (unsigned char *)ptr;
	unsigned long i;

	for (i = 0; i < len; ++i)
		p[i] = 0;
}

static inline int dsa_enqcmd_local(void *portal_slot, const void *desc)
{
#if defined(__x86_64__)
	unsigned char retry = 0;

	asm volatile(
		"sfence\n\t"
		".byte 0xf2, 0x0f, 0x38, 0xf8, 0x02\n\t"
		"setz %0\n\t"
		: "=r"(retry)
		: "a"(portal_slot), "d"(desc)
		: "memory", "cc");

	return (int)retry;
#else
	(void)portal_slot;
	(void)desc;
	return 1;
#endif
}

static inline void dsa_cpu_relax(void)
{
#if defined(__x86_64__)
	asm volatile("pause" ::: "memory");
#else
	asm volatile("" ::: "memory");
#endif
}

static inline void dsa_prefault_range(uint8_t *buf, uint32_t len)
{
	uint32_t i;
	const uint32_t step = 4096;
	volatile uint8_t sink = 0;

	if (!buf || !len)
		return;

	for (i = 0; i < len; i += step)
		sink ^= buf[i];

	(void)sink;
}

static inline void dsa_touch_read(uint8_t *addr)
{
	volatile uint8_t value;

	value = *(volatile uint8_t *)addr;
	(void)value;
}

static inline void dsa_touch_write(uint8_t *addr)
{
	volatile uint8_t *target = (volatile uint8_t *)addr;
	uint8_t value = *target;

	*target = value;
}

static inline u64 dsa_now_us(void)
{
	struct timeval tv;

	if (sys_gettimeofday(&tv, NULL))
		return 0;

	return (u64)tv.tv_sec * 1000000ULL + (u64)tv.tv_usec;
}

static inline int dsa_path_eq(const char *a, const char *b, u32 max_len)
{
	u32 i;

	for (i = 0; i < max_len; i++) {
		if (a[i] != b[i])
			return 0;
		if (!a[i])
			return 1;
	}

	return 1;
}

static inline void dsa_path_copy(char *dst, const char *src, u32 max_len)
{
	u32 i;

	if (!max_len)
		return;

	for (i = 0; i < max_len - 1 && src[i]; i++)
		dst[i] = src[i];

	dst[i] = '\0';
}

static void dsa_wq_cache_init_once(void)
{
	u32 i;

	if (dsa_cached_wq_inited)
		return;

	for (i = 0; i < DSA_DUMP_MAX_WQ; i++) {
		dsa_cached_wq_fds[i] = -1;
		dsa_cached_wq_portals[i] = (void *)-1;
		dsa_cached_wq_portal_off[i] = 0;
		dsa_cached_wq_paths[i][0] = '\0';
	}

	dsa_cached_wq_inited = 1;
}

static void dsa_wq_cache_drop_idx(u32 i)
{
	if (i >= DSA_DUMP_MAX_WQ)
		return;

	if ((long)dsa_cached_wq_portals[i] >= 0) {
		sys_munmap(dsa_cached_wq_portals[i], DSA_PORTAL_MAP_SIZE);
		dsa_cached_wq_portals[i] = (void *)-1;
	}

	if (dsa_cached_wq_fds[i] >= 0) {
		sys_close(dsa_cached_wq_fds[i]);
		dsa_cached_wq_fds[i] = -1;
	}

	dsa_cached_wq_portal_off[i] = 0;
	dsa_cached_wq_paths[i][0] = '\0';
}

static inline u32 dsa_atomic_load_u32(volatile u32 *p)
{
	return __atomic_load_n(p, __ATOMIC_ACQUIRE);
}

static inline void dsa_atomic_store_u32(volatile u32 *p, u32 v)
{
	__atomic_store_n(p, v, __ATOMIC_RELEASE);
}

static int dsa_submit_copy_desc(struct parasite_dsa_dump_pages_args *a,
				struct dsa_hw_desc *desc, uint32_t wq_idx,
				int *use_portal, unsigned long *portal_mask,
				unsigned long *portal_offset)
{
	uint32_t retry_count;
	u64 submit_begin;
	u64 submit_end;
	int ret = 0;

	submit_begin = dsa_now_us();
	if (!use_portal[wq_idx]) {
		ret = -EOPNOTSUPP;
		goto out;
	}

	for (retry_count = 0; retry_count < DSA_MAX_ENQ_RETRY; retry_count++) {
		unsigned long off = ((unsigned long)portal_offset[wq_idx]++ << 6) & 0xfffUL;
		void *slot = (void *)(portal_mask[wq_idx] | off);

		if (dsa_enqcmd_local(slot, desc) == 0) {
			a->submit_enqcmd++;
			goto out;
		}
		dsa_cpu_relax();
	}

	ret = -EAGAIN;
out:
	submit_end = dsa_now_us();
	if (submit_end > submit_begin)
		a->submit_us += submit_end - submit_begin;
	return ret;
}

static int dsa_copy_descs(struct parasite_dsa_dump_pages_args *a,
			  uint8_t *shared_buf,
			  struct dsa_dump_descriptor *descriptors,
			  uint32_t nr_descriptors, uint32_t data_off,
			  uint32_t data_bytes,
			  uint32_t active_wq_count,
			  uint32_t *active_wq_idx,
			  uint64_t *active_wq_load,
			  int *use_portal,
			  unsigned long *portal_mask,
			  unsigned long *portal_offset)
{
	struct dsa_hw_desc *dsa_descs = dsa_copy_hw_descs;
	volatile struct dsa_completion_record *dsa_comps = dsa_copy_comps;
	uint32_t *lpt_order = dsa_copy_lpt_order;
	uint32_t *submitted_idx = dsa_copy_submitted_idx;
	uint32_t *submitted_wq_idx = dsa_copy_wq_idx;
	const uint32_t max_timeout_retries = 1000000;
	uint32_t desc_base = 0;
	uint32_t buf_write_offset = data_off;
	uint32_t total_size = 0;
	uint32_t i, j, k;


	if (!nr_descriptors || data_off > a->shared_buf_size ||
	    data_bytes > a->shared_buf_size - data_off) {
		a->failed_idx = -1;
		a->failed_status = 0;
		a->op_ret = -EINVAL;
		return -1;
	}

	if (!active_wq_count) {
		a->failed_idx = -1;
		a->failed_status = 0;
		a->op_ret = -EIO;
		return -1;
	}

	while (desc_base < nr_descriptors) {
		uint32_t remaining = nr_descriptors - desc_base;
		uint32_t window = a->wq_count * DSA_DESC_PER_WQ;
		u64 window_bytes = 0;
		uint32_t submitted = 0;
		uint32_t completed = 0;
		uint32_t order_cnt;
		int window_failed = 0;

		if (window > DSA_DUMP_BATCH_SIZE)
			window = DSA_DUMP_BATCH_SIZE;
		if (window > remaining)
			window = remaining;

		for (i = 0; i < window; i++) {
			struct dsa_dump_descriptor *desc =
				&descriptors[desc_base + i];

			if (!desc->copy_len ||
			    (desc->src_addr & (DSA_PAGE_SIZE - 1U)) ||
			    (desc->copy_len & (DSA_PAGE_SIZE - 1U))) {
				a->failed_idx = desc_base + i;
				a->op_ret = -EINVAL;
				return -1;
			}
			window_bytes += desc->copy_len;
			if (window_bytes > data_bytes - total_size ||
			    window_bytes > a->shared_buf_size - buf_write_offset) {
				a->failed_idx = desc_base + i;
				a->op_ret = -ENOSPC;
				return -1;
			}
		}

		/*
		 * A generation without a direct parent is a dense full capture.
		 * Populate only the source pages represented by this window's
		 * capture runs. Later generations keep this loop disabled and
		 * recover only addresses reported by PAGE_FAULT_NOBOF.
		 */
		if (a->raw_full_prefault) {
			u64 prefault_begin = 0;
			u64 prefault_end = 0;

			if (a->profile_enabled)
				prefault_begin = dsa_now_us();

			for (i = 0; i < window; i++) {
				struct dsa_dump_descriptor *desc =
					&descriptors[desc_base + i];

				dsa_prefault_range(
					(uint8_t *)(unsigned long)desc->src_addr,
					desc->copy_len);
				a->raw_prefault_pages +=
					desc->copy_len / DSA_PAGE_SIZE;
			}

			if (a->profile_enabled) {
				prefault_end = dsa_now_us();
				if (prefault_end > prefault_begin)
					a->prefault_us += prefault_end - prefault_begin;
			}
		}

		for (i = 0; i < window; i++) {
			struct dsa_dump_descriptor *desc = &descriptors[desc_base + i];
			uint8_t *src = (uint8_t *)(unsigned long)desc->src_addr;
			uint32_t copy_len = desc->copy_len;
			uint8_t *dst = shared_buf + buf_write_offset;

			if (buf_write_offset + copy_len > a->shared_buf_size ||
			    total_size + copy_len > data_bytes) {
				pr_err("DSA stream copy overflow desc=%u copy_len=%u total=%u data_bytes=%u off=%u shared=%u\n",
				       desc_base + i, copy_len, total_size, data_bytes,
				       buf_write_offset, a->shared_buf_size);
				a->op_ret = -ENOSPC;
				return -1;
			}

			dsa_memzero(&dsa_descs[i], sizeof(struct dsa_hw_desc));
			dsa_descs[i].opcode = DSA_OPCODE_MEMMOVE;
			dsa_descs[i].flags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR;
			dsa_descs[i].src_addr = (uint64_t)(unsigned long)src;
			dsa_descs[i].dst_addr = (uint64_t)(unsigned long)dst;
			dsa_descs[i].xfer_size = copy_len;
			dsa_descs[i].completion_addr = (uint64_t)(unsigned long)&dsa_comps[i];

			dsa_memzero((void *)&dsa_comps[i], sizeof(struct dsa_completion_record));

			buf_write_offset += copy_len;
			total_size += copy_len;
		}

		order_cnt = window;
		for (i = 0; i < order_cnt; i++)
			lpt_order[i] = i;

		if (a->wq_policy != DSA_WQ_POLICY_RR) {
			for (i = 0; i < order_cnt; i++) {
				uint32_t best = i;

				for (j = i + 1; j < order_cnt; j++) {
					struct dsa_dump_descriptor *desc;

					desc = &descriptors[desc_base + lpt_order[j]];
					if (desc->copy_len >
					    descriptors[desc_base + lpt_order[best]].copy_len)
						best = j;
				}

				if (best != i) {
					uint32_t tmp = lpt_order[i];

					lpt_order[i] = lpt_order[best];
					lpt_order[best] = tmp;
				}
			}
		}

		for (k = 0; k < order_cnt; k++) {
			uint32_t desc_idx = lpt_order[k];
			uint32_t wq_sel;
			uint32_t wq_idx;
			int submit_ret;

			if (a->wq_policy == DSA_WQ_POLICY_RR) {
				wq_sel = k % active_wq_count;
			} else {
				wq_sel = 0;
				for (j = 1; j < active_wq_count; j++) {
					if (active_wq_load[j] < active_wq_load[wq_sel])
						wq_sel = j;
				}
			}

			wq_idx = active_wq_idx[wq_sel];
			submit_ret = dsa_submit_copy_desc(a, &dsa_descs[desc_idx],
							  wq_idx, use_portal,
							  portal_mask, portal_offset);
			if (submit_ret) {
				a->failed_idx = desc_base + desc_idx;
				a->op_ret = submit_ret;
				window_failed = 1;
				goto poll_completed;
			}

			submitted_idx[submitted++] = desc_idx;
			submitted_wq_idx[desc_idx] = wq_idx;
			active_wq_load[wq_sel] +=
				descriptors[desc_base + desc_idx].copy_len;
		}

poll_completed:
		if (!submitted) {
			return -1;
		}

		for (k = 0; k < submitted; k++) {
			uint32_t desc_idx = submitted_idx[k];
			uint32_t timeout_count = 0;
			uint32_t fault_count = 0;
			uint32_t max_fault_count;
			uint32_t last_fault_operand = ~0U;
			uint64_t last_fault_page = ~0ULL;
			uint64_t last_fault_progress = ~0ULL;
			uint64_t logical_progress = 0;
			uint32_t original_len = dsa_descs[desc_idx].xfer_size;
			u64 poll_begin;
			u64 poll_end;
			int poll_failed = 0;

			max_fault_count =
				2U * (((original_len - 1U) / DSA_PAGE_SIZE) + 1U) + 2U;
			poll_begin = dsa_now_us();
			while (1) {
				uint8_t comp_status = dsa_comps[desc_idx].status;
				uint8_t comp_code = (uint8_t)DSA_COMP_STATUS(comp_status);

				if (comp_status != 0 && comp_code != DSA_COMP_NONE) {
					if (comp_code == DSA_COMP_SUCCESS || comp_code == DSA_COMP_SUCCESS_PRED) {
						a->completed_count++;
						completed++;
					} else if (comp_code == DSA_COMP_PAGE_FAULT_NOBOF &&
						   !window_failed) {
						uint8_t fault_info = dsa_comps[desc_idx].fault_info;
						uint32_t fault_operand =
							(fault_info >> DSA_FAULT_OPERAND_SHIFT) &
							DSA_FAULT_OPERAND_MASK;
						uint32_t partial = dsa_comps[desc_idx].bytes_completed;
						uint64_t fault_addr = dsa_comps[desc_idx].fault_addr;
						uint64_t operand_addr;
						uint64_t expected_addr;
						uint64_t fault_page;
						uint64_t expected_page;
						u64 touch_begin;
						u64 touch_end;
						u64 resubmit_begin;
						u64 resubmit_end;
						int submit_ret;

						if ((fault_info & DSA_FAULT_ADDR_MASKED) ||
						    (fault_operand != DSA_FAULT_OPERAND_SRC &&
						     fault_operand != DSA_FAULT_OPERAND_DST) ||
						    partial >= dsa_descs[desc_idx].xfer_size) {
							a->failed_idx = desc_base + desc_idx;
							a->failed_status = comp_code;
							a->op_ret = -EPROTO;
							poll_failed = 1;
							break;
						}

						operand_addr =
							fault_operand == DSA_FAULT_OPERAND_SRC ?
							dsa_descs[desc_idx].src_addr :
							dsa_descs[desc_idx].dst_addr;
						expected_addr = operand_addr + partial;
						fault_page =
							fault_addr & ~((uint64_t)DSA_PAGE_SIZE - 1ULL);
						expected_page =
							expected_addr & ~((uint64_t)DSA_PAGE_SIZE - 1ULL);
						if (fault_page != expected_page ||
						    fault_count++ >= max_fault_count ||
						    (fault_operand == last_fault_operand &&
						     fault_page == last_fault_page &&
						     logical_progress + partial ==
							     last_fault_progress)) {
							a->failed_idx = desc_base + desc_idx;
							a->failed_status = comp_code;
							a->op_ret = -EPROTO;
							poll_failed = 1;
							break;
						}

						last_fault_operand = fault_operand;
						last_fault_page = fault_page;
						last_fault_progress = logical_progress + partial;
						logical_progress += partial;
						a->raw_faults++;
						a->raw_fault_partial_bytes += partial;
						if (fault_operand == DSA_FAULT_OPERAND_SRC)
							a->raw_fault_source++;
						else
							a->raw_fault_destination++;

						dsa_descs[desc_idx].src_addr += partial;
						dsa_descs[desc_idx].dst_addr += partial;
						dsa_descs[desc_idx].xfer_size -= partial;

						touch_begin = dsa_now_us();
						if (touch_begin > poll_begin)
							a->poll_us += touch_begin - poll_begin;
						if (fault_operand == DSA_FAULT_OPERAND_SRC)
							dsa_touch_read((uint8_t *)(unsigned long)
								       expected_addr);
						else
							dsa_touch_write((uint8_t *)(unsigned long)
									expected_addr);
						touch_end = dsa_now_us();
						if (touch_end > touch_begin)
							a->raw_fault_touch_us += touch_end - touch_begin;

						dsa_memzero((void *)&dsa_comps[desc_idx],
							    sizeof(struct dsa_completion_record));
						resubmit_begin = dsa_now_us();
						submit_ret = dsa_submit_copy_desc(
							a, &dsa_descs[desc_idx],
							submitted_wq_idx[desc_idx], use_portal,
							portal_mask, portal_offset);
						resubmit_end = dsa_now_us();
						if (resubmit_end > resubmit_begin)
							a->raw_fault_resubmit_us +=
								resubmit_end - resubmit_begin;
						poll_begin = resubmit_end;
						if (submit_ret) {
							a->failed_idx = desc_base + desc_idx;
							a->failed_status = comp_code;
							a->op_ret = submit_ret;
							poll_failed = 1;
							break;
						}
						a->raw_fault_resubmits++;
						timeout_count = 0;
						continue;
					} else {
						if (!window_failed) {
							a->failed_idx = desc_base + desc_idx;
							a->failed_status = comp_code;
							a->op_ret = -(int)comp_code;
						}
						poll_failed = 1;
					}
					break;
				}

				if (timeout_count++ >= max_timeout_retries) {
					a->failed_idx = desc_base + desc_idx;
					a->op_ret = -ETIMEDOUT;
					poll_failed = 1;
					break;
				}
				dsa_cpu_relax();
			}

			poll_end = dsa_now_us();
			if (poll_end > poll_begin)
				a->poll_us += poll_end - poll_begin;

			if (poll_failed) {
				window_failed = 1;
				if (a->op_ret == -ETIMEDOUT)
					return -1;
			}
		}

		if (window_failed)
			return -1;

		if (completed != submitted) {
			return -1;
		}

		desc_base += window;
	}

	if (total_size != data_bytes) {
		pr_err("DSA stream copy size mismatch desc_sum=%u data_bytes=%u data_off=%u nr_desc=%u\n",
		       total_size, data_bytes, data_off, nr_descriptors);
		a->op_ret = -EINVAL;
		return -1;
	}

	a->total_copied += total_size;
	a->new_buf_offset = data_off + total_size;
	return 0;
}

static int dsa_stream_consume(struct parasite_dsa_dump_pages_args *a,
			      uint8_t *shared_buf,
			      struct parasite_dsa_stream_hdr *hdr,
			      uint32_t active_wq_count,
			      uint32_t *active_wq_idx,
			      uint64_t *active_wq_load,
			      int *use_portal,
			      unsigned long *portal_mask,
			      unsigned long *portal_offset)
{
	uint32_t consumer_seq = 0;

	if (hdr->slot_count != DSA_STREAM_SLOT_COUNT ||
	    hdr->slot_desc_cap != DSA_STREAM_SLOT_DESC_CAP ||
	    hdr->slots_off > a->shared_buf_size ||
	    hdr->desc_area_off > a->shared_buf_size ||
	    hdr->payload_base > a->shared_buf_size ||
	    hdr->payload_limit > a->shared_buf_size ||
	    hdr->payload_base > hdr->payload_limit) {
		a->op_ret = -EINVAL;
		return -1;
	}

	while (1) {
		struct parasite_dsa_stream_slot *slots;
		struct parasite_dsa_stream_slot *slot;
		struct dsa_dump_descriptor *descriptors;
		uint32_t desc_size = sizeof(struct dsa_dump_descriptor);
		uint32_t idx;
		uint32_t state;

		if (dsa_atomic_load_u32(&hdr->error)) {
			a->op_ret = -EIO;
			return -1;
		}

		if (dsa_atomic_load_u32(&hdr->finish) &&
		    consumer_seq == dsa_atomic_load_u32(&hdr->producer_seq)) {
			a->op_ret = 0;
			return 0;
		}

		slots = (struct parasite_dsa_stream_slot *)(shared_buf + hdr->slots_off);
		idx = consumer_seq % hdr->slot_count;
		slot = &slots[idx];
		state = dsa_atomic_load_u32(&slot->state);
		if (state != DSA_STREAM_SLOT_READY || slot->seq != consumer_seq) {
			dsa_cpu_relax();
			continue;
		}

		__atomic_thread_fence(__ATOMIC_ACQUIRE);

		dsa_atomic_store_u32(&slot->state, DSA_STREAM_SLOT_COPYING);
		if (!slot->desc_count || slot->desc_count > hdr->slot_desc_cap ||
		    slot->desc_off < hdr->desc_area_off ||
		    slot->desc_off >= hdr->payload_base ||
		    slot->desc_count > (hdr->payload_base - slot->desc_off) / desc_size ||
		    slot->payload_off < hdr->payload_base ||
		    slot->payload_off > hdr->payload_limit ||
		    slot->payload_bytes > hdr->payload_limit - slot->payload_off) {
			pr_err("DSA stream slot validation failed\n");
			slot->status = (u32)-EINVAL;
			dsa_atomic_store_u32(&slot->state, DSA_STREAM_SLOT_ERROR);
			dsa_atomic_store_u32(&hdr->error, (u32)-EINVAL);
			a->op_ret = -EINVAL;
			return -1;
		}

		descriptors = (struct dsa_dump_descriptor *)(shared_buf + slot->desc_off);
		if (dsa_copy_descs(a, shared_buf, descriptors, slot->desc_count,
				   slot->payload_off, slot->payload_bytes,
				   active_wq_count, active_wq_idx, active_wq_load,
				   use_portal, portal_mask, portal_offset)) {
			slot->status = (u32)a->op_ret;
			dsa_atomic_store_u32(&slot->state, DSA_STREAM_SLOT_ERROR);
			dsa_atomic_store_u32(&hdr->error, (u32)a->op_ret);
			return -1;
		}

		slot->copied_bytes = slot->payload_bytes;
		slot->status = 0;
		dsa_atomic_store_u32(&slot->state, DSA_STREAM_SLOT_DONE);
		consumer_seq++;
		dsa_atomic_store_u32(&hdr->consumer_seq, consumer_seq);
	}
}


#ifdef CRIU_DSA_ENABLE_LEGACY_SINGLE_RPC
static int dsa_legacy_single_rpc_consume(struct parasite_dsa_dump_pages_args *a,
					  uint8_t *shared_buf,
					  struct parasite_dsa_shm_hdr *hdr,
					  uint32_t active_wq_count,
					  uint32_t *active_wq_idx,
					  uint64_t *active_wq_load,
					  int *use_portal,
					  unsigned long *portal_mask,
					  unsigned long *portal_offset)
{
	struct dsa_dump_descriptor *descriptors;
	u32 desc_bytes;
	u32 min_data_off;

	if (!(hdr->flags & PARASITE_DSA_SHM_F_SINGLE_RPC)) {
		a->op_ret = -EINVAL;
		return -1;
	}

	desc_bytes = hdr->desc_count * sizeof(struct dsa_dump_descriptor);
	if (!hdr->desc_count || hdr->desc_bytes != desc_bytes) {
		pr_err("DSA legacy single-RPC invalid descriptor count=%u bytes=%u expected=%u\n",
		       hdr->desc_count, hdr->desc_bytes, desc_bytes);
		a->op_ret = -EINVAL;
		return -1;
	}

	if (a->hdr_off + sizeof(*hdr) > a->shared_buf_size ||
	    desc_bytes > a->shared_buf_size - (a->hdr_off + sizeof(*hdr))) {
		a->op_ret = -EINVAL;
		return -1;
	}

	min_data_off = (u32)(((a->hdr_off + sizeof(*hdr) + desc_bytes) +
			     DSA_SHARED_DATA_ALIGN - 1) & ~(DSA_SHARED_DATA_ALIGN - 1));
	if (hdr->data_off < min_data_off || hdr->data_off > a->shared_buf_size ||
	    hdr->data_bytes > a->shared_buf_size - hdr->data_off) {
		pr_err("DSA legacy single-RPC invalid layout desc_bytes=%u data_off=%u min_data_off=%u data_bytes=%u shared=%u\n",
		       desc_bytes, hdr->data_off, min_data_off, hdr->data_bytes,
		       a->shared_buf_size);
		a->op_ret = -EINVAL;
		return -1;
	}

	descriptors = (struct dsa_dump_descriptor *)((uint8_t *)hdr + sizeof(*hdr));
	if (dsa_copy_descs(a, shared_buf, descriptors, hdr->desc_count,
			   hdr->data_off, hdr->data_bytes, active_wq_count,
			   active_wq_idx, active_wq_load, use_portal,
			   portal_mask, portal_offset))
		return -1;

	a->op_ret = 0;
	return 0;
}
#endif


/*
 * Batch DSA dump pages to shared buffer
 * This function performs bulk copy of memory pages using DSA hardware acceleration
 * to a shared memory buffer managed by CRIU.
 */
static int parasite_dsa_dump_pages(struct parasite_dsa_dump_pages_args *a)
{
	struct parasite_dsa_dump_pages_args *orig_args = a;
	struct parasite_dsa_dump_pages_args local_args = *a;
	int wq_fds[DSA_DUMP_MAX_WQ];
	int use_portal[DSA_DUMP_MAX_WQ];
	unsigned long portal_mask[DSA_DUMP_MAX_WQ];
	unsigned long portal_offset[DSA_DUMP_MAX_WQ];
	void *portals[DSA_DUMP_MAX_WQ];
	uint32_t active_wq_idx[DSA_DUMP_MAX_WQ];
	uint64_t active_wq_load[DSA_DUMP_MAX_WQ];
	uint32_t active_wq_count = 0;
	uint32_t i;
	uint8_t *shared_buf;
	struct parasite_dsa_shm_hdr *shm_hdr;
	struct parasite_dsa_stream_hdr *stream_hdr = NULL;
	void *portal_va;
	int tsock;
	int shared_buf_fd = -1;
	void *shared_map = (void *)-1;
	u64 setup_begin_us = 0;
	u64 setup_end_us = 0;
	u64 shared_setup_begin_us = 0;
	u64 shared_setup_end_us = 0;
	u64 wq_setup_begin_us = 0;
	u64 wq_setup_end_us = 0;
	u64 t_begin_us;
	u64 t_end_us;

	/*
	 * The RPC argument area is shared with CRIU and can be reused by the
	 * producer while this streaming RPC is still consuming slots. Keep all
	 * long-lived inputs/results in a private copy; final results are published
	 * through the DSA stream header.
	 */
	a = &local_args;

	/* Initialize output fields */
	a->op_ret = -1;
	a->total_copied = 0;
	a->completed_count = 0;
	a->failed_idx = -1;
	a->failed_status = 0;
	a->new_buf_offset = a->buf_write_offset;
	a->submit_enqcmd = 0;
	a->submit_write = 0;
	a->map_populate_fallbacks = 0;
	a->raw_faults = 0;
	a->raw_fault_source = 0;
	a->raw_fault_destination = 0;
	a->raw_fault_resubmits = 0;
	a->raw_prefault_pages = 0;
	a->raw_fault_partial_bytes = 0;
	a->raw_fault_touch_us = 0;
	a->raw_fault_resubmit_us = 0;
	a->prefault_us = 0;
	a->submit_us = 0;
	a->poll_us = 0;
	a->setup_us = 0;
	a->setup_shared_us = 0;
	a->setup_wq_us = 0;
	a->setup_shared_recv_fd_us = 0;
	a->setup_shared_mmap_us = 0;
	a->setup_wq_recv_fd_us = 0;
	a->setup_wq_open_us = 0;
	a->setup_wq_mmap_us = 0;
	a->cleanup_munmap_us = 0;
	a->cleanup_close_us = 0;

	/* Validate input parameters */
	if (!a->shared_map_size)
		a->shared_map_size = a->shared_buf_size;

	if (a->shared_map_size < a->shared_buf_size) {
		pr_err("DSA strict: shared map smaller than usable size map=%llu size=%u\n",
		       (unsigned long long)a->shared_map_size, a->shared_buf_size);
		a->op_ret = -EINVAL;
		goto out_copy_results;
	}

	if ((!a->use_shared_buf_fd && !a->shared_buf_addr &&
	     ((long)dsa_cached_shared_map < 0 ||
	      dsa_cached_shared_size != a->shared_buf_size ||
	      dsa_cached_shared_map_size != a->shared_map_size)) ||
	    !a->shared_buf_size || !a->wq_count ||
	    a->wq_count > DSA_DUMP_MAX_WQ || a->buf_write_offset >= a->shared_buf_size) {
		pr_err("DSA strict: invalid entry args use_fd=%u shared_addr=%llu cached=%u cached_size=%llu cached_map=%llu shared_size=%u map_size=%llu wq_count=%u buf_write_offset=%u\n",
		       a->use_shared_buf_fd, (unsigned long long)a->shared_buf_addr,
		       (long)dsa_cached_shared_map >= 0 ? 1U : 0U,
		       (unsigned long long)dsa_cached_shared_size,
		       (unsigned long long)dsa_cached_shared_map_size,
		       a->shared_buf_size, (unsigned long long)a->shared_map_size,
		       a->wq_count, a->buf_write_offset);
		a->op_ret = -EINVAL;
		goto out_copy_results;
	}

	setup_begin_us = dsa_now_us();
	shared_setup_begin_us = dsa_now_us();

	if (a->use_shared_buf_fd) {
		tsock = parasite_get_rpc_sock();
		t_begin_us = dsa_now_us();
		shared_buf_fd = recv_fd(tsock);
		t_end_us = dsa_now_us();
		if (t_end_us > t_begin_us)
			a->setup_shared_recv_fd_us += t_end_us - t_begin_us;
		if (shared_buf_fd < 0) {
			pr_err("DSA: recv shared buffer fd failed\n");
			a->op_ret = -EIO;
			goto out_copy_results;
		}

		t_begin_us = dsa_now_us();
		shared_map = (void *)sys_mmap(NULL, a->shared_map_size,
					     PROT_READ | PROT_WRITE,
					     MAP_SHARED | MAP_POPULATE,
					     shared_buf_fd, 0);
		t_end_us = dsa_now_us();
		if (t_end_us > t_begin_us)
			a->setup_shared_mmap_us += t_end_us - t_begin_us;
		if ((long)shared_map < 0) {
			pr_err("DSA strict: shared mmap MAP_POPULATE failed\n");
			a->op_ret = -EOPNOTSUPP;
			goto out_cleanup;
		}

		if ((long)dsa_cached_shared_map >= 0) {
			t_begin_us = dsa_now_us();
			sys_munmap(dsa_cached_shared_map, dsa_cached_shared_map_size);
			t_end_us = dsa_now_us();
			if (t_end_us > t_begin_us)
				a->cleanup_munmap_us += t_end_us - t_begin_us;
		}
		dsa_cached_shared_map = shared_map;
		dsa_cached_shared_size = a->shared_buf_size;
		dsa_cached_shared_map_size = a->shared_map_size;
		shared_buf = (uint8_t *)dsa_cached_shared_map;
		shared_map = (void *)-1;
		t_begin_us = dsa_now_us();
		sys_close(shared_buf_fd);
		t_end_us = dsa_now_us();
		if (t_end_us > t_begin_us)
			a->cleanup_close_us += t_end_us - t_begin_us;
		shared_buf_fd = -1;
	} else if (a->shared_buf_addr) {
		shared_buf = (uint8_t *)(unsigned long)a->shared_buf_addr;
	} else if ((long)dsa_cached_shared_map >= 0 &&
		   dsa_cached_shared_size == a->shared_buf_size &&
		   dsa_cached_shared_map_size == a->shared_map_size) {
		shared_buf = (uint8_t *)dsa_cached_shared_map;
	} else {
		a->op_ret = -EINVAL;
		goto out_cleanup;
	}

	shared_setup_end_us = dsa_now_us();
	if (shared_setup_end_us > shared_setup_begin_us)
		a->setup_shared_us = shared_setup_end_us - shared_setup_begin_us;

	if (a->hdr_off > a->shared_buf_size - sizeof(*shm_hdr)) {
		a->op_ret = -EINVAL;
		goto out_cleanup;
	}

	shm_hdr = (struct parasite_dsa_shm_hdr *)(shared_buf + a->hdr_off);
	if (shm_hdr->magic != PARASITE_DSA_SHM_HDR_MAGIC ||
	    shm_hdr->version != PARASITE_DSA_SHM_HDR_VERSION) {
		pr_err("DSA: shared header mismatch magic=%x version=%u\n",
		       shm_hdr->magic, shm_hdr->version);
		a->op_ret = -EINVAL;
		goto out_cleanup;
	}

	if (shm_hdr->flags & PARASITE_DSA_SHM_F_STREAM) {
		stream_hdr = (struct parasite_dsa_stream_hdr *)shm_hdr;
	}
#ifdef CRIU_DSA_ENABLE_LEGACY_SINGLE_RPC
	else if (shm_hdr->flags & PARASITE_DSA_SHM_F_SINGLE_RPC) {
		stream_hdr = NULL;
	}
#endif
	else {
		pr_err("DSA strict: unsupported shared header flags=%u\n",
		       shm_hdr->flags);
		a->op_ret = -EINVAL;
		goto out_cleanup;
	}
	dsa_wq_cache_init_once();

	/* Initialize all WQ pointers */
	for (i = 0; i < a->wq_count; i++) {
		wq_fds[i] = -1;
		use_portal[i] = 0;
		portal_mask[i] = 0;
		portal_offset[i] = 0;
		portals[i] = (void *)-1;
	}

	wq_setup_begin_us = dsa_now_us();

	/* Acquire WQ file descriptors */
	if (a->use_wq_fd) {
		/* Receive FDs from parent via RPC socket */
		tsock = parasite_get_rpc_sock();
		for (i = 0; i < a->wq_count; i++) {
			t_begin_us = dsa_now_us();
			wq_fds[i] = recv_fd(tsock);
			t_end_us = dsa_now_us();
			if (t_end_us > t_begin_us)
				a->setup_wq_recv_fd_us += t_end_us - t_begin_us;
			if (wq_fds[i] < 0) {
				/* Some WQs not available, continue with fewer */
				if (i == 0) {
					pr_err("DSA: recv first workqueue fd failed\n");
					a->op_ret = -EIO;
					goto out_cleanup;
				}
				a->wq_count = i;
				break;
			}
		}
	} else {
		/* Open/map WQ paths once and reuse across calls */
		for (i = 0; i < a->wq_count; i++) {
			if (!a->wq_paths[i][0])
				continue;

			if (dsa_cached_wq_fds[i] >= 0 &&
			    dsa_path_eq(dsa_cached_wq_paths[i], a->wq_paths[i],
					sizeof(dsa_cached_wq_paths[i]))) {
				wq_fds[i] = dsa_cached_wq_fds[i];
				portals[i] = dsa_cached_wq_portals[i];
				if ((long)portals[i] >= 0) {
					use_portal[i] = 1;
					portal_mask[i] = ((unsigned long)portals[i]) & ~0xfffUL;
					portal_offset[i] = dsa_cached_wq_portal_off[i];
				}
				continue;
			}

			dsa_wq_cache_drop_idx(i);

			t_begin_us = dsa_now_us();
			wq_fds[i] = sys_open(a->wq_paths[i], O_RDWR, 0);
			t_end_us = dsa_now_us();
			if (t_end_us > t_begin_us)
				a->setup_wq_open_us += t_end_us - t_begin_us;
			if (wq_fds[i] < 0) {
				pr_err("DSA: open workqueue path failed %s ret=%d\n",
				       a->wq_paths[i], wq_fds[i]);
				if (i == 0) {
					a->op_ret = -EIO;
					goto out_cleanup;
				}
				a->wq_count = i;
				break;
			}

			dsa_cached_wq_fds[i] = wq_fds[i];
			dsa_path_copy(dsa_cached_wq_paths[i], a->wq_paths[i],
			      sizeof(dsa_cached_wq_paths[i]));

			t_begin_us = dsa_now_us();
			portal_va = (void *)sys_mmap(NULL, DSA_PORTAL_MAP_SIZE,
					   PROT_WRITE,
					   MAP_SHARED | MAP_POPULATE,
					   wq_fds[i], 0);
			t_end_us = dsa_now_us();
			if (t_end_us > t_begin_us)
				a->setup_wq_mmap_us += t_end_us - t_begin_us;
			if ((long)portal_va < 0) {
				pr_err("DSA strict: portal mmap failed for %s\n",
				       a->wq_paths[i]);
				a->op_ret = -EOPNOTSUPP;
				goto out_cleanup;
			}

			dsa_cached_wq_portals[i] = portal_va;
			dsa_cached_wq_portal_off[i] = 0;

			portals[i] = portal_va;
			use_portal[i] = 1;
			portal_mask[i] = ((unsigned long)portal_va) & ~0xfffUL;
			portal_offset[i] = 0;
		}

	}


	if (a->wq_count == 0) {
		pr_err("DSA: no workqueue available after setup\n");
		a->op_ret = -EIO;
		goto out_cleanup;
	}

	for (i = 0; i < a->wq_count; i++) {
		if (wq_fds[i] >= 0)
			active_wq_idx[active_wq_count++] = i;
	}

	for (i = 0; i < active_wq_count; i++)
		active_wq_load[i] = 0;

	if (!active_wq_count) {
		pr_err("DSA: active workqueue count is zero\n");
		a->op_ret = -EIO;
		goto out_cleanup;
	}

	/* FD mode needs per-call portal mapping; path mode reuses cached portals. */
	if (a->use_wq_fd) {
		for (i = 0; i < a->wq_count; i++) {
			if (wq_fds[i] < 0)
				continue;

			t_begin_us = dsa_now_us();
			portal_va = (void *)sys_mmap(NULL, DSA_PORTAL_MAP_SIZE,
					   PROT_WRITE,
					   MAP_SHARED | MAP_POPULATE,
					   wq_fds[i], 0);
			t_end_us = dsa_now_us();
			if (t_end_us > t_begin_us)
				a->setup_wq_mmap_us += t_end_us - t_begin_us;
			if ((long)portal_va < 0) {
				pr_err("DSA strict: portal mmap failed for wq_fd idx=%u\n", i);
				a->op_ret = -EOPNOTSUPP;
				goto out_cleanup;
			}

			use_portal[i] = 1;
			portals[i] = portal_va;
			portal_mask[i] = ((unsigned long)portal_va) & ~0xfffUL;
			portal_offset[i] = ((unsigned long)portal_va) & 0xfffUL;
		}
	}

	wq_setup_end_us = dsa_now_us();
	if (wq_setup_end_us > wq_setup_begin_us)
		a->setup_wq_us = wq_setup_end_us - wq_setup_begin_us;

	setup_end_us = dsa_now_us();
	if (setup_end_us > setup_begin_us)
		a->setup_us = setup_end_us - setup_begin_us;

	if (stream_hdr) {
		dsa_atomic_store_u32(&stream_hdr->consumer_ready, 1);
		if (dsa_stream_consume(a, shared_buf, stream_hdr,
				       active_wq_count,
				       active_wq_idx, active_wq_load, use_portal,
				       portal_mask, portal_offset))
			goto out_cleanup;
	} else {
#ifdef CRIU_DSA_ENABLE_LEGACY_SINGLE_RPC
		if (dsa_legacy_single_rpc_consume(a, shared_buf, shm_hdr,
						  active_wq_count, active_wq_idx,
						  active_wq_load, use_portal,
						  portal_mask, portal_offset))
			goto out_cleanup;
#endif
	}
	goto out_cleanup;

out_cleanup:
	if (!a->setup_shared_us && shared_setup_begin_us) {
		shared_setup_end_us = dsa_now_us();
		if (shared_setup_end_us > shared_setup_begin_us)
			a->setup_shared_us = shared_setup_end_us - shared_setup_begin_us;
	}

	if (!a->setup_wq_us && wq_setup_begin_us) {
		wq_setup_end_us = dsa_now_us();
		if (wq_setup_end_us > wq_setup_begin_us)
			a->setup_wq_us = wq_setup_end_us - wq_setup_begin_us;
	}

	if (!a->setup_us && setup_begin_us) {
		setup_end_us = dsa_now_us();
		if (setup_end_us > setup_begin_us)
			a->setup_us = setup_end_us - setup_begin_us;
	}

	/* Clean up resources */
	for (i = 0; i < a->wq_count; i++) {
		if (a->use_wq_fd) {
			if ((long)portals[i] >= 0) {
				t_begin_us = dsa_now_us();
				sys_munmap(portals[i], DSA_PORTAL_MAP_SIZE);
				t_end_us = dsa_now_us();
				if (t_end_us > t_begin_us)
					a->cleanup_munmap_us += t_end_us - t_begin_us;
			}
			if (wq_fds[i] >= 0) {
				t_begin_us = dsa_now_us();
				sys_close(wq_fds[i]);
				t_end_us = dsa_now_us();
				if (t_end_us > t_begin_us)
					a->cleanup_close_us += t_end_us - t_begin_us;
			}
		} else if (use_portal[i]) {
			dsa_cached_wq_portal_off[i] = portal_offset[i];
		}
	}

	if (shared_buf_fd >= 0) {
		t_begin_us = dsa_now_us();
		sys_close(shared_buf_fd);
		t_end_us = dsa_now_us();
		if (t_end_us > t_begin_us)
			a->cleanup_close_us += t_end_us - t_begin_us;
	}

	out_copy_results:
	*orig_args = *a;
	if (stream_hdr) {
		stream_hdr->result_op_ret = a->op_ret;
		stream_hdr->result_total_copied = a->total_copied;
		stream_hdr->result_completed_count = a->completed_count;
		stream_hdr->result_failed_idx = a->failed_idx;
		stream_hdr->result_failed_status = a->failed_status;
		stream_hdr->result_new_buf_offset = a->new_buf_offset;
		stream_hdr->result_setup_shared_recv_fd_us = a->setup_shared_recv_fd_us;
		stream_hdr->result_setup_shared_mmap_us = a->setup_shared_mmap_us;
		stream_hdr->result_cleanup_munmap_us = a->cleanup_munmap_us;
		stream_hdr->result_cleanup_close_us = a->cleanup_close_us;
		stream_hdr->result_setup_shared_us = a->setup_shared_us;
		stream_hdr->result_prefault_us = a->prefault_us;
		stream_hdr->result_submit_us = a->submit_us;
		stream_hdr->result_poll_us = a->poll_us;
		stream_hdr->result_submit_enqcmd = a->submit_enqcmd;
		stream_hdr->result_submit_write = a->submit_write;
		stream_hdr->result_raw_faults = a->raw_faults;
		stream_hdr->result_raw_fault_source = a->raw_fault_source;
		stream_hdr->result_raw_fault_destination = a->raw_fault_destination;
		stream_hdr->result_raw_fault_resubmits = a->raw_fault_resubmits;
		stream_hdr->result_raw_prefault_pages = a->raw_prefault_pages;
		stream_hdr->result_raw_fault_partial_bytes = a->raw_fault_partial_bytes;
		stream_hdr->result_raw_fault_touch_us = a->raw_fault_touch_us;
		stream_hdr->result_raw_fault_resubmit_us = a->raw_fault_resubmit_us;
		__atomic_thread_fence(__ATOMIC_RELEASE);
	}
	return 0;
}

static int mprotect_vmas(struct parasite_dump_pages_args *args)
{
	struct parasite_vma_entry *vmas, *vma;
	int ret = 0, i;

	vmas = pargs_vmas(args);
	for (i = 0; i < args->nr_vmas; i++) {
		vma = vmas + i;
		ret = sys_mprotect((void *)vma->start, vma->len, vma->prot | args->add_prot);
		if (ret) {
			pr_err("mprotect(%08lx, %ld) failed with code %d\n", vma->start, vma->len, ret);
			break;
		}
	}

	if (args->add_prot)
		mprotect_args = args;
	else
		mprotect_args = NULL;

	return ret;
}

static int dump_pages(struct parasite_dump_pages_args *args)
{
	int p, ret, tsock;
	struct iovec *iovs;
	int off, nr_segs;
	unsigned long spliced_bytes = 0;

	tsock = parasite_get_rpc_sock();
	p = recv_fd(tsock);
	if (p < 0)
		return -1;

	iovs = pargs_iovs(args);
	off = 0;
	nr_segs = args->nr_segs;
	if (nr_segs > UIO_MAXIOV)
		nr_segs = UIO_MAXIOV;
	while (1) {
		ret = sys_vmsplice(p, &iovs[args->off + off], nr_segs, SPLICE_F_GIFT | SPLICE_F_NONBLOCK);
		if (ret < 0) {
			sys_close(p);
			pr_err("Can't splice pages to pipe (%d/%d/%d)\n", ret, nr_segs, args->off + off);
			return -1;
		}
		spliced_bytes += ret;
		off += nr_segs;
		if (off == args->nr_segs)
			break;
		if (off + nr_segs > args->nr_segs)
			nr_segs = args->nr_segs - off;
	}
	if (spliced_bytes != args->nr_pages * PAGE_SIZE) {
		sys_close(p);
		pr_err("Can't splice all pages to pipe (%ld/%ld)\n", spliced_bytes, args->nr_pages);
		return -1;
	}

	sys_close(p);
	return 0;
}

static int dump_sigact(struct parasite_dump_sa_args *da)
{
	int sig, ret = 0;

	for (sig = 1; sig <= SIGMAX; sig++) {
		int i = sig - 1;

		if (sig == SIGKILL || sig == SIGSTOP)
			continue;

		ret = sys_sigaction(sig, NULL, &da->sas[i], sizeof(k_rtsigset_t));
		if (ret < 0) {
			pr_err("sys_sigaction failed (%d)\n", ret);
			break;
		}
	}

	return ret;
}

static int dump_itimers(struct parasite_dump_itimers_args *args)
{
	int ret;

	ret = sys_getitimer(ITIMER_REAL, &args->real);
	if (!ret)
		ret = sys_getitimer(ITIMER_VIRTUAL, &args->virt);
	if (!ret)
		ret = sys_getitimer(ITIMER_PROF, &args->prof);

	if (ret)
		pr_err("getitimer failed (%d)\n", ret);

	return ret;
}

static int dump_posix_timers(struct parasite_dump_posix_timers_args *args)
{
	int i;
	int ret = 0;

	for (i = 0; i < args->timer_n; i++) {
		ret = sys_timer_gettime(args->timer[i].it_id, &args->timer[i].val);
		if (ret < 0) {
			pr_err("sys_timer_gettime failed (%d)\n", ret);
			return ret;
		}
		ret = sys_timer_getoverrun(args->timer[i].it_id);
		if (ret < 0) {
			pr_err("sys_timer_getoverrun failed (%d)\n", ret);
			return ret;
		}
		args->timer[i].overrun = ret;
		ret = 0;
	}

	return ret;
}

static int dump_creds(struct parasite_dump_creds *args);
static int check_rseq(struct parasite_check_rseq *rseq);

static int dump_thread_common(struct parasite_dump_thread *ti)
{
	int ret;

	arch_get_tls(&ti->tls);
	ret = sys_prctl(PR_GET_TID_ADDRESS, (unsigned long)&ti->tid_addr, 0, 0, 0);
	if (ret) {
		pr_err("Unable to get the clear_child_tid address: %d\n", ret);
		goto out;
	}

	ret = sys_sigaltstack(NULL, &ti->sas);
	if (ret) {
		pr_err("Unable to get signal stack context: %d\n", ret);
		goto out;
	}

	ret = sys_prctl(PR_GET_PDEATHSIG, (unsigned long)&ti->pdeath_sig, 0, 0, 0);
	if (ret) {
		pr_err("Unable to get the parent death signal: %d\n", ret);
		goto out;
	}

	{
		long slack = sys_prctl(PR_GET_TIMERSLACK, 0, 0, 0, 0);
		if (slack < 0) {
			pr_err("Unable to get timer slack: %ld\n", slack);
			ret = (int)slack;
			goto out;
		}
		ti->timerslack_ns = (unsigned long)slack;
	}

	ret = sys_prctl(PR_GET_NAME, (unsigned long)&ti->comm, 0, 0, 0);
	if (ret) {
		pr_err("Unable to get the thread name: %d\n", ret);
		goto out;
	}

	ret = check_rseq(&ti->rseq);
	if (ret) {
		pr_err("Unable to check if rseq() is initialized: %d\n", ret);
		goto out;
	}

	ret = dump_creds(ti->creds);
out:
	return ret;
}

/*
 * Returns a membarrier() registration command (it is a bitmask) if the process
 * was registered for specified (as a bit index) membarrier()-issuing command;
 * returns zero otherwise.
 */
static int get_membarrier_registration_mask(int cmd_bit)
{
	unsigned cmd = 1 << cmd_bit;
	int ret;

	/*
	 * Issuing a barrier will be successful only if the process was registered
	 * for this type of membarrier. All errors are a sign that the type issued
	 * was not registered (EPERM) or not supported by kernel (EINVAL or ENOSYS).
	 */
	ret = sys_membarrier(cmd, 0, 0);
	if (ret && ret != -EPERM && ret != -EINVAL && ret != -ENOSYS) {
		pr_err("membarrier(1 << %d) returned %d\n", cmd_bit, ret);
		return -1;
	}
	pr_debug("membarrier(1 << %d) returned %d\n", cmd_bit, ret);
	/*
	 * For supported registrations, MEMBARRIER_CMD_REGISTER_xxx = MEMBARRIER_CMD_xxx << 1.
	 * See: enum membarrier_cmd in include/uapi/linux/membarrier.h in kernel sources.
	 */
	return ret ? 0 : cmd << 1;
}

/*
 * It would be better to check the following with BUILD_BUG_ON, but we might
 * have an old linux/membarrier.h header without necessary enum values.
 */
#define MEMBARRIER_CMDBIT_PRIVATE_EXPEDITED	      3
#define MEMBARRIER_CMDBIT_PRIVATE_EXPEDITED_SYNC_CORE 5
#define MEMBARRIER_CMDBIT_PRIVATE_EXPEDITED_RSEQ      7
#define MEMBARRIER_CMDBIT_GET_REGISTRATIONS	      9

static int dump_membarrier_compat(int *membarrier_registration_mask)
{
	int ret;

	*membarrier_registration_mask = 0;
	ret = get_membarrier_registration_mask(MEMBARRIER_CMDBIT_PRIVATE_EXPEDITED);
	if (ret < 0)
		return -1;
	*membarrier_registration_mask |= ret;
	ret = get_membarrier_registration_mask(MEMBARRIER_CMDBIT_PRIVATE_EXPEDITED_SYNC_CORE);
	if (ret < 0)
		return -1;
	*membarrier_registration_mask |= ret;
	ret = get_membarrier_registration_mask(MEMBARRIER_CMDBIT_PRIVATE_EXPEDITED_RSEQ);
	if (ret < 0)
		return -1;
	*membarrier_registration_mask |= ret;
	return 0;
}

static int dump_misc(struct parasite_dump_misc *args)
{
	int ret;

	args->brk = sys_brk(0);

	args->pid = sys_getpid();
	args->sid = sys_getsid();
	args->pgid = sys_getpgid(0);
	args->umask = sys_umask(0);
	sys_umask(args->umask); /* never fails */
	args->dumpable = sys_prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
	args->thp_disabled = sys_prctl(PR_GET_THP_DISABLE, 0, 0, 0, 0);

	if (args->has_membarrier_get_registrations) {
		ret = sys_membarrier(1 << MEMBARRIER_CMDBIT_GET_REGISTRATIONS, 0, 0);
		if (ret < 0) {
			pr_err("membarrier(1 << %d) returned %d\n", MEMBARRIER_CMDBIT_GET_REGISTRATIONS, ret);
			return -1;
		}
		args->membarrier_registration_mask = ret;
	} else {
		ret = dump_membarrier_compat(&args->membarrier_registration_mask);
		if (ret)
			return ret;
	}

	ret = sys_prctl(PR_GET_CHILD_SUBREAPER, (unsigned long)&args->child_subreaper, 0, 0, 0);
	if (ret)
		pr_err("PR_GET_CHILD_SUBREAPER failed (%d)\n", ret);

	return ret;
}

static int dump_creds(struct parasite_dump_creds *args)
{
	int ret, i, j;
	struct cap_data data[_LINUX_CAPABILITY_U32S_3];
	struct cap_header hdr = { _LINUX_CAPABILITY_VERSION_3, 0 };

	ret = sys_capget(&hdr, data);
	if (ret < 0) {
		pr_err("Unable to get capabilities: %d\n", ret);
		return -1;
	}

	/*
	 * Loop through the capability constants until we reach cap_last_cap.
	 * The cap_bnd set is stored as a bitmask comprised of CR_CAP_SIZE number of
	 * 32-bit uints, hence the inner loop from 0 to 32.
	 */
	for (i = 0; i < CR_CAP_SIZE; i++) {
		args->cap_eff[i] = data[i].eff;
		args->cap_prm[i] = data[i].prm;
		args->cap_inh[i] = data[i].inh;
		args->cap_bnd[i] = 0;
		args->cap_amb[i] = 0;

		for (j = 0; j < 32; j++) {
			if (j + i * 32 > args->cap_last_cap)
				break;
			ret = sys_prctl(PR_CAPBSET_READ, j + i * 32, 0, 0, 0);
			if (ret < 0) {
				pr_err("Unable to read capability %d: %d\n", j + i * 32, ret);
				return -1;
			}
			if (ret)
				args->cap_bnd[i] |= (1 << j);
		}

		for (j = 0; j < 32; j++) {
			if (j + i * 32 > args->cap_last_cap)
				break;
			ret = sys_prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, j + i * 32, 0, 0);
			if (ret < 0) {
				pr_err("Unable to read ambient capability %d: %d\n", j + i * 32, ret);
				return -1;
			}
			if (ret)
				args->cap_amb[i] |= (1 << j);
		}
	}

	args->no_new_privs = sys_prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
	args->secbits = sys_prctl(PR_GET_SECUREBITS, 0, 0, 0, 0);

	ret = sys_getgroups(0, NULL);
	if (ret < 0)
		goto grps_err;

	args->ngroups = ret;
	if (args->ngroups >= PARASITE_MAX_GROUPS) {
		pr_err("Too many groups in task %d\n", (int)args->ngroups);
		return -1;
	}

	ret = sys_getgroups(args->ngroups, args->groups);
	if (ret < 0)
		goto grps_err;

	if (ret != args->ngroups) {
		pr_err("Groups changed on the fly %d -> %d\n", args->ngroups, ret);
		return -1;
	}

	ret = sys_getresuid(&args->uids[0], &args->uids[1], &args->uids[2]);
	if (ret) {
		pr_err("Unable to get uids: %d\n", ret);
		return -1;
	}

	args->uids[3] = sys_setfsuid(-1L);

	/*
	 * FIXME In https://github.com/checkpoint-restore/criu/issues/95 it is
	 * been reported that only low 16 bits are set upon syscall
	 * on ARMv7.
	 *
	 * We may rather need implement builtin-memset and clear the
	 * whole memory needed here.
	 */
	args->gids[0] = args->gids[1] = args->gids[2] = args->gids[3] = 0;

	ret = sys_getresgid(&args->gids[0], &args->gids[1], &args->gids[2]);
	if (ret) {
		pr_err("Unable to get uids: %d\n", ret);
		return -1;
	}

	args->gids[3] = sys_setfsgid(-1L);

	return 0;

grps_err:
	pr_err("Error calling getgroups (%d)\n", ret);
	return -1;
}

static int check_rseq(struct parasite_check_rseq *rseq)
{
	int ret;
	unsigned long rseq_abi_pointer;
	unsigned long rseq_abi_size;
	uint32_t rseq_signature;
	void *addr;

	/* no need to do hacky check if we can get all info from ptrace() */
	if (!rseq->has_rseq || rseq->has_ptrace_get_rseq_conf)
		return 0;

	/*
	 * We need to determine if victim process has rseq()
	 * initialized, but we have no *any* proper kernel interface
	 * supported at this point.
	 * Our plan:
	 * 1. We know that if we call rseq() syscall and process already
	 * has current->rseq filled, then we get:
	 * -EINVAL if current->rseq != rseq || rseq_len != sizeof(*rseq),
	 * -EPERM  if current->rseq_sig != sig),
	 * -EBUSY  if current->rseq == rseq && rseq_len == sizeof(*rseq) &&
	 *            current->rseq_sig != sig
	 * if current->rseq == NULL (rseq() wasn't used) then we go to:
	 * IS_ALIGNED(rseq ...) check, if we fail it we get -EINVAL and it
	 * will be hard to distinguish case when rseq() was initialized or not.
	 * Let's construct arguments payload
	 * with:
	 * 1. correct rseq_abi_size
	 * 2. aligned and correct rseq_abi_pointer
	 * And see what rseq() return to us.
	 * If ret value is:
	 * 0: it means that rseq *wasn't* used and we successfully registered it,
	 * -EINVAL or : it means that rseq is already initialized,
	 * so we *have* to dump it. But as we have has_ptrace_get_rseq_conf = false,
	 * we should just fail dump as it's unsafe to skip rseq() dump for processes
	 * with rseq() initialized.
	 * -EPERM or -EBUSY: should not happen as we take a fresh memory area for rseq
	 */
	addr = (void *)sys_mmap(NULL, sizeof(struct criu_rseq), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1,
				0);
	if (addr == MAP_FAILED) {
		pr_err("mmap() failed for struct rseq ret = %lx\n", (unsigned long)addr);
		return -1;
	}

	memset(addr, 0, sizeof(struct criu_rseq));

	/* sys_mmap returns page aligned addresses */
	rseq_abi_pointer = (unsigned long)addr;
	rseq_abi_size = (unsigned long)sizeof(struct criu_rseq);
	/* it's not so important to have unique signature for us,
	 * because rseq_abi_pointer is guaranteed to be unique
	 */
	rseq_signature = 0x12345612;

	pr_info("\ttrying sys_rseq(%lx, %lx, %x, %x)\n", rseq_abi_pointer, rseq_abi_size, 0, rseq_signature);
	ret = sys_rseq((void *)rseq_abi_pointer, rseq_abi_size, 0, rseq_signature);
	if (ret) {
		if (ret == -EINVAL) {
			pr_info("\trseq is initialized in the victim\n");
			rseq->rseq_inited = true;

			ret = 0;
		} else {
			pr_err("\tunexpected failure of sys_rseq(%lx, %lx, %x, %x) = %d\n", rseq_abi_pointer,
			       rseq_abi_size, 0, rseq_signature, ret);

			ret = -1;
		}
	} else {
		ret = sys_rseq((void *)rseq_abi_pointer, sizeof(struct criu_rseq), RSEQ_FLAG_UNREGISTER,
			       rseq_signature);
		if (ret) {
			pr_err("\tfailed to unregister sys_rseq(%lx, %lx, %x, %x) = %d\n", rseq_abi_pointer,
			       rseq_abi_size, RSEQ_FLAG_UNREGISTER, rseq_signature, ret);

			ret = -1;
			/* we can't do munmap() because rseq is registered and we failed to unregister it */
			goto out_nounmap;
		}

		rseq->rseq_inited = false;
		ret = 0;
	}

	sys_munmap(addr, sizeof(struct criu_rseq));
out_nounmap:
	return ret;
}

static int fill_fds_fown(int fd, struct fd_opts *p)
{
	int flags, ret;
	struct f_owner_ex owner_ex;
	uint32_t v[2];

	/*
	 * For O_PATH opened files there is no owner at all.
	 */
	flags = sys_fcntl(fd, F_GETFL, 0);
	if (flags < 0) {
		pr_err("fcntl(%d, F_GETFL) -> %d\n", fd, flags);
		return -1;
	}
	if (flags & O_PATH) {
		p->fown.pid = 0;
		return 0;
	}

	ret = sys_fcntl(fd, F_GETOWN_EX, (long)&owner_ex);
	if (ret) {
		pr_err("fcntl(%d, F_GETOWN_EX) -> %d\n", fd, ret);
		return -1;
	}

	/*
	 * Simple case -- nothing is changed.
	 */
	if (owner_ex.pid == 0) {
		p->fown.pid = 0;
		return 0;
	}

	ret = sys_fcntl(fd, F_GETOWNER_UIDS, (long)&v);
	if (ret) {
		pr_err("fcntl(%d, F_GETOWNER_UIDS) -> %d\n", fd, ret);
		return -1;
	}

	p->fown.uid = v[0];
	p->fown.euid = v[1];
	p->fown.pid_type = owner_ex.type;
	p->fown.pid = owner_ex.pid;

	return 0;
}

static int fill_fds_opts(struct parasite_drain_fd *fds, struct fd_opts *opts)
{
	int i;

	for (i = 0; i < fds->nr_fds; i++) {
		int flags, fd = fds->fds[i];
		struct fd_opts *p = opts + i;

		flags = sys_fcntl(fd, F_GETFD, 0);
		if (flags < 0) {
			pr_err("fcntl(%d, F_GETFD) -> %d\n", fd, flags);
			return -1;
		}

		p->flags = (char)flags;

		if (fill_fds_fown(fd, p))
			return -1;
	}

	return 0;
}

static int drain_fds(struct parasite_drain_fd *args)
{
	int ret, tsock;
	struct fd_opts *opts;

	/*
	 * See the drain_fds_size() in criu code, the memory
	 * for this args is ensured to be large enough to keep
	 * an array of fd_opts at the tail.
	 */
	opts = ((void *)args) + sizeof(*args) + args->nr_fds * sizeof(args->fds[0]);
	ret = fill_fds_opts(args, opts);
	if (ret)
		return ret;

	tsock = parasite_get_rpc_sock();
	ret = send_fds(tsock, NULL, 0, args->fds, args->nr_fds, opts, sizeof(struct fd_opts));
	if (ret)
		pr_err("send_fds failed (%d)\n", ret);

	return ret;
}

static int dump_thread(struct parasite_dump_thread *args)
{
	args->tid = sys_gettid();
	return dump_thread_common(args);
}

static char proc_mountpoint[] = "proc.crtools";

static int pie_atoi(char *str)
{
	int ret = 0;

	while (*str) {
		ret *= 10;
		ret += *str - '0';
		str++;
	}

	return ret;
}

static int get_proc_fd(void)
{
	int ret;
	char buf[11];

	ret = sys_readlinkat(AT_FDCWD, "/proc/self", buf, sizeof(buf) - 1);
	if (ret < 0 && ret != -ENOENT) {
		pr_err("Can't readlink /proc/self (%d)\n", ret);
		return ret;
	}
	if (ret > 0) {
		buf[ret] = 0;

		/* Fast path -- if /proc belongs to this pidns */
		if (pie_atoi(buf) == sys_getpid())
			return sys_open("/proc", O_RDONLY, 0);
	}

	ret = sys_mkdir(proc_mountpoint, 0700);
	if (ret) {
		pr_err("Can't create a directory (%d)\n", ret);
		return -1;
	}

	ret = sys_mount("proc", proc_mountpoint, "proc", MS_MGC_VAL, NULL);
	if (ret) {
		if (ret == -EPERM)
			pr_err("can't dump unprivileged task whose /proc doesn't belong to it\n");
		else
			pr_err("mount failed (%d)\n", ret);
		sys_rmdir(proc_mountpoint);
		return -1;
	}

	return open_detach_mount(proc_mountpoint);
}

static int parasite_get_proc_fd(void)
{
	int fd, ret, tsock;

	fd = get_proc_fd();
	if (fd < 0) {
		pr_err("Can't get /proc fd\n");
		return -1;
	}

	tsock = parasite_get_rpc_sock();
	ret = send_fd(tsock, NULL, 0, fd);
	sys_close(fd);
	return ret;
}

static inline int tty_ioctl(int fd, int cmd, int *arg)
{
	int ret;

	ret = sys_ioctl(fd, cmd, (unsigned long)arg);
	if (ret < 0) {
		if (ret != -ENOTTY)
			return ret;
		*arg = 0;
	}
	return 0;
}

/*
 * Stolen from kernel/fs/aio.c
 *
 * Is it valid to go to memory and check it? Should be,
 * as libaio does the same.
 */

#define AIO_RING_MAGIC		   0xa10a10a1
#define AIO_RING_COMPAT_FEATURES   1
#define AIO_RING_INCOMPAT_FEATURES 0

static int sane_ring(struct parasite_aio *aio)
{
	struct aio_ring *ring = (struct aio_ring *)aio->ctx;
	unsigned nr;

	nr = (aio->size - sizeof(struct aio_ring)) / sizeof(struct io_event);

	return ring->magic == AIO_RING_MAGIC && ring->compat_features == AIO_RING_COMPAT_FEATURES &&
	       ring->incompat_features == AIO_RING_INCOMPAT_FEATURES &&
	       ring->header_length == sizeof(struct aio_ring) && ring->nr == nr;
}

static int parasite_check_aios(struct parasite_check_aios_args *args)
{
	int i;

	for (i = 0; i < args->nr_rings; i++) {
		struct aio_ring *ring;

		ring = (struct aio_ring *)args->ring[i].ctx;
		if (!sane_ring(&args->ring[i])) {
			pr_err("Not valid ring #%d\n", i);
			pr_info(" `- magic %x\n", ring->magic);
			pr_info(" `- cf    %d\n", ring->compat_features);
			pr_info(" `- if    %d\n", ring->incompat_features);
			pr_info(" `- header size  %d (%zd)\n", ring->header_length, sizeof(struct aio_ring));
			pr_info(" `- nr    %d\n", ring->nr);
			return -1;
		}

		/* XXX: wait aio completion */
	}

	return 0;
}

static int parasite_dump_tty(struct parasite_tty_args *args)
{
	int ret;

#ifndef TIOCGPKT
#define TIOCGPKT _IOR('T', 0x38, int)
#endif

#ifndef TIOCGPTLCK
#define TIOCGPTLCK _IOR('T', 0x39, int)
#endif

#ifndef TIOCGEXCL
#define TIOCGEXCL _IOR('T', 0x40, int)
#endif

	args->sid = 0;
	args->pgrp = 0;
	args->st_pckt = 0;
	args->st_lock = 0;
	args->st_excl = 0;

#define __tty_ioctl(cmd, arg)                         \
	do {                                          \
		ret = tty_ioctl(args->fd, cmd, &arg); \
		if (ret < 0) {                        \
			if (ret == -ENOTTY)           \
				arg = 0;              \
			else if (ret == -EIO)         \
				goto err_io;          \
			else                          \
				goto err;             \
		}                                     \
	} while (0)

	__tty_ioctl(TIOCGSID, args->sid);
	__tty_ioctl(TIOCGPGRP, args->pgrp);
	__tty_ioctl(TIOCGEXCL, args->st_excl);

	if (args->type == TTY_TYPE__PTY) {
		__tty_ioctl(TIOCGPKT, args->st_pckt);
		__tty_ioctl(TIOCGPTLCK, args->st_lock);
	}

	args->hangup = false;
	return 0;

err:
	pr_err("tty: Can't fetch params: err = %d\n", ret);
	return -1;
err_io:

	/* kernel reports EIO for get ioctls on pair-less ptys */
	pr_debug("tty: EIO on tty\n");
	args->hangup = true;
	return 0;
#undef __tty_ioctl
}

static int parasite_check_vdso_mark(struct parasite_vdso_vma_entry *args)
{
	struct vdso_mark *m = (void *)args->start;

	if (is_vdso_mark(m)) {
		/*
		 * Make sure we don't meet some corrupted entry
		 * where signature matches but versions do not!
		 */
		if (m->version != VDSO_MARK_CUR_VERSION) {
			pr_err("vdso: Mark version mismatch!\n");
			return -EINVAL;
		}
		args->is_marked = 1;
		args->orig_vdso_addr = m->orig_vdso_addr;
		args->orig_vvar_addr = m->orig_vvar_addr;
		args->rt_vvar_addr = m->rt_vvar_addr;
	} else {
		args->is_marked = 0;
		args->orig_vdso_addr = VDSO_BAD_ADDR;
		args->orig_vvar_addr = VVAR_BAD_ADDR;
		args->rt_vvar_addr = VVAR_BAD_ADDR;

		if (args->try_fill_symtable) {
			struct vdso_symtable t;

			if (vdso_fill_symtable(args->start, args->len, &t))
				args->is_vdso = false;
			else
				args->is_vdso = true;
		}
	}

	return 0;
}

static int parasite_dump_cgroup(struct parasite_dump_cgroup_args *args)
{
	int proc, cgroup, len;

	proc = get_proc_fd();
	if (proc < 0) {
		pr_err("can't get /proc fd\n");
		return -1;
	}

	cgroup = sys_openat(proc, args->thread_cgrp, O_RDONLY, 0);
	sys_close(proc);
	if (cgroup < 0) {
		pr_err("can't get /proc/self/cgroup fd\n");
		sys_close(cgroup);
		return -1;
	}

	len = sys_read(cgroup, args->contents, sizeof(args->contents));
	sys_close(cgroup);
	if (len < 0) {
		pr_err("can't read /proc/self/cgroup %d\n", len);
		return -1;
	}

	if (len == sizeof(args->contents)) {
		pr_warn("/proc/self/cgroup was bigger than the page size\n");
		return -1;
	}

	/* null terminate */
	args->contents[len] = 0;
	return 0;
}

void parasite_cleanup(void)
{
	u32 i;

	if ((long)dsa_cached_shared_map >= 0) {
		sys_munmap(dsa_cached_shared_map, dsa_cached_shared_map_size);
		dsa_cached_shared_map = (void *)-1;
		dsa_cached_shared_size = 0;
		dsa_cached_shared_map_size = 0;
	}

	if (dsa_cached_wq_inited) {
		for (i = 0; i < DSA_DUMP_MAX_WQ; i++)
			dsa_wq_cache_drop_idx(i);
		dsa_cached_wq_inited = 0;
	}

	if (mprotect_args) {
		mprotect_args->add_prot = 0;
		mprotect_vmas(mprotect_args);
	}
}

int parasite_daemon_cmd(int cmd, void *args)
{
	int ret;

	switch (cmd) {
	case PARASITE_CMD_DUMPPAGES:
		ret = dump_pages(args);
		break;
	case PARASITE_CMD_MPROTECT_VMAS:
		ret = mprotect_vmas(args);
		break;
	case PARASITE_CMD_DUMP_SIGACTS:
		ret = dump_sigact(args);
		break;
	case PARASITE_CMD_DUMP_ITIMERS:
		ret = dump_itimers(args);
		break;
	case PARASITE_CMD_DUMP_POSIX_TIMERS:
		ret = dump_posix_timers(args);
		break;
	case PARASITE_CMD_DUMP_THREAD:
		ret = dump_thread(args);
		break;
	case PARASITE_CMD_DUMP_MISC:
		ret = dump_misc(args);
		break;
	case PARASITE_CMD_DRAIN_FDS:
		ret = drain_fds(args);
		break;
	case PARASITE_CMD_GET_PROC_FD:
		ret = parasite_get_proc_fd();
		break;
	case PARASITE_CMD_DUMP_TTY:
		ret = parasite_dump_tty(args);
		break;
	case PARASITE_CMD_CHECK_AIOS:
		ret = parasite_check_aios(args);
		break;
	case PARASITE_CMD_CHECK_VDSO_MARK:
		ret = parasite_check_vdso_mark(args);
		break;
	case PARASITE_CMD_DUMP_CGROUP:
		ret = parasite_dump_cgroup(args);
		break;
	case PARASITE_CMD_DSA_DUMP_PAGES:
		ret = parasite_dsa_dump_pages(args);
		break;
	default:
		pr_err("Unknown command in parasite daemon thread leader: %d\n", cmd);
		ret = -1;
		break;
	}

	return ret;
}

int parasite_trap_cmd(int cmd, void *args)
{
	switch (cmd) {
	case PARASITE_CMD_DUMP_THREAD:
		return dump_thread(args);
	}

	pr_err("Unknown command to parasite: %d\n", cmd);
	return -EINVAL;
}
