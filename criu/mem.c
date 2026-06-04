#include <unistd.h>
#include <stdio.h>
#include <sys/mman.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <dirent.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <linux/memfd.h>

#ifndef MFD_HUGE_1GB
#define MFD_HUGE_1GB	(30 << MFD_HUGE_SHIFT)
#endif

#include "types.h"
#include "cr_options.h"
#include "servicefd.h"
#include "mem.h"
#include "mman.h"
#include "parasite-syscall.h"
#include "parasite.h"
#include "page-pipe.h"
#include "page-xfer.h"
#include "log.h"
#include "kerndat.h"
#include "stats.h"
#include "vma.h"
#include "shmem.h"
#include "uffd.h"
#include "pstree.h"
#include "restorer.h"
#include "rst-malloc.h"
#include "bitmap.h"
#include "sk-packet.h"
#include "files-reg.h"
#include "pagemap-cache.h"
#include "fault-injection.h"
#include "prctl.h"
#include "memfd.h"
#include "compel/infect-util.h"
#include "pidfd-store.h"

#include "protobuf.h"
#include "images/pagemap.pb-c.h"

static int task_reset_dirty_track(int pid)
{
	int ret;

	if (!opts.track_mem)
		return 0;

	BUG_ON(!kdat.has_dirty_track);

	ret = do_task_reset_dirty_track(pid);
	BUG_ON(ret == 1);
	return ret;
}

int do_task_reset_dirty_track(int pid)
{
	int fd, ret;
	char cmd[] = "4";

	pr_info("Reset %d's dirty tracking\n", pid);

	fd = __open_proc(pid, EACCES, O_RDWR, "clear_refs");
	if (fd < 0)
		return errno == EACCES ? 1 : -1;

	ret = write(fd, cmd, sizeof(cmd));
	if (ret < 0) {
		if (errno == EINVAL) /* No clear-soft-dirty in kernel */
			ret = 1;
		else {
			pr_perror("Can't reset %d's dirty memory tracker", pid);
			ret = -1;
		}
	} else {
		pr_info(" ... done\n");
		ret = 0;
	}

	close(fd);
	return ret;
}

unsigned long dump_pages_args_size(struct vm_area_list *vmas)
{
	/* In the worst case I need one iovec for each page */
	return sizeof(struct parasite_dump_pages_args) + vmas->nr * sizeof(struct parasite_vma_entry) +
	       (vmas->nr_priv_pages + 1) * sizeof(struct iovec);
}

static inline bool __page_is_zero(u64 pme)
{
	return (pme & PME_PFRAME_MASK) == kdat.zero_page_pfn;
}

static inline bool __page_in_parent(bool dirty)
{
	/*
	 * If we do memory tracking, but w/o parent images,
	 * then we have to dump all memory
	 */

	return opts.track_mem && opts.img_parent && !dirty;
}

static bool should_dump_entire_vma(VmaEntry *vmae)
{
	/*
	 * vDSO area must be always dumped because on restore
	 * we might need to generate a proxy.
	 */
	if (vma_entry_is(vmae, VMA_AREA_VDSO))
		return true;
	if (vma_entry_is(vmae, VMA_AREA_AIORING))
		return true;

	return false;
}

/*
 * should_dump_page writes vaddr in page_info->next if an addressed page has to be dumped.
 * Otherwise, it writes an address that has to be inspected next.
 */
int should_dump_page(pmc_t *pmc, VmaEntry *vmae, u64 vaddr, struct page_info *page_info)
{
	if (!page_info)
		goto err;

	if (vaddr >= pmc->end && pmc_fill(pmc, vaddr, vmae->end))
		goto err;

	if (pmc->regs) {
		while (1) {
			if (pmc->regs_idx == pmc->regs_len) {
				page_info->next = pmc->end;
				return 0;
			}

			if (vaddr < pmc->regs[pmc->regs_idx].end)
				break;
			pmc->regs_idx++;
		}

		if (vaddr < pmc->regs[pmc->regs_idx].start) {
			page_info->next = pmc->regs[pmc->regs_idx].start;
			return 0;
		}

		if (pmc->regs[pmc->regs_idx].categories & PAGE_IS_GUARD)
			goto skip_guard_page;

		page_info->softdirty = pmc->regs[pmc->regs_idx].categories & PAGE_IS_SOFT_DIRTY;
		page_info->next = vaddr;
		return 0;
	} else {
		u64 pme = pmc->map[PAGE_PFN(vaddr - pmc->start)];

		if (pme & PME_GUARD_REGION)
			goto skip_guard_page;

		/*
		 * Optimisation for private mapping pages, that haven't
		 * yet being COW-ed
		 */
		if (vma_entry_is(vmae, VMA_FILE_PRIVATE) && (pme & PME_FILE)) {
			page_info->next = vaddr + PAGE_SIZE;
			return 0;
		}

		if ((pme & (PME_PRESENT | PME_SWAP)) && !__page_is_zero(pme)) {
			page_info->softdirty = pme & PME_SOFT_DIRTY;
			page_info->next = vaddr;
			return 0;
		}

		page_info->next = vaddr + PAGE_SIZE;
		return 0;
	}

err:
	pr_err("should_dump_page failed on vma "
	       "%#016" PRIx64 "-%#016" PRIx64 " vaddr=%#016" PRIx64 "\n",
	       vmae->start, vmae->end, vaddr);
	return -1;

skip_guard_page:
	page_info->next = vaddr + PAGE_SIZE;
	return 0;
}

bool page_is_zero(u64 pme)
{
	return __page_is_zero(pme);
}

bool page_in_parent(bool dirty)
{
	return __page_in_parent(dirty);
}

static bool is_stack(struct pstree_item *item, unsigned long vaddr)
{
	int i;

	for (i = 0; i < item->nr_threads; i++) {
		uint64_t sp = dmpi(item)->thread_sp[i];

		if (!((sp ^ vaddr) & ~PAGE_MASK))
			return true;
	}

	return false;
}

/*
 * This routine finds out what memory regions to grab from the
 * dumpee. The iovs generated are then fed into vmsplice to
 * put the memory into the page-pipe's pipe.
 *
 * "Holes" in page-pipe are regions, that should be dumped, but
 * the memory contents is present in the parent image set.
 */

static int generate_iovs(struct pstree_item *item, struct vma_area *vma, struct page_pipe *pp, pmc_t *pmc, u64 *pvaddr,
			 bool has_parent)
{
	unsigned long nr_scanned;
	unsigned long pages[3] = {};
	unsigned long vaddr;
	bool dump_all_pages;
	int ret = 0;

	dump_all_pages = should_dump_entire_vma(vma->e);

	nr_scanned = 0;
	for (vaddr = *pvaddr; vaddr < vma->e->end; vaddr += PAGE_SIZE, nr_scanned++) {
		unsigned int ppb_flags = 0;
		struct page_info page_info = {};
		int st;

		/* If dump_all_pages is true, should_dump_page is called to get pme. */
		if (should_dump_page(pmc, vma->e, vaddr, &page_info))
			return -1;

		if (!dump_all_pages && page_info.next != vaddr) {
			vaddr = page_info.next - PAGE_SIZE;
			continue;
		}

		if (vma_entry_can_be_lazy(vma->e) && !is_stack(item, vaddr))
			ppb_flags |= PPB_LAZY;

		/*
		 * If we're doing incremental dump (parent images
		 * specified) and page is not soft-dirty -- we dump
		 * hole and expect the parent images to contain this
		 * page. The latter would be checked in page-xfer.
		 */

		if (has_parent && page_in_parent(page_info.softdirty)) {
			ret = page_pipe_add_hole(pp, vaddr, PP_HOLE_PARENT);
			st = 0;
		} else {
			ret = page_pipe_add_page(pp, vaddr, ppb_flags);
			if (ppb_flags & PPB_LAZY && opts.lazy_pages)
				st = 1;
			else
				st = 2;
		}

		if (ret) {
			/* Do not do pfn++, just bail out */
			pr_debug("Pagemap full\n");
			break;
		}

		pages[st]++;
	}

	*pvaddr = vaddr;
	cnt_add(CNT_PAGES_SCANNED, nr_scanned);
	cnt_add(CNT_PAGES_SKIPPED_PARENT, pages[0]);
	cnt_add(CNT_PAGES_LAZY, pages[1]);
	cnt_add(CNT_PAGES_WRITTEN, pages[2]);

	pr_info("Pagemap generated: %lu pages (%lu lazy) %lu holes\n", pages[2] + pages[1], pages[1], pages[0]);
	return ret;
}

static struct parasite_dump_pages_args *
prep_dump_pages_args(struct parasite_ctl *ctl, struct vm_area_list *vma_area_list, bool skip_non_trackable)
{
	struct parasite_dump_pages_args *args;
	struct parasite_vma_entry *p_vma;
	struct vma_area *vma;

	args = compel_parasite_args_s(ctl, dump_pages_args_size(vma_area_list));

	p_vma = pargs_vmas(args);
	args->nr_vmas = 0;

	list_for_each_entry(vma, &vma_area_list->h, list) {
		if (!vma_area_is_private(vma, kdat.task_size))
			continue;
		/*
		 * Kernel write to aio ring is not soft-dirty tracked,
		 * so we ignore them at pre-dump.
		 */
		if (vma_entry_is(vma->e, VMA_AREA_AIORING) && skip_non_trackable)
			continue;
		/*
		 * We totally ignore MAP_HUGETLB on pre-dump.
		 * See also generate_vma_iovs() comment.
		 */
		if ((vma->e->flags & MAP_HUGETLB) && skip_non_trackable)
			continue;
		if (vma->e->prot & PROT_READ)
			continue;

		p_vma->start = vma->e->start;
		p_vma->len = vma_area_len(vma);
		p_vma->prot = vma->e->prot;

		args->nr_vmas++;
		p_vma++;
	}

	return args;
}

#define DSA_SHARED_BUF_SIZE_DEFAULT	(128U * 1024U * 1024U)
#define DSA_SHARED_BUF_SIZE_MIN	(64U * 1024U)
#define DSA_SHARED_BUF_SIZE_MAX \
	((unsigned int)((4ULL * 1024ULL * 1024ULL * 1024ULL) - DSA_SHARED_DATA_ALIGN))
#define DSA_HUGEPAGE_2MB_SIZE	(2U * 1024U * 1024U)
#define DSA_HUGEPAGE_1GB_SIZE	(1ULL * 1024ULL * 1024ULL * 1024ULL)
#define DSA_HUGEPAGE_1GB_PAGES	4U
#define DSA_SHARED_BUF_EST_MARGIN_PCT	25U
#define DSA_SHARED_BUF_EST_RESERVE	(16U * 1024U * 1024U)
#define DSA_HUGEPAGE_FREE_PATH	"/sys/kernel/mm/hugepages/hugepages-2048kB/free_hugepages"
#define MEM_DUMP_ASYNC_MIN_PAGES_DEFAULT	4096U

struct dsa_dump_ctx;

struct mem_dump_async {
	pthread_t tid;
	pthread_t dsa_replay_tid;
	struct page_pipe *pp;
	struct page_xfer xfer;
	int xfer_ret;
	int dsa_replay_ret;
	int pid;
	u64 xfer_worker_us;
	u64 dsa_replay_worker_us;
	bool thread_started;
	bool dsa_replay_started;
	bool dsa_live_defer;
	struct dsa_dump_ctx *dsa_ctx_deferred;
};
#define DSA_DESC_SCAN_MAX_COPY_LEN	(128U * 1024U)

#ifndef MADV_POPULATE_READ
#define MADV_POPULATE_READ	22
#endif

static unsigned int dsa_parse_env_u32(const char *name, unsigned int def,
				      unsigned int min, unsigned int max)
{
	const char *env;
	unsigned long long v;
	char *end;

	env = getenv(name);
	if (!env)
		return def;

	errno = 0;
	v = strtoull(env, &end, 10);
	if (errno || end == env)
		return def;

	if (v < (unsigned long long)min)
		return min;
	if (v > (unsigned long long)max)
		return max;

	return (unsigned int)v;
}

static __maybe_unused unsigned int dsa_round_up_u32(unsigned int val, unsigned int align)
{
	unsigned long long rounded;

	if (!align)
		return val;

	rounded = ((unsigned long long)val + align - 1ULL) & ~(unsigned long long)(align - 1ULL);
	if (rounded > UINT_MAX)
		return UINT_MAX;

	return (unsigned int)rounded;
}

static __maybe_unused bool dsa_read_ull_file(const char *path, unsigned long long *value)
{
	FILE *fp;
	char buf[64];
	char *end;

	fp = fopen(path, "re");
	if (!fp)
		return false;

	if (!fgets(buf, sizeof(buf), fp)) {
		fclose(fp);
		return false;
	}

	fclose(fp);

	errno = 0;
	*value = strtoull(buf, &end, 10);
	if (errno || end == buf)
		return false;

	return true;
}

static __maybe_unused unsigned int dsa_shared_buf_size_manual(void)
{
	return dsa_round_up_u32(dsa_parse_env_u32("CRIU_DSA_SHARED_BUF_SIZE",
						 DSA_SHARED_BUF_SIZE_DEFAULT,
						 DSA_SHARED_BUF_SIZE_MIN,
						 DSA_SHARED_BUF_SIZE_MAX),
				 DSA_SHARED_DATA_ALIGN);
}

static __maybe_unused unsigned int dsa_shared_buf_auto_max(void)
{
	unsigned long long free_pages;
	unsigned long long free_bytes;

	if (!dsa_read_ull_file(DSA_HUGEPAGE_FREE_PATH, &free_pages) || !free_pages)
		return DSA_SHARED_BUF_SIZE_MAX;

	if (free_pages > ULLONG_MAX / DSA_HUGEPAGE_2MB_SIZE)
		free_bytes = ULLONG_MAX;
	else
		free_bytes = free_pages * DSA_HUGEPAGE_2MB_SIZE;

	if (free_bytes > DSA_SHARED_BUF_SIZE_MAX)
		free_bytes = DSA_SHARED_BUF_SIZE_MAX;

	return (unsigned int)free_bytes;
}

static __maybe_unused unsigned long long dsa_estimate_dirty_bytes(pid_t pid)
{
	char path[64];
	FILE *fp;
	char line[256];
	unsigned long long private_dirty_kb = 0;
	unsigned long long shared_dirty_kb = 0;
	unsigned long long kb;

	if (snprintf(path, sizeof(path), "/proc/%d/smaps_rollup", pid) >= sizeof(path))
		return 0;

	fp = fopen(path, "re");
	if (!fp)
		return 0;

	while (fgets(line, sizeof(line), fp)) {
		if (sscanf(line, "Private_Dirty: %llu kB", &kb) == 1) {
			private_dirty_kb = kb;
			continue;
		}

		if (sscanf(line, "Shared_Dirty: %llu kB", &kb) == 1)
			shared_dirty_kb = kb;
	}

	fclose(fp);

	if (private_dirty_kb > (ULLONG_MAX - shared_dirty_kb))
		return ULLONG_MAX;

	return (private_dirty_kb + shared_dirty_kb) * 1024ULL;
}

static __maybe_unused unsigned int dsa_shared_buf_size_auto(pid_t target_pid)
{
	unsigned long long dirty_bytes;
	unsigned long long target;
	unsigned int max_size;
	unsigned int final_size;

	dirty_bytes = dsa_estimate_dirty_bytes(target_pid);
	if (!dirty_bytes)
		return dsa_shared_buf_size_manual();

	target = dirty_bytes;
	target += (dirty_bytes * DSA_SHARED_BUF_EST_MARGIN_PCT) / 100ULL;
	target += DSA_SHARED_BUF_EST_RESERVE;

	max_size = dsa_shared_buf_auto_max();
	if (max_size < DSA_SHARED_BUF_SIZE_MIN)
		return dsa_shared_buf_size_manual();

	if (target < DSA_SHARED_BUF_SIZE_MIN)
		target = DSA_SHARED_BUF_SIZE_MIN;
	if (target > max_size)
		target = max_size;

	final_size = dsa_round_up_u32((unsigned int)target, DSA_HUGEPAGE_2MB_SIZE);
	if (final_size > max_size) {
		if (max_size >= DSA_HUGEPAGE_2MB_SIZE)
			final_size = max_size - (max_size % DSA_HUGEPAGE_2MB_SIZE);
		else
			final_size = max_size;
	}

	if (final_size < DSA_SHARED_BUF_SIZE_MIN)
		final_size = DSA_SHARED_BUF_SIZE_MIN;

	final_size = dsa_round_up_u32(final_size, DSA_SHARED_DATA_ALIGN);

	pr_info("DSA_SHARED_MEM_AUTO: pid=%d dirty_bytes=%llu final_size=%u max_size=%u\n",
		target_pid, dirty_bytes, final_size, max_size);

	return final_size;
}

static __maybe_unused unsigned int dsa_shared_buf_size(pid_t target_pid)
{
	if (getenv("CRIU_DSA_SHARED_BUF_SIZE"))
		return dsa_shared_buf_size_manual();

	return dsa_shared_buf_size_auto(target_pid);
}

static __maybe_unused unsigned int mem_dump_async_min_pages(void)
{
	return dsa_parse_env_u32("CRIU_MEM_DUMP_ASYNC_MIN_PAGES",
				 MEM_DUMP_ASYNC_MIN_PAGES_DEFAULT,
				 1,
				 UINT_MAX);
}

static __maybe_unused unsigned long dsa_timespec_delta_us(const struct timespec *start,
					   const struct timespec *end)
{
	long sec;
	long nsec;

	sec = end->tv_sec - start->tv_sec;
	nsec = end->tv_nsec - start->tv_nsec;
	if (nsec < 0) {
		nsec += 1000000000L;
		sec--;
	}

	if (sec < 0)
		return 0;

	return (unsigned long)sec * 1000000UL + (unsigned long)nsec / 1000UL;
}

static __maybe_unused u64 dsa_wall_now_us(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts))
		return 0;

	return (u64)ts.tv_sec * 1000000ULL + (u64)ts.tv_nsec / 1000ULL;
}

static __maybe_unused u64 dsa_wall_delta_us(u64 start, u64 end)
{
	if (!start || end <= start)
		return 0;

	return end - start;
}


enum memdump_phase {
	MEMDUMP_PHASE_PROTECT_VMAS,
	MEMDUMP_PHASE_SETUP,
	MEMDUMP_PHASE_SCAN_BUILD,
	MEMDUMP_PHASE_BASE_RPC,
	MEMDUMP_PHASE_DSA_RPC,
	MEMDUMP_PHASE_IMAGE_WRITE,
	MEMDUMP_PHASE_ASYNC_START,
	MEMDUMP_PHASE_ASYNC_WAIT,
	MEMDUMP_PHASE_DIRTY_RESET,
	MEMDUMP_PHASE_RESTORE_VMAS,
	MEMDUMP_PHASE_CLEANUP,
	MEMDUMP_PHASE_NR,
};

struct memdump_timeline {
	int pid;
	int phase;
	u64 start_us;
	u64 last_us;
	u64 phase_us[MEMDUMP_PHASE_NR];
};

static void memdump_timeline_begin(struct memdump_timeline *tl, int pid,
					   int phase)
{
	memset(tl, 0, sizeof(*tl));
	tl->pid = pid;
	tl->phase = phase;
	tl->start_us = dsa_wall_now_us();
	tl->last_us = tl->start_us;
}

static void memdump_timeline_switch(struct memdump_timeline *tl, int phase)
{
	u64 now;

	if (!tl || !tl->start_us || phase < 0 || phase >= MEMDUMP_PHASE_NR)
		return;

	now = dsa_wall_now_us();
	if (tl->phase >= 0 && tl->phase < MEMDUMP_PHASE_NR)
		tl->phase_us[tl->phase] += dsa_wall_delta_us(tl->last_us, now);
	tl->phase = phase;
	tl->last_us = now;
}

static void memdump_timeline_finish(struct memdump_timeline *tl, int ret,
					    bool dsa_mode, bool deferred_async)
{
	u64 now;
	u64 total_us;
	u64 accounted_us = 0;
	u64 gap_us;
	int i;

	if (!tl || !tl->start_us)
		return;

	now = dsa_wall_now_us();
	if (tl->phase >= 0 && tl->phase < MEMDUMP_PHASE_NR)
		tl->phase_us[tl->phase] += dsa_wall_delta_us(tl->last_us, now);
	total_us = dsa_wall_delta_us(tl->start_us, now);

	for (i = 0; i < MEMDUMP_PHASE_NR; i++)
		accounted_us += tl->phase_us[i];
	gap_us = accounted_us <= total_us ? total_us - accounted_us : 0;

	pr_info("MEMDUMP_TIMELINE: pid=%d mode=%s ret=%d deferred_async=%u total_us=%llu protect_vmas_us=%llu setup_us=%llu scan_build_us=%llu base_rpc_us=%llu dsa_rpc_us=%llu image_write_us=%llu async_start_us=%llu async_wait_us=%llu dirty_reset_us=%llu restore_vmas_us=%llu cleanup_us=%llu accounted_us=%llu gap_us=%llu\n",
		tl->pid, dsa_mode ? "dsa" : "base", ret, deferred_async ? 1 : 0,
		(unsigned long long)total_us,
		(unsigned long long)tl->phase_us[MEMDUMP_PHASE_PROTECT_VMAS],
		(unsigned long long)tl->phase_us[MEMDUMP_PHASE_SETUP],
		(unsigned long long)tl->phase_us[MEMDUMP_PHASE_SCAN_BUILD],
		(unsigned long long)tl->phase_us[MEMDUMP_PHASE_BASE_RPC],
		(unsigned long long)tl->phase_us[MEMDUMP_PHASE_DSA_RPC],
		(unsigned long long)tl->phase_us[MEMDUMP_PHASE_IMAGE_WRITE],
		(unsigned long long)tl->phase_us[MEMDUMP_PHASE_ASYNC_START],
		(unsigned long long)tl->phase_us[MEMDUMP_PHASE_ASYNC_WAIT],
		(unsigned long long)tl->phase_us[MEMDUMP_PHASE_DIRTY_RESET],
		(unsigned long long)tl->phase_us[MEMDUMP_PHASE_RESTORE_VMAS],
		(unsigned long long)tl->phase_us[MEMDUMP_PHASE_CLEANUP],
		(unsigned long long)accounted_us,
		(unsigned long long)gap_us);

	tl->start_us = 0;
}

static bool dsa_dump_enabled(void)
{
	const char *env;

	env = getenv("CRIU_DSA_DUMP");
	if (!env)
		return false;

	return atoi(env) > 0;
}

static int dsa_collect_workqueues(char wq_paths[DSA_DUMP_MAX_WQ][64], int max_wq)
{
	DIR *dir;
	struct dirent *de;
	int nr = 0;
	char path[128];
	char type_path[160];
	char state_path[160];
	char type_buf[32];
	char state_buf[32];
	int type_fd;
	int state_fd;
	ssize_t read_len;
	int i;

	for (i = 0; i < DSA_DUMP_MAX_WQ; i++)
		wq_paths[i][0] = '\0';

	dir = opendir("/dev/dsa");
	if (!dir)
		return 0;

	while ((de = readdir(dir)) && nr < max_wq) {
		int n;

		if (strncmp(de->d_name, "wq", 2))
			continue;

		n = snprintf(type_path, sizeof(type_path),
			     "/sys/bus/dsa/devices/%s/type", de->d_name);
		if (n < 0 || n >= sizeof(type_path))
			continue;

		n = snprintf(state_path, sizeof(state_path),
			     "/sys/bus/dsa/devices/%s/state", de->d_name);
		if (n < 0 || n >= sizeof(state_path))
			continue;

		type_fd = open(type_path, O_RDONLY | O_CLOEXEC);
		if (type_fd < 0)
			continue;

		read_len = read(type_fd, type_buf, sizeof(type_buf) - 1);
		close(type_fd);
		if (read_len <= 0)
			continue;
		type_buf[read_len] = '\0';
		if (strncmp(type_buf, "user", 4))
			continue;

		state_fd = open(state_path, O_RDONLY | O_CLOEXEC);
		if (state_fd < 0)
			continue;

		read_len = read(state_fd, state_buf, sizeof(state_buf) - 1);
		close(state_fd);
		if (read_len <= 0)
			continue;
		state_buf[read_len] = '\0';
		if (strncmp(state_buf, "enabled", 7))
			continue;

		n = snprintf(path, sizeof(path), "/dev/dsa/%.*s",
			     (int)(sizeof(path) - sizeof("/dev/dsa/")), de->d_name);
		if (n < 0 || n >= sizeof(path))
			continue;

		n = snprintf(wq_paths[nr], sizeof(wq_paths[nr]), "/dev/dsa/%s", de->d_name);
		if (n < 0 || n >= sizeof(wq_paths[nr]))
			continue;

		pr_debug("Use DSA wq %s\n", de->d_name);
		nr++;
	}

	closedir(dir);
	return nr;
}

struct dsa_dump_ctx {
	int shared_fd;
	void *shared_buf;
	bool shared_from_before_freeze;
	bool shared_fds_sent;
	bool shared_hugetlb;
	u32 shared_degrade_cnt;
	size_t shared_buf_size;
	size_t shared_map_size;
	int wq_count;
	char wq_paths[DSA_DUMP_MAX_WQ][64];
	struct {
		bool ready;
		int pipe_fd;
		u32 data_off;
		u32 data_bytes;
		u32 batch_id;
	} replay;
};

static void dsa_replay_ctx_init(struct dsa_dump_ctx *ctx);
static int dsa_replay_to_pipe(struct dsa_dump_ctx *ctx);

struct dsa_shared_mem_before_freeze {
	int fd;
	void *buf;
	size_t alloc_size;
	size_t size;
	bool ready;
	u64 total_us;
	u64 create_us;
	u64 truncate_us;
	u64 mmap_us;
};

static struct dsa_shared_mem_before_freeze dsa_shared_mem_bf = {
	.fd = -1,
	.buf = MAP_FAILED,
	.alloc_size = 0,
	.size = 0,
	.ready = false,
	.total_us = 0,
	.create_us = 0,
	.truncate_us = 0,
	.mmap_us = 0,
};

static void dsa_shared_mem_bf_reset(void)
{
	dsa_shared_mem_bf.fd = -1;
	dsa_shared_mem_bf.buf = MAP_FAILED;
	dsa_shared_mem_bf.alloc_size = 0;
	dsa_shared_mem_bf.size = 0;
	dsa_shared_mem_bf.ready = false;
	dsa_shared_mem_bf.total_us = 0;
	dsa_shared_mem_bf.create_us = 0;
	dsa_shared_mem_bf.truncate_us = 0;
	dsa_shared_mem_bf.mmap_us = 0;
}

void dsa_shared_mem_cleanup_after_dump(void)
{
	if (dsa_shared_mem_bf.buf != MAP_FAILED)
		munmap(dsa_shared_mem_bf.buf, dsa_shared_mem_bf.alloc_size);

	if (dsa_shared_mem_bf.fd >= 0)
		close(dsa_shared_mem_bf.fd);

	dsa_shared_mem_bf_reset();
}

int dsa_shared_mem_prepare_before_freeze(void)
{
	int htlb_flags;
	int fd = -1;
	void *buf = MAP_FAILED;
	size_t alloc_size = (size_t)DSA_HUGEPAGE_1GB_PAGES * (size_t)DSA_HUGEPAGE_1GB_SIZE;
	size_t usable_size = DSA_SHARED_BUF_SIZE_MAX;
	struct timespec all_begin;
	struct timespec all_end;
	struct timespec t_begin;
	struct timespec t_end;

	if (!dsa_dump_enabled())
		return 0;

	if (dsa_shared_mem_bf.ready)
		return 0;

	if (dsa_shared_mem_bf.fd >= 0 || dsa_shared_mem_bf.buf != MAP_FAILED)
		dsa_shared_mem_cleanup_after_dump();

	htlb_flags = MFD_CLOEXEC | MFD_HUGETLB | MFD_HUGE_1GB;

	clock_gettime(CLOCK_MONOTONIC, &all_begin);

	clock_gettime(CLOCK_MONOTONIC, &t_begin);
	fd = memfd_create("criu_dsa_dump", htlb_flags);
	clock_gettime(CLOCK_MONOTONIC, &t_end);
	dsa_shared_mem_bf.create_us = dsa_timespec_delta_us(&t_begin, &t_end);
	if (fd < 0) {
		pr_perror("DSA: before-freeze memfd_create failed");
		return -1;
	}

	clock_gettime(CLOCK_MONOTONIC, &t_begin);
	if (ftruncate(fd, alloc_size)) {
		clock_gettime(CLOCK_MONOTONIC, &t_end);
		dsa_shared_mem_bf.truncate_us = dsa_timespec_delta_us(&t_begin, &t_end);
		pr_perror("DSA: before-freeze ftruncate failed");
		goto err;
	}
	clock_gettime(CLOCK_MONOTONIC, &t_end);
	dsa_shared_mem_bf.truncate_us = dsa_timespec_delta_us(&t_begin, &t_end);

	clock_gettime(CLOCK_MONOTONIC, &t_begin);
	buf = mmap(NULL, alloc_size, PROT_READ | PROT_WRITE,
		   MAP_SHARED | MAP_POPULATE, fd, 0);
	clock_gettime(CLOCK_MONOTONIC, &t_end);
	dsa_shared_mem_bf.mmap_us = dsa_timespec_delta_us(&t_begin, &t_end);
	if (buf == MAP_FAILED) {
		pr_perror("DSA: before-freeze mmap MAP_POPULATE failed");
		goto err;
	}

	if (((unsigned long)buf & (DSA_SHARED_DATA_ALIGN - 1)) != 0) {
		pr_err("DSA before-freeze shared buffer alignment is invalid\n");
		goto err;
	}

	clock_gettime(CLOCK_MONOTONIC, &all_end);
	dsa_shared_mem_bf.total_us = dsa_timespec_delta_us(&all_begin, &all_end);
	dsa_shared_mem_bf.fd = fd;
	dsa_shared_mem_bf.buf = buf;
	dsa_shared_mem_bf.alloc_size = alloc_size;
	dsa_shared_mem_bf.size = usable_size;
	dsa_shared_mem_bf.ready = true;

	pr_info("DSA_SHARED_MEM_PREPARE: mode=hugetlb_1gb pages=%u alloc_size=%zu usable_size=%zu create_us=%llu truncate_us=%llu mmap_us=%llu total_us=%llu\n",
		DSA_HUGEPAGE_1GB_PAGES,
		alloc_size,
		usable_size,
		(unsigned long long)dsa_shared_mem_bf.create_us,
		(unsigned long long)dsa_shared_mem_bf.truncate_us,
		(unsigned long long)dsa_shared_mem_bf.mmap_us,
		(unsigned long long)dsa_shared_mem_bf.total_us);

	return 0;

err:
	if (buf != MAP_FAILED)
		munmap(buf, alloc_size);
	if (fd >= 0)
		close(fd);

	dsa_shared_mem_bf_reset();
	return -1;
}

static int dsa_take_shared_mem_before_freeze(struct dsa_dump_ctx *ctx, pid_t target_pid)
{
	if (!dsa_shared_mem_bf.ready || dsa_shared_mem_bf.fd < 0 ||
	    dsa_shared_mem_bf.buf == MAP_FAILED || !dsa_shared_mem_bf.size) {
		pr_err("DSA strict: before-freeze shared memory is not ready for pid %d\n",
		       target_pid);
		return -1;
	}

	ctx->shared_fd = dup(dsa_shared_mem_bf.fd);
	if (ctx->shared_fd < 0) {
		pr_perror("DSA: dup before-freeze shared fd failed");
		return -1;
	}

	ctx->shared_buf = dsa_shared_mem_bf.buf;
	ctx->shared_buf_size = dsa_shared_mem_bf.size;
	ctx->shared_map_size = dsa_shared_mem_bf.alloc_size;
	ctx->shared_from_before_freeze = true;

	return 0;
}

static int dsa_dump_ctx_init(struct dsa_dump_ctx *ctx, pid_t target_pid)
{
	int ret;

	if (!ctx)
		return -1;

	if (ctx->shared_fd >= 0)
		return 0;

	ctx->shared_from_before_freeze = false;
	ctx->shared_hugetlb = true;
	ctx->shared_degrade_cnt = 0;

	ctx->wq_count = dsa_collect_workqueues(ctx->wq_paths, DSA_DUMP_MAX_WQ);
	if (ctx->wq_count <= 0) {
		pr_info("DSA dump requested, but no /dev/dsa workqueue is available\n");
		return 1;
	}

	ret = dsa_take_shared_mem_before_freeze(ctx, target_pid);
	if (ret)
		return ret;

	if (((unsigned long)ctx->shared_buf & (DSA_SHARED_DATA_ALIGN - 1)) != 0) {
		pr_err("DSA shared buffer alignment is invalid\n");
		return -1;
	}
	pr_info("DSA_SHARED_MEM_MODE: mode=%s pid=%d shared_buf_size=%zu degrade_count=%u\n",
		ctx->shared_hugetlb ? "hugetlb" : "normal_memfd", target_pid,
		ctx->shared_buf_size, ctx->shared_degrade_cnt);

	ctx->shared_fds_sent = false;
	dsa_replay_ctx_init(ctx);

	return 0;
}

static int dsa_dump_ctx_fini(struct dsa_dump_ctx *ctx)
{
	int ret = 0;

	if (!ctx)
		return 0;

	if (ctx->shared_buf != MAP_FAILED && !ctx->shared_from_before_freeze)
		munmap(ctx->shared_buf, ctx->shared_buf_size);
	if (ctx->shared_fd >= 0)
		close(ctx->shared_fd);
	ctx->shared_fd = -1;
	ctx->shared_buf = MAP_FAILED;
	ctx->shared_map_size = 0;
	ctx->shared_from_before_freeze = false;

	return ret;
}

static int dsa_vmsplice_to_pipe(int pipe_fd, void *buf, size_t len,
				u32 batch_id)
{
	size_t done = 0;

	while (done < len) {
		struct iovec iov = {
			.iov_base = (char *)buf + done,
			.iov_len = len - done,
		};
		ssize_t ret;

		ret = vmsplice(pipe_fd, &iov, 1,
			       SPLICE_F_GIFT | SPLICE_F_NONBLOCK);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN) {
				struct pollfd pfd = {
					.fd = pipe_fd,
					.events = POLLOUT,
				};
				if (poll(&pfd, 1, -1) < 0) {
					pr_perror("DSA vmsplice poll failed (batch=%u)",
						 batch_id);
					return -1;
				}
				continue;
			}
			pr_perror("DSA vmsplice failed (batch=%u)", batch_id);
			return -1;
		}
		if (!ret) {
			pr_err("DSA vmsplice returned 0 (batch=%u)\n", batch_id);
			return -1;
		}
		done += ret;
	}

	return 0;
}

static void dsa_replay_ctx_init(struct dsa_dump_ctx *ctx)
{
	ctx->replay.ready = false;
	ctx->replay.pipe_fd = -1;
	ctx->replay.data_off = 0;
	ctx->replay.data_bytes = 0;
	ctx->replay.batch_id = 0;
}

static int dsa_replay_to_pipe(struct dsa_dump_ctx *ctx)
{
	int ret;

	if (!ctx || !ctx->replay.ready)
		return 0;

	if (ctx->replay.pipe_fd < 0 || ctx->shared_buf == MAP_FAILED) {
		pr_err("DSA replay missing pipe or shared buffer\n");
		return -1;
	}

	ret = dsa_vmsplice_to_pipe(ctx->replay.pipe_fd,
				   (u8 *)ctx->shared_buf + ctx->replay.data_off,
				   ctx->replay.data_bytes,
				   ctx->replay.batch_id);

	ctx->replay.ready = false;
	return ret;
}

static void dsa_abort_replay_pipe(struct page_pipe *pp, int pipe_fd)
{
	struct page_pipe_buf *ppb;
	bool closed = false;

	if (!pp || pipe_fd < 0)
		return;

	list_for_each_entry(ppb, &pp->bufs, l) {
		if (ppb->p[1] != pipe_fd)
			continue;
		if (!closed) {
			close(pipe_fd);
			closed = true;
		}
		ppb->p[1] = -1;
	}
}

/*
 * TODO(TEMP_CDF): This is temporary instrumentation and may be removed later.
 * The samples are dirty extents discovered during DSA pagemap scan, before
 * DSA descriptors are split, merged, or flushed into batches.
 */
/* TODO(TEMP_CDF): BEGIN temporary dump CDF stats */
struct temp_cdf_stats {
	u64 *size_samples;
	u64 *gap_samples;
	u64 *ratio_samples_q20;
	size_t size_nr;
	size_t size_cap;
	size_t gap_nr;
	size_t gap_cap;
	size_t ratio_nr;
	size_t ratio_cap;
	u64 gap_zero_count;
	u64 gap_negative_or_overlap_count;
	u64 seq_reset_count;
	bool has_prev;
	u64 prev_start;
	u64 prev_len;
	bool enabled;
};

static struct temp_cdf_stats g_temp_cdf_stats;

static int temp_cdf_ensure_cap(u64 **arr, size_t *cap, size_t need)
{
	void *tmp;
	size_t new_cap;

	if (need <= *cap)
		return 0;

	new_cap = *cap ? *cap : 1024;
	while (new_cap < need)
		new_cap <<= 1;

	tmp = xrealloc(*arr, new_cap * sizeof(**arr));
	if (!tmp)
		return -1;

	*arr = tmp;
	*cap = new_cap;
	return 0;
}

static int temp_cdf_push_u64(u64 **arr, size_t *nr, size_t *cap, u64 v)
{
	if (temp_cdf_ensure_cap(arr, cap, *nr + 1))
		return -1;
	(*arr)[(*nr)++] = v;
	return 0;
}

static void temp_cdf_reset_prev(void)
{
	g_temp_cdf_stats.has_prev = false;
	g_temp_cdf_stats.prev_start = 0;
	g_temp_cdf_stats.prev_len = 0;
}

static void temp_cdf_collect_one(u64 start, u64 len)
{
	s64 gap;
	u64 prev_end;
	u64 ratio_q20;

	if (!g_temp_cdf_stats.enabled)
		return;

	if (temp_cdf_push_u64(&g_temp_cdf_stats.size_samples,
			      &g_temp_cdf_stats.size_nr,
			      &g_temp_cdf_stats.size_cap,
			      len))
		return;

	if (g_temp_cdf_stats.has_prev) {
		prev_end = g_temp_cdf_stats.prev_start + g_temp_cdf_stats.prev_len;
		gap = (s64)start - (s64)prev_end;

		if (gap > 0) {
			if (!temp_cdf_push_u64(&g_temp_cdf_stats.gap_samples,
					       &g_temp_cdf_stats.gap_nr,
					       &g_temp_cdf_stats.gap_cap,
					       (u64)gap)) {
				ratio_q20 = ((g_temp_cdf_stats.prev_len + len) << 20) /
					(u64)gap;
				(void)temp_cdf_push_u64(&g_temp_cdf_stats.ratio_samples_q20,
							&g_temp_cdf_stats.ratio_nr,
							&g_temp_cdf_stats.ratio_cap,
							ratio_q20);
			}
		} else if (gap == 0) {
			g_temp_cdf_stats.gap_zero_count++;
		} else {
			g_temp_cdf_stats.gap_negative_or_overlap_count++;
		}
	}

	g_temp_cdf_stats.prev_start = start;
	g_temp_cdf_stats.prev_len = len;
	g_temp_cdf_stats.has_prev = true;
}

void temp_cdf_dump_begin(void)
{
	memset(&g_temp_cdf_stats, 0, sizeof(g_temp_cdf_stats));
	g_temp_cdf_stats.enabled = true;
	temp_cdf_reset_prev();
}

void temp_cdf_dump_task_boundary(void)
{
	if (!g_temp_cdf_stats.enabled)
		return;
	if (g_temp_cdf_stats.has_prev)
		g_temp_cdf_stats.seq_reset_count++;
	temp_cdf_reset_prev();
}

static int temp_cdf_write_raw_values(int fd, const char *metric,
				     const u64 *samples, size_t nr)
{
	char line[128];
	size_t i;

	for (i = 0; i < nr; i++) {
		int off;

		off = snprintf(line, sizeof(line),
			       "TEMP_CDF_VALUE: metric=%s value=%llu\n",
			       metric, (unsigned long long)samples[i]);
		if (off < 0 || off >= sizeof(line))
			return -1;
		if (write_all(fd, line, off) != off)
			return -1;
	}

	return 0;
}

static int temp_cdf_write_raw_file(void)
{
	const char path[] = "temp-cdf.raw";
	char line[256];
	int fd;
	int off;
	int ret = -1;

	fd = openat(get_service_fd(IMG_FD_OFF), path,
		    O_CREAT | O_TRUNC | O_WRONLY, 0600);
	if (fd < 0) {
		pr_perror("Can't open TEMP_CDF raw file");
		return -1;
	}

	off = snprintf(line, sizeof(line),
		       "TEMP_CDF_COUNTS: size=%zu gap=%zu ratio_q20=%zu gap_zero=%llu gap_neg_or_overlap=%llu seq_reset=%llu\n",
		       g_temp_cdf_stats.size_nr,
		       g_temp_cdf_stats.gap_nr,
		       g_temp_cdf_stats.ratio_nr,
		       (unsigned long long)g_temp_cdf_stats.gap_zero_count,
		       (unsigned long long)g_temp_cdf_stats.gap_negative_or_overlap_count,
		       (unsigned long long)g_temp_cdf_stats.seq_reset_count);
	if (off < 0 || off >= sizeof(line))
		goto out;
	if (write_all(fd, line, off) != off)
		goto out;

	if (temp_cdf_write_raw_values(fd, "size", g_temp_cdf_stats.size_samples,
				      g_temp_cdf_stats.size_nr))
		goto out;
	if (temp_cdf_write_raw_values(fd, "gap", g_temp_cdf_stats.gap_samples,
				      g_temp_cdf_stats.gap_nr))
		goto out;
	if (temp_cdf_write_raw_values(fd, "ratio_q20",
				      g_temp_cdf_stats.ratio_samples_q20,
				      g_temp_cdf_stats.ratio_nr))
		goto out;

	pr_info("TEMP_CDF_FILE: path=%s\n", path);
	ret = 0;
out:
	if (close(fd))
		ret = -1;
	return ret;
}

void temp_cdf_dump_finalize_log(void)
{
	if (!g_temp_cdf_stats.enabled)
		return;

	pr_info("TEMP_CDF_COUNTS: size=%zu gap=%zu ratio_q20=%zu gap_zero=%llu gap_neg_or_overlap=%llu seq_reset=%llu\n",
		g_temp_cdf_stats.size_nr,
		g_temp_cdf_stats.gap_nr,
		g_temp_cdf_stats.ratio_nr,
		(unsigned long long)g_temp_cdf_stats.gap_zero_count,
		(unsigned long long)g_temp_cdf_stats.gap_negative_or_overlap_count,
		(unsigned long long)g_temp_cdf_stats.seq_reset_count);

	if (temp_cdf_write_raw_file())
		pr_err("TEMP_CDF raw file write failed\n");
}

void temp_cdf_dump_abort(void)
{
	g_temp_cdf_stats.enabled = false;
	temp_cdf_reset_prev();
	xfree(g_temp_cdf_stats.size_samples);
	xfree(g_temp_cdf_stats.gap_samples);
	xfree(g_temp_cdf_stats.ratio_samples_q20);
	memset(&g_temp_cdf_stats, 0, sizeof(g_temp_cdf_stats));
}
/* TODO(TEMP_CDF): END temporary dump CDF stats */

struct dsa_desc_scan_ctx {
	struct parasite_ctl *ctl;
	struct parasite_dump_pages_args *args;
	struct dsa_dump_ctx *dsa_ctx;
	struct memdump_timeline *timeline;

	unsigned int args_nr_vmas_saved;
	unsigned int args_add_prot_saved;
	unsigned int args_off_saved;
	void *args_vmas_saved;
	size_t args_vmas_sz;

	int dsa_pipe_fd;
	struct parasite_dsa_dump_pages_args rpc_args;
	pthread_t rpc_tid;
	bool rpc_started;
	volatile bool rpc_done;
	int rpc_ret;

	struct parasite_dsa_stream_hdr *stream_hdr;
	struct parasite_dsa_stream_slot *stream_slots;
	u32 desc_area_off;
	u32 desc_head;
	u32 desc_limit;
	u32 payload_base;
	u32 payload_head;
	struct dsa_dump_descriptor descs[DSA_STREAM_SLOT_DESC_CAP];
	u32 current_slot;
	u32 produced_slots;
	u32 desc_count;
	u32 slot_payload_off;
	u32 slot_payload_bytes;
	u64 producer_wait_slot_us;
	u64 finish_wait_us;
	u64 stream_bytes;
	u64 stream_descs;

	bool raw_has_extent;
	u64 raw_start;
	u64 raw_len;
	u64 desc_seq_out_of_order;
	u64 desc_seq_discont;
	u64 desc_seq_total;
};

static inline u32 dsa_shared_load_u32(volatile u32 *p)
{
	return __atomic_load_n(p, __ATOMIC_ACQUIRE);
}

static inline void dsa_shared_store_u32(volatile u32 *p, u32 v)
{
	__atomic_store_n(p, v, __ATOMIC_RELEASE);
}

static inline void dsa_stream_cpu_relax(void)
{
#if defined(__x86_64__)
	asm volatile("pause" ::: "memory");
#else
	asm volatile("" ::: "memory");
#endif
}

#define DSA_STREAM_SLOT_PAYLOAD_TARGET (2U * 1024U * 1024U)
#define DSA_STREAM_DESC_REGION_BYTES (64U * 1024U * 1024U)

static void dsa_stream_restore_parasite_args(struct dsa_desc_scan_ctx *sc)
{
	if (!sc || !sc->args)
		return;

	sc->args->nr_vmas = sc->args_nr_vmas_saved;
	sc->args->add_prot = sc->args_add_prot_saved;
	sc->args->off = sc->args_off_saved;
	if (sc->args_vmas_saved && sc->args_vmas_sz)
		memcpy(pargs_vmas(sc->args), sc->args_vmas_saved, sc->args_vmas_sz);
}

static void *dsa_stream_rpc_thread(void *arg)
{
	struct dsa_desc_scan_ctx *sc = arg;

	sc->rpc_ret = parasite_dsa_dump_pages_seized(sc->ctl, &sc->rpc_args,
						       sc->dsa_ctx->shared_fd, NULL,
						       sc->dsa_ctx->wq_count);
	__atomic_store_n(&sc->rpc_done, true, __ATOMIC_RELEASE);
	return NULL;
}

static int dsa_stream_layout_init(struct dsa_desc_scan_ctx *sc)
{
	u8 *shared_u8 = sc->dsa_ctx->shared_buf;
	u32 slots_off;
	u32 desc_area_off;
	u32 payload_base;
	u32 desc_area_bytes;
	u32 i;
	unsigned int j;

	if (sc->dsa_ctx->shared_buf_size > UINT_MAX) {
		pr_err("DSA strict: streaming shared buffer exceeds u32 size=%zu\n",
		       sc->dsa_ctx->shared_buf_size);
		return -1;
	}

	slots_off = round_up(sizeof(struct parasite_dsa_stream_hdr), 64U);
	desc_area_off = round_up(slots_off +
				 DSA_STREAM_SLOT_COUNT * sizeof(struct parasite_dsa_stream_slot),
				 64U);
	desc_area_bytes = DSA_STREAM_DESC_REGION_BYTES;
	payload_base = round_up(desc_area_off + desc_area_bytes,
			       DSA_SHARED_DATA_ALIGN);

	if (payload_base >= sc->dsa_ctx->shared_buf_size) {
		pr_err("DSA strict: streaming metadata does not fit shared buffer payload_base=%u shared=%zu\n",
		       payload_base, sc->dsa_ctx->shared_buf_size);
		return -1;
	}

	memset(shared_u8, 0, desc_area_off);
	sc->stream_hdr = (struct parasite_dsa_stream_hdr *)shared_u8;
	sc->stream_slots = (struct parasite_dsa_stream_slot *)(shared_u8 + slots_off);
	sc->desc_area_off = desc_area_off;
	sc->desc_head = desc_area_off;
	sc->desc_limit = payload_base;
	sc->payload_base = payload_base;
	sc->payload_head = payload_base;
	sc->current_slot = 0;
	sc->produced_slots = 0;
	sc->desc_count = 0;
	sc->slot_payload_off = payload_base;
	sc->slot_payload_bytes = 0;

	sc->stream_hdr->base.magic = PARASITE_DSA_SHM_HDR_MAGIC;
	sc->stream_hdr->base.version = PARASITE_DSA_SHM_HDR_VERSION;
	sc->stream_hdr->base.flags = PARASITE_DSA_SHM_F_STREAM;
	sc->stream_hdr->base.data_off = payload_base;
	sc->stream_hdr->slot_count = DSA_STREAM_SLOT_COUNT;
	sc->stream_hdr->slot_desc_cap = DSA_STREAM_SLOT_DESC_CAP;
	sc->stream_hdr->slots_off = slots_off;
	sc->stream_hdr->desc_area_off = desc_area_off;
	sc->stream_hdr->payload_base = payload_base;
	sc->stream_hdr->payload_limit = sc->dsa_ctx->shared_buf_size;
	dsa_shared_store_u32(&sc->stream_hdr->payload_head, payload_base);

	for (i = 0; i < DSA_STREAM_SLOT_COUNT; i++)
		dsa_shared_store_u32(&sc->stream_slots[i].state, DSA_STREAM_SLOT_EMPTY);

	memset(&sc->rpc_args, 0, sizeof(sc->rpc_args));
	sc->rpc_args.shared_buf_addr = 0;
	sc->rpc_args.shared_buf_size = sc->dsa_ctx->shared_buf_size;
	sc->rpc_args.shared_map_size = sc->dsa_ctx->shared_map_size ?
		sc->dsa_ctx->shared_map_size : sc->dsa_ctx->shared_buf_size;
	sc->rpc_args.hdr_off = 0;
	sc->rpc_args.buf_write_offset = payload_base;
	sc->rpc_args.batch_id = 1;
	sc->rpc_args.is_last_batch = true;
	sc->rpc_args.wq_count = sc->dsa_ctx->wq_count;
	sc->rpc_args.use_shared_buf_fd = !sc->dsa_ctx->shared_fds_sent;
	sc->rpc_args.use_wq_fd = 0;
	sc->rpc_args.wq_policy = DSA_WQ_POLICY_LPT;

	for (j = 0; j < (unsigned int)sc->dsa_ctx->wq_count; j++) {
		size_t path_len;

		path_len = strnlen(sc->dsa_ctx->wq_paths[j],
				   sizeof(sc->rpc_args.wq_paths[j]) - 1);
		memcpy(sc->rpc_args.wq_paths[j], sc->dsa_ctx->wq_paths[j], path_len);
		sc->rpc_args.wq_paths[j][path_len] = '\0';
	}

	return 0;
}

#define DSA_STREAM_CONSUMER_READY_TIMEOUT_US (5000000ULL)

static int dsa_stream_start_rpc(struct dsa_desc_scan_ctx *sc)
{
	u64 wait_start;

	sc->rpc_done = false;
	if (pthread_create(&sc->rpc_tid, NULL, dsa_stream_rpc_thread, sc)) {
		pr_err("DSA strict: can't create streaming RPC thread\n");
		return -1;
	}
	sc->rpc_started = true;
	sc->dsa_ctx->shared_fds_sent = true;

	wait_start = dsa_wall_now_us();
	while (!dsa_shared_load_u32(&sc->stream_hdr->consumer_ready)) {
		if (__atomic_load_n(&sc->rpc_done, __ATOMIC_ACQUIRE)) {
			pr_err("DSA streaming RPC ended before consumer ready: ret=%d op_ret=%d\n",
			       sc->rpc_ret, sc->rpc_args.op_ret);
			return -1;
		}
		if (dsa_wall_delta_us(wait_start, dsa_wall_now_us()) >
		    DSA_STREAM_CONSUMER_READY_TIMEOUT_US) {
			pr_err("DSA streaming consumer ready timeout producer_seq=%u error=%d finish=%u\n",
			       dsa_shared_load_u32(&sc->stream_hdr->producer_seq),
			       (s32)dsa_shared_load_u32(&sc->stream_hdr->error),
			       dsa_shared_load_u32(&sc->stream_hdr->finish));
			return -1;
		}
		dsa_stream_cpu_relax();
	}

	return 0;
}

static int dsa_stream_join_rpc(struct dsa_desc_scan_ctx *sc)
{
	u64 wait_start;

	if (!sc->rpc_started)
		return 0;

	wait_start = dsa_wall_now_us();
	if (pthread_join(sc->rpc_tid, NULL)) {
		pr_err("DSA strict: can't join streaming RPC thread\n");
		return -1;
	}
	sc->finish_wait_us += dsa_wall_delta_us(wait_start, dsa_wall_now_us());
	sc->rpc_started = false;

	__atomic_thread_fence(__ATOMIC_ACQUIRE);
	if (sc->stream_hdr) {
		sc->rpc_args.op_ret = sc->stream_hdr->result_op_ret;
		sc->rpc_args.total_copied = sc->stream_hdr->result_total_copied;
		sc->rpc_args.completed_count = sc->stream_hdr->result_completed_count;
		sc->rpc_args.failed_idx = sc->stream_hdr->result_failed_idx;
		sc->rpc_args.failed_status = sc->stream_hdr->result_failed_status;
		sc->rpc_args.new_buf_offset = sc->stream_hdr->result_new_buf_offset;
		sc->rpc_args.setup_shared_recv_fd_us =
			sc->stream_hdr->result_setup_shared_recv_fd_us;
		sc->rpc_args.setup_shared_mmap_us =
			sc->stream_hdr->result_setup_shared_mmap_us;
		sc->rpc_args.cleanup_munmap_us =
			sc->stream_hdr->result_cleanup_munmap_us;
		sc->rpc_args.cleanup_close_us =
			sc->stream_hdr->result_cleanup_close_us;
		sc->rpc_args.setup_shared_us = sc->stream_hdr->result_setup_shared_us;
	}
	dsa_stream_restore_parasite_args(sc);

	if (sc->rpc_ret || sc->rpc_args.op_ret) {
		pr_err("DSA streaming RPC failed: ret=%d op_ret=%d failed_idx=%d status=%u completed=%u copied=%u\n",
		       sc->rpc_ret, sc->rpc_args.op_ret, sc->rpc_args.failed_idx,
		       sc->rpc_args.failed_status, sc->rpc_args.completed_count,
		       sc->rpc_args.total_copied);
		return -1;
	}

	return 0;
}

static struct dsa_dump_descriptor *dsa_stream_slot_desc(struct dsa_desc_scan_ctx *sc,
					       u32 slot_idx)
{
	(void)slot_idx;
	return sc->descs;
}

#define DSA_STREAM_WAIT_SLOT_TIMEOUT_US (5000000ULL)

static int dsa_stream_wait_slot(struct dsa_desc_scan_ctx *sc, u32 slot_idx)
{
	struct parasite_dsa_stream_slot *slot = &sc->stream_slots[slot_idx];
	u64 wait_start = 0;

	while (1) {
		u32 state = dsa_shared_load_u32(&slot->state);

		if (state == DSA_STREAM_SLOT_EMPTY)
			break;
		if (state == DSA_STREAM_SLOT_DONE) {
			dsa_shared_store_u32(&slot->state, DSA_STREAM_SLOT_EMPTY);
			break;
		}
		if (state == DSA_STREAM_SLOT_ERROR ||
		    dsa_shared_load_u32(&sc->stream_hdr->error)) {
			pr_err("DSA streaming slot error state=%u hdr_error=%d status=%d seq=%u\n",
			       state, (s32)dsa_shared_load_u32(&sc->stream_hdr->error),
			       (s32)slot->status, slot->seq);
			return -1;
		}
		if (__atomic_load_n(&sc->rpc_done, __ATOMIC_ACQUIRE)) {
			pr_err("DSA streaming RPC ended while waiting slot=%u state=%u ret=%d op_ret=%d\n",
			       slot_idx, state, sc->rpc_ret, sc->rpc_args.op_ret);
			return -1;
		}
		if (!wait_start)
			wait_start = dsa_wall_now_us();
		else if (dsa_wall_delta_us(wait_start, dsa_wall_now_us()) >
			 DSA_STREAM_WAIT_SLOT_TIMEOUT_US) {
			pr_err("DSA streaming wait slot timeout slot=%u state=%u seq=%u produced=%u producer_seq=%u consumer_seq=%u finish=%u error=%d payload_head=%u\n",
			       slot_idx, state, slot->seq, sc->produced_slots,
			       dsa_shared_load_u32(&sc->stream_hdr->producer_seq),
			       dsa_shared_load_u32(&sc->stream_hdr->consumer_seq),
			       dsa_shared_load_u32(&sc->stream_hdr->finish),
			       (s32)dsa_shared_load_u32(&sc->stream_hdr->error),
			       dsa_shared_load_u32(&sc->stream_hdr->payload_head));
			dsa_shared_store_u32(&sc->stream_hdr->error, (u32)-ETIMEDOUT);
			dsa_shared_store_u32(&sc->stream_hdr->finish, 1);
			return -1;
		}
		dsa_stream_cpu_relax();
	}

	if (wait_start)
		sc->producer_wait_slot_us += dsa_wall_delta_us(wait_start,
							       dsa_wall_now_us());
	return 0;
}

static void dsa_desc_scan_reset_batch(struct dsa_desc_scan_ctx *sc)
{
	sc->desc_count = 0;
	sc->slot_payload_off = sc->payload_head;
	sc->slot_payload_bytes = 0;
}

static void dsa_desc_scan_raw_flush(struct dsa_desc_scan_ctx *sc)
{
	if (!sc->raw_has_extent)
		return;

	temp_cdf_collect_one(sc->raw_start, sc->raw_len);
	sc->raw_has_extent = false;
	sc->raw_start = 0;
	sc->raw_len = 0;
}

static void dsa_desc_scan_raw_append(struct dsa_desc_scan_ctx *sc,
				     u64 src_addr, u64 copy_len)
{
	if (sc->raw_has_extent && src_addr == sc->raw_start + sc->raw_len) {
		sc->raw_len += copy_len;
		return;
	}

	dsa_desc_scan_raw_flush(sc);
	sc->raw_has_extent = true;
	sc->raw_start = src_addr;
	sc->raw_len = copy_len;
}

static int dsa_stream_flush_slot(struct dsa_desc_scan_ctx *sc)
{
	struct parasite_dsa_stream_slot *slot;
	struct dsa_dump_descriptor *slot_desc;
	u32 slot_idx;
	u32 desc_off;
	u32 desc_sum = 0;
	u32 i;

	if (!sc->desc_count)
		return 0;

	slot_idx = sc->current_slot;
	if (dsa_stream_wait_slot(sc, slot_idx))
		return -1;

	slot = &sc->stream_slots[slot_idx];
	desc_off = sc->desc_head;
	slot_desc = dsa_stream_slot_desc(sc, slot_idx);
	for (i = 0; i < sc->desc_count; i++)
		desc_sum += slot_desc[i].copy_len;
	if (desc_off + sc->desc_count * sizeof(struct dsa_dump_descriptor) > sc->desc_limit) {
		pr_err("DSA strict: streaming descriptor region exhausted used=%u append=%zu limit=%u\n",
		       desc_off - sc->desc_area_off,
		       (size_t)sc->desc_count * sizeof(struct dsa_dump_descriptor),
		       sc->desc_limit - sc->desc_area_off);
		dsa_shared_store_u32(&sc->stream_hdr->error, (u32)-ENOSPC);
		return -1;
	}
	memcpy((u8 *)sc->dsa_ctx->shared_buf + desc_off, slot_desc,
	       sc->desc_count * sizeof(struct dsa_dump_descriptor));
	if (desc_sum != sc->slot_payload_bytes)
		pr_warn("DSA streaming producer size adjusted desc_sum=%u payload_bytes=%u descs=%u\n",
			desc_sum, sc->slot_payload_bytes, sc->desc_count);

	slot->seq = sc->produced_slots;
	slot->desc_off = desc_off;
	slot->desc_count = sc->desc_count;
	slot->payload_off = sc->slot_payload_off;
	slot->payload_bytes = desc_sum;
	slot->copied_bytes = 0;
	slot->status = 0;


	__atomic_thread_fence(__ATOMIC_RELEASE);
	dsa_shared_store_u32(&slot->state, DSA_STREAM_SLOT_READY);
	sc->desc_head = desc_off + sc->desc_count * sizeof(struct dsa_dump_descriptor);
	sc->produced_slots++;
	dsa_shared_store_u32(&sc->stream_hdr->producer_seq, sc->produced_slots);
	sc->current_slot = sc->produced_slots % DSA_STREAM_SLOT_COUNT;
	dsa_desc_scan_reset_batch(sc);
	return 0;
}

static int dsa_desc_scan_batch_append(struct dsa_desc_scan_ctx *sc,
				      u64 src_addr, u32 copy_len)
{
	struct dsa_dump_descriptor *slot_desc;
	u32 merge_idx = 0;
	bool merge_prev = false;

	if (copy_len > sc->stream_hdr->payload_limit - sc->payload_head) {
		pr_err("DSA strict: streaming payload exhausted used=%u append=%u limit=%u\n",
		       sc->payload_head - sc->payload_base, copy_len,
		       sc->stream_hdr->payload_limit - sc->payload_base);
		dsa_shared_store_u32(&sc->stream_hdr->error, (u32)-ENOSPC);
		return -1;
	}

	if (sc->desc_count == DSA_STREAM_SLOT_DESC_CAP ||
	    (sc->desc_count &&
	     sc->slot_payload_bytes + copy_len > DSA_STREAM_SLOT_PAYLOAD_TARGET)) {
		if (dsa_stream_flush_slot(sc))
			return -1;
	}

	slot_desc = dsa_stream_slot_desc(sc, sc->current_slot);
	if (sc->desc_count > 0) {
		u64 prev_src = slot_desc[sc->desc_count - 1].src_addr;
		u32 prev_len = slot_desc[sc->desc_count - 1].copy_len;
		u64 expected = prev_src + prev_len;

		if (src_addr == expected && prev_len <= UINT_MAX - copy_len &&
		    prev_len + copy_len <= DSA_DESC_SCAN_MAX_COPY_LEN) {
			merge_prev = true;
			merge_idx = sc->desc_count - 1;
		}

		sc->desc_seq_total++;
		if (src_addr < prev_src)
			sc->desc_seq_out_of_order++;
		else if (src_addr != expected)
			sc->desc_seq_discont++;
	}

	if (merge_prev) {
		slot_desc[merge_idx].copy_len += copy_len;
	} else {
		slot_desc[sc->desc_count].src_addr = src_addr;
		slot_desc[sc->desc_count].copy_len = copy_len;
		slot_desc[sc->desc_count].reserved0 = 0;
		sc->desc_count++;
		sc->stream_descs++;
	}

	sc->payload_head += copy_len;
	sc->slot_payload_bytes += copy_len;
	sc->stream_bytes += copy_len;
	dsa_shared_store_u32(&sc->stream_hdr->payload_head, sc->payload_head);
	return 0;
}

static int dsa_stream_finish(struct dsa_desc_scan_ctx *sc)
{
	if (dsa_stream_flush_slot(sc))
		return -1;

	sc->stream_hdr->base.data_bytes = sc->payload_head - sc->payload_base;
	dsa_shared_store_u32(&sc->stream_hdr->finish, 1);

	if (dsa_stream_join_rpc(sc))
		return -1;

	if (sc->rpc_args.total_copied != sc->stream_bytes ||
	    sc->rpc_args.new_buf_offset != sc->payload_head) {
		pr_err("DSA streaming copied size mismatch: expected copied=%llu off=%u got copied=%u off=%u\n",
		       (unsigned long long)sc->stream_bytes, sc->payload_head,
		       sc->rpc_args.total_copied, sc->rpc_args.new_buf_offset);
		return -1;
	}

	sc->dsa_ctx->replay.ready = true;
	sc->dsa_ctx->replay.pipe_fd = sc->dsa_pipe_fd;
	sc->dsa_ctx->replay.data_off = sc->payload_base;
	sc->dsa_ctx->replay.data_bytes = sc->payload_head - sc->payload_base;
	sc->dsa_ctx->replay.batch_id = 1;

	pr_info("DSA_SHARED_MAP_TIMING: recv_fd_us=%llu mmap_us=%llu munmap_us=%llu close_us=%llu setup_shared_us=%llu\n",
		(unsigned long long)sc->rpc_args.setup_shared_recv_fd_us,
		(unsigned long long)sc->rpc_args.setup_shared_mmap_us,
		(unsigned long long)sc->rpc_args.cleanup_munmap_us,
		(unsigned long long)sc->rpc_args.cleanup_close_us,
		(unsigned long long)sc->rpc_args.setup_shared_us);

	return 0;
}

static int drain_pages(struct page_pipe *pp, struct parasite_ctl *ctl,
		       struct parasite_dump_pages_args *args)
{
	struct page_pipe_buf *ppb;
	unsigned int args_off;
	int ret = 0;

	args_off = args->off;


	/*
	 * DSA RPC uses the same parasite args area and may leave header fields
	 * clobbered on failure paths; restore the caller-visible offset before
	 * falling back to legacy DUMPPAGES.
	 */
	args->off = args_off;

	debug_show_page_pipe(pp);

	/* Step 2 -- grab pages into page-pipe */
	list_for_each_entry(ppb, &pp->bufs, l) {
		args->nr_segs = ppb->nr_segs;
		args->nr_pages = ppb->pages_in;
		args->off = args_off;
		pr_debug("PPB: %ld pages %d segs %u pipe %d off\n", args->nr_pages, args->nr_segs, ppb->pipe_size,
			 args->off);

		ret = compel_rpc_call(PARASITE_CMD_DUMPPAGES, ctl);
		if (ret < 0) {
			return -1;
		}
		ret = compel_util_send_fd(ctl, ppb->p[1]);
		if (ret) {
			return -1;
		}

		ret = compel_rpc_sync(PARASITE_CMD_DUMPPAGES, ctl);
		if (ret < 0) {
			return -1;
		}

		args_off += args->nr_segs;
	}

	args->off = args_off;

	return 0;
}

static int xfer_pages(struct page_pipe *pp, struct page_xfer *xfer)
{
	int ret;

	/*
	 * Step 3 -- write pages into image (or delay writing for
	 *           pre-dump action (see pre_dump_one_task)
	 */
	timing_start(TIME_MEMWRITE);
	ret = page_xfer_dump_pages(xfer, pp);
	timing_stop(TIME_MEMWRITE);

	return ret;
}

static void dsa_sanitize_page_pipe(struct page_pipe *pp)
{
	struct page_pipe_buf *ppb;

	if (!pp)
		return;

	list_for_each_entry(ppb, &pp->bufs, l) {
		unsigned int i;
		unsigned int out = 0;
		unsigned long pages = 0;

		for (i = 0; i < ppb->nr_segs; i++) {
			if (!ppb->iov[i].iov_len)
				continue;
			if (out != i)
				ppb->iov[out] = ppb->iov[i];
			pages += ppb->iov[out].iov_len / PAGE_SIZE;
			out++;
		}

		ppb->nr_segs = out;
		ppb->pages_in = pages;
	}
}

static int dsa_validate_page_pipe(struct page_pipe *pp)
{
	struct page_pipe_buf *ppb;
	unsigned int bi = 0;

	if (!pp)
		return 0;

	pr_info("DSA validate page-pipe: iovs=%u free_iov=%u\n",
		pp->nr_iovs, pp->free_iov);

	list_for_each_entry(ppb, &pp->bufs, l) {
		unsigned int i;

		pr_debug("DSA validate buf=%u pages=%lu segs=%u\n",
			 bi, ppb->pages_in, ppb->nr_segs);

		for (i = 0; i < ppb->nr_segs; i++) {
			if (!ppb->iov[i].iov_base || !ppb->iov[i].iov_len) {
				pr_err("DSA invalid iov buf=%u seg=%u base=%p len=%zu\n",
				       bi, i, ppb->iov[i].iov_base,
				       ppb->iov[i].iov_len);
				return -1;
			}
		}
		bi++;
	}

	return 0;
}

static void *mem_dump_async_xfer_thread(void *arg)
{
	struct mem_dump_async *async = arg;
	u64 start_us;

	pr_debug("Async memwrite: start for pid %d\n", async->pid);
	timing_start(TIME_MEMWRITE);
	start_us = dsa_wall_now_us();
	async->xfer_ret = page_xfer_dump_pages(&async->xfer, async->pp);
	async->xfer_worker_us = dsa_wall_delta_us(start_us, dsa_wall_now_us());
	timing_stop(TIME_MEMWRITE);
	pr_debug("Async memwrite: done for pid %d ret=%d\n", async->pid,
		 async->xfer_ret);

	return NULL;
}

static void *mem_dump_async_dsa_replay_thread(void *arg)
{
	struct mem_dump_async *async = arg;
	u64 start_us;

	start_us = dsa_wall_now_us();
	async->dsa_replay_ret = dsa_replay_to_pipe(async->dsa_ctx_deferred);
	async->dsa_replay_worker_us = dsa_wall_delta_us(start_us, dsa_wall_now_us());

	return NULL;
}

static int start_mem_dump_async_xfer(struct pstree_item *item, struct page_pipe *pp,
				     struct page_xfer *xfer)
{
	struct mem_dump_async *async;

	if (dmpi(item)->mem_async) {
		pr_err("Async memwrite context already exists for pid %d\n",
		       item->pid->real);
		return -1;
	}

	async = xzalloc(sizeof(*async));
	if (!async)
		return -1;

	async->pp = pp;
	async->xfer = *xfer;
	async->xfer_ret = 0;
	async->dsa_replay_ret = 0;
	async->pid = item->pid->real;
	async->xfer_worker_us = 0;
	async->dsa_replay_worker_us = 0;
	async->thread_started = false;
	async->dsa_replay_started = false;
	async->dsa_live_defer = false;
	async->dsa_ctx_deferred = NULL;

	if (pthread_create(&async->tid, NULL, mem_dump_async_xfer_thread, async)) {
		pr_err("Can't create async memwrite thread for pid %d\n",
		       item->pid->real);
		xfree(async);
		return -1;
	}
	async->thread_started = true;

	dmpi(item)->mem_async = async;
	return 0;
}

static int start_deferred_mem_dump_async_xfer(struct mem_dump_async *async)
{
	if (!async || async->thread_started)
		return 0;

	if (pthread_create(&async->tid, NULL, mem_dump_async_xfer_thread, async)) {
		pr_err("Can't create deferred async memwrite thread for pid %d\n",
		       async->pid);
		return -1;
	}

	async->thread_started = true;
	return 0;
}

static int start_deferred_dsa_replay(struct mem_dump_async *async)
{
	if (!async || async->dsa_replay_started)
		return 0;

	if (!async->dsa_ctx_deferred) {
		pr_err("DSA deferred replay missing context for pid %d\n",
		       async->pid);
		return -1;
	}

	if (pthread_create(&async->dsa_replay_tid, NULL,
			   mem_dump_async_dsa_replay_thread, async)) {
		pr_err("Can't create deferred DSA replay thread for pid %d\n",
		       async->pid);
		return -1;
	}

	async->dsa_replay_started = true;
	return 0;
}

static int defer_mem_dump_async_xfer(struct pstree_item *item,
				     struct page_pipe *pp,
				     struct page_xfer *xfer,
				     struct dsa_dump_ctx *dsa_ctx)
{
	struct mem_dump_async *async;

	if (dmpi(item)->mem_async) {
		pr_err("Async memwrite context already exists for pid %d\n",
		       item->pid->real);
		return -1;
	}

	async = xzalloc(sizeof(*async));
	if (!async)
		return -1;

	async->pp = pp;
	async->xfer = *xfer;
	async->xfer_ret = 0;
	async->dsa_replay_ret = 0;
	async->pid = item->pid->real;
	async->xfer_worker_us = 0;
	async->dsa_replay_worker_us = 0;
	async->thread_started = false;
	async->dsa_replay_started = false;
	async->dsa_live_defer = true;
	async->dsa_ctx_deferred = dsa_ctx;

	dmpi(item)->mem_async = async;

	if (start_deferred_mem_dump_async_xfer(async)) {
		dmpi(item)->mem_async = NULL;
		xfree(async);
		return -1;
	}
	if (start_deferred_dsa_replay(async)) {
		dsa_abort_replay_pipe(async->pp, dsa_ctx->replay.pipe_fd);
		if (async->thread_started)
			pthread_join(async->tid, NULL);
		dmpi(item)->mem_async = NULL;
		xfree(async);
		return -1;
	}

	return 0;
}

bool parasite_mem_async_deferred(const struct pstree_item *item)
{
	struct mem_dump_async *async;

	if (!item)
		return false;

	async = dmpi(item)->mem_async;
	return async && async->dsa_live_defer;
}

static int dsa_deferred_ctx_finalize(struct mem_dump_async *async)
{
	int ret = 0;

	if (!async || !async->dsa_ctx_deferred)
		return 0;

	ret = dsa_dump_ctx_fini(async->dsa_ctx_deferred);
	xfree(async->dsa_ctx_deferred);
	async->dsa_ctx_deferred = NULL;
	async->dsa_live_defer = false;

	return ret;
}

int parasite_dump_pages_seized_wait(struct pstree_item *item)
{
	struct mem_dump_async *async;
	u64 wait_start_us;
	u64 wait_us;
	u64 xfer_worker_us = 0;
	u64 dsa_replay_worker_us = 0;
	bool dsa_live_defer = false;
	int ret = 0;
	int dsa_ret;

	async = dmpi(item)->mem_async;
	if (!async)
		return 0;

	wait_start_us = dsa_wall_now_us();
	dsa_live_defer = async->dsa_live_defer;

	if (async->dsa_live_defer) {
		if (start_deferred_mem_dump_async_xfer(async)) {
			ret = -1;
		}
		if (!ret && start_deferred_dsa_replay(async)) {
			if (async->dsa_ctx_deferred)
				dsa_abort_replay_pipe(async->pp,
						      async->dsa_ctx_deferred->replay.pipe_fd);
			ret = -1;
		}
	}

	if (async->dsa_replay_started && pthread_join(async->dsa_replay_tid, NULL)) {
		pr_err("Can't join deferred DSA replay thread for pid %d\n",
		       async->pid);
		return -1;
	}

	if (async->dsa_replay_ret) {
		if (async->dsa_ctx_deferred)
			dsa_abort_replay_pipe(async->pp,
					      async->dsa_ctx_deferred->replay.pipe_fd);
		if (!ret)
			ret = async->dsa_replay_ret;
	}

	if (async->thread_started && pthread_join(async->tid, NULL)) {
		pr_err("Can't join async memwrite thread for pid %d\n", async->pid);
		/*
		 * Thread state is unknown here, don't release shared resources
		 * to avoid use-after-free if it is still running.
		 */
		return -1;
	}

	if (!ret && async->xfer_ret)
		ret = async->xfer_ret;

	dsa_ret = dsa_deferred_ctx_finalize(async);
	if (!ret && dsa_ret)
		ret = dsa_ret;

	wait_us = dsa_wall_delta_us(wait_start_us, dsa_wall_now_us());
	xfer_worker_us = async->xfer_worker_us;
	dsa_replay_worker_us = async->dsa_replay_worker_us;
	pr_info("MEMDUMP_DEFERRED_ASYNC: pid=%d ret=%d dsa_live_defer=%u wait_us=%llu image_write_worker_us=%llu dsa_replay_worker_us=%llu\n",
		item->pid->real, ret, dsa_live_defer ? 1 : 0,
		(unsigned long long)wait_us,
		(unsigned long long)xfer_worker_us,
		(unsigned long long)dsa_replay_worker_us);

	async->xfer.close(&async->xfer);
	destroy_page_pipe(async->pp);
	dmpi(item)->mem_async = NULL;
	xfree(async);

	if (ret)
		pr_err("Async memwrite failed for pid %d ret=%d\n", item->pid->real,
		       ret);

	return ret;
}

static int detect_pid_reuse(struct pstree_item *item, struct proc_pid_stat *pps, InventoryEntry *parent_ie)
{
	unsigned long long dump_ticks;
	struct proc_pid_stat pps_buf;
	unsigned long long tps; /* ticks per second */
	int ret;

	/* Check pid reuse using pidfds */
	if (pidfd_store_ready())
		return pidfd_store_check_pid_reuse(item->pid->real);

	if (!parent_ie) {
		pr_err("Pid-reuse detection failed: no parent inventory, "
		       "check warnings in get_parent_inventory\n");
		return -1;
	}

	tps = sysconf(_SC_CLK_TCK);
	if (tps == -1) {
		pr_perror("Failed to get clock ticks via sysconf");
		return -1;
	}

	if (!pps) {
		pps = &pps_buf;
		ret = parse_pid_stat(item->pid->real, pps);
		if (ret < 0)
			return -1;
	}

	dump_ticks = parent_ie->dump_uptime / (USEC_PER_SEC / tps);

	if (pps->start_time >= dump_ticks) {
		/* Print "*" if unsure */
		pr_warn("Pid reuse%s detected for pid %d\n", pps->start_time == dump_ticks ? "*" : "", item->pid->real);
		return 1;
	}
	return 0;
}

static int generate_vma_iovs(struct pstree_item *item, struct vma_area *vma, struct page_pipe *pp,
			     struct page_xfer *xfer, struct parasite_dump_pages_args *args, struct parasite_ctl *ctl,
			     pmc_t *pmc, bool has_parent, bool pre_dump,
			     int parent_predump_mode, struct memdump_timeline *timeline)
{
	u64 vaddr;
	int ret;

	if (!vma_area_is_private(vma, kdat.task_size) && !vma_area_is(vma, VMA_ANON_SHARED))
		return 0;
	/*
	 * In turn VVAR area is special and referenced from
	 * vDSO area by IP addressing (at least on x86) thus
	 * never ever dump its content but always use one provided
	 * by the kernel on restore, ie runtime VVAR area must
	 * be remapped into proper place..
	 */
	if (vma_entry_is(vma->e, VMA_AREA_VVAR))
		return 0;

	/*
	 * 9651fcedf7b9 ("mm: add MAP_DROPPABLE for designating always lazily freeable mappings")
	 * tells us that:
	 * Under memory pressure, mm can just drop the pages (so that they're
	 * zero when read back again).
	 *
	 * Let's just skip MAP_DROPPABLE mappings pages dump logic.
	 */
	if (vma->e->flags & MAP_DROPPABLE)
		return 0;

	/*
	 * To facilitate any combination of pre-dump modes to run after
	 * one another, we need to take extra care as discussed below.
	 *
	 * The SPLICE mode pre-dump, processes all type of memory regions,
	 * whereas READ mode pre-dump skips processing those memory regions
	 * which lacks PROT_READ flag.
	 *
	 * Now on mixing pre-dump modes:
	 * 	If SPLICE mode follows SPLICE mode	: no issue
	 *		-> everything dumped both the times
	 *
	 * 	If READ mode follows READ mode		: no issue
	 *		-> non-PROT_READ skipped both the time
	 *
	 * 	If READ mode follows SPLICE mode   	: no issue
	 *		-> everything dumped at first,
	 *		   the non-PROT_READ skipped later
	 *
	 * 	If SPLICE mode follows READ mode   	: Need special care
	 *
	 * If READ pre-dump happens first, then it has skipped processing
	 * non-PROT_READ regions. Following SPLICE pre-dump expects pagemap
	 * entries for all mappings in parent pagemap, but last READ mode
	 * pre-dump cycle has skipped processing & pagemap generation for
	 * non-PROT_READ regions. So SPLICE mode throws error of missing
	 * pagemap entry for encountered non-PROT_READ mapping.
	 *
	 * To resolve this, the pre-dump-mode is stored in current pre-dump's
	 * inventoy file. This pre-dump mode is read back from this file
	 * (present in parent pre-dump dir) as parent-pre-dump-mode during
	 * next pre-dump.
	 *
	 * If parent-pre-dump-mode and next-pre-dump-mode are in READ-mode ->
	 * SPLICE-mode order, then SPLICE mode doesn't expect mappings for
	 * non-PROT_READ regions in parent-image and marks "has_parent=false".
	 */

	if (!(vma->e->prot & PROT_READ)) {
		if (opts.pre_dump_mode == PRE_DUMP_READ && pre_dump)
			return 0;
		if ((parent_predump_mode == PRE_DUMP_READ && opts.pre_dump_mode == PRE_DUMP_SPLICE) || !pre_dump)
			has_parent = false;
	}

	/*
	 * We want to completely ignore these VMA types on the pre-dump:
	 * 1. VMA_AREA_AIORING because it is not soft-dirty trackable (kernel writes)
	 * 2. MAP_HUGETLB mappings because they are not premapped and we can't use
	 * parent images from pre-dump stages. Instead, the content is restored from
	 * the parasite context using full memory image.
	 */
	if (vma_entry_is(vma->e, VMA_AREA_AIORING) || vma->e->flags & MAP_HUGETLB) {
		if (pre_dump)
			return 0;
		has_parent = false;
	}

	if (pmc_get_map(pmc, vma))
		return -1;

	if (vma_area_is(vma, VMA_ANON_SHARED))
		return add_shmem_area(item->pid->real, vma->e, pmc);
	vaddr = vma->e->start;
again:
	ret = generate_iovs(item, vma, pp, pmc, &vaddr, has_parent);
	if (ret == -EAGAIN) {
		BUG_ON(!(pp->flags & PP_CHUNK_MODE));

		memdump_timeline_switch(timeline, MEMDUMP_PHASE_BASE_RPC);
		ret = drain_pages(pp, ctl, args);
		if (!ret) {
			memdump_timeline_switch(timeline, MEMDUMP_PHASE_IMAGE_WRITE);
			ret = xfer_pages(pp, xfer);
		}
		if (!ret) {
			page_pipe_reinit(pp);
			memdump_timeline_switch(timeline, MEMDUMP_PHASE_SCAN_BUILD);
			goto again;
		}
	}

	return ret;
}

static int generate_iovs_dsa_desc_scan(struct pstree_item *item,
				       struct vma_area *vma,
				       struct page_pipe *pp,
				       pmc_t *pmc, u64 *pvaddr,
				       bool has_parent,
				       struct dsa_desc_scan_ctx *sc)
{
	unsigned long nr_scanned;
	unsigned long pages[3] = {};
	unsigned long vaddr;
	bool dump_all_pages;
	int ret = 0;

	dump_all_pages = should_dump_entire_vma(vma->e);

	nr_scanned = 0;
	for (vaddr = *pvaddr; vaddr < vma->e->end; vaddr += PAGE_SIZE, nr_scanned++) {
		unsigned int ppb_flags = 0;
		struct page_info page_info = {};
		int st;

		if (should_dump_page(pmc, vma->e, vaddr, &page_info))
			return -1;

		if (!dump_all_pages && page_info.next != vaddr) {
			dsa_desc_scan_raw_flush(sc);
			vaddr = page_info.next - PAGE_SIZE;
			continue;
		}

		if (vma_entry_can_be_lazy(vma->e) && !is_stack(item, vaddr))
			ppb_flags |= PPB_LAZY;

		if (has_parent && page_in_parent(page_info.softdirty)) {
			dsa_desc_scan_raw_flush(sc);
			ret = page_pipe_add_hole(pp, vaddr, PP_HOLE_PARENT);
			st = 0;
		} else {
			ret = page_pipe_add_page_unbounded(pp, vaddr, ppb_flags);
			if (!ret) {
				dsa_desc_scan_raw_append(sc,
					(u64)(unsigned long)vaddr,
					PAGE_SIZE);
				ret = dsa_desc_scan_batch_append(sc,
					(u64)(unsigned long)vaddr,
					PAGE_SIZE);
			}
			if (ppb_flags & PPB_LAZY && opts.lazy_pages)
				st = 1;
			else
				st = 2;
		}

		if (ret)
			break;

		pages[st]++;
	}

	*pvaddr = vaddr;
	cnt_add(CNT_PAGES_SCANNED, nr_scanned);
	cnt_add(CNT_PAGES_SKIPPED_PARENT, pages[0]);
	cnt_add(CNT_PAGES_LAZY, pages[1]);
	cnt_add(CNT_PAGES_WRITTEN, pages[2]);

	pr_info("DSA desc-scan pagemap generated: %lu pages (%lu lazy) %lu holes\n",
		pages[2] + pages[1], pages[1], pages[0]);

	return ret;
}

static int generate_vma_iovs_dsa_desc_scan(struct pstree_item *item,
					   struct vma_area *vma,
					   struct page_pipe *pp,
					   pmc_t *pmc,
					   bool has_parent,
					   bool pre_dump,
					   int parent_predump_mode,
					   struct dsa_desc_scan_ctx *sc)
{
	u64 vaddr;
	int ret;

	if (!vma_area_is_private(vma, kdat.task_size) && !vma_area_is(vma, VMA_ANON_SHARED))
		return 0;

	if (vma_entry_is(vma->e, VMA_AREA_VVAR))
		return 0;

	if (vma->e->flags & MAP_DROPPABLE)
		return 0;

	if (!(vma->e->prot & PROT_READ)) {
		if (opts.pre_dump_mode == PRE_DUMP_READ && pre_dump)
			return 0;
		if ((parent_predump_mode == PRE_DUMP_READ && opts.pre_dump_mode == PRE_DUMP_SPLICE) || !pre_dump)
			has_parent = false;
	}

	if (vma_entry_is(vma->e, VMA_AREA_AIORING) || vma->e->flags & MAP_HUGETLB) {
		if (pre_dump)
			return 0;
		has_parent = false;
	}

	if (pmc_get_map(pmc, vma))
		return -1;

	if (vma_area_is(vma, VMA_ANON_SHARED))
		return add_shmem_area(item->pid->real, vma->e, pmc);

	vaddr = vma->e->start;
	ret = generate_iovs_dsa_desc_scan(item, vma, pp, pmc, &vaddr,
					 has_parent, sc);

	if (ret == -EAGAIN) {
		pr_err("DSA desc-scan got unexpected EAGAIN\n");
		return -1;
	}

	return ret;
}

static int __parasite_dump_pages_seized(struct pstree_item *item, struct parasite_dump_pages_args *args,
					struct vm_area_list *vma_area_list, struct mem_dump_ctl *mdc,
					struct parasite_ctl *ctl, struct memdump_timeline *timeline)
{
	pmc_t pmc = PMC_INIT;
	struct page_pipe *pp;
	struct vma_area *vma_area;
	struct page_xfer xfer = { .parent = NULL };
	int ret = -1, exit_code = -1;
	unsigned cpp_flags = 0;
	unsigned long pmc_size;
	int possible_pid_reuse = 0;
	bool has_parent;
	bool async_regular = false;
	bool async_started = false;
	bool async_cleaned = false;
	bool dsa_strict = dsa_dump_enabled();
	bool dsa_desc_scan_active = false;
	bool dsa_desc_scan_ready = false;
	bool dsa_ctx_deferred = false;
	struct dsa_dump_ctx *dsa_ctx = NULL;
	struct dsa_desc_scan_ctx dsa_sc = {
		.dsa_pipe_fd = -1,
	};
	int parent_predump_mode = -1;
	u64 setup_start_us = 0;
	u64 setup_end_us = 0;
	u64 setup_total_us = 0;
	u64 setup_accounted_us = 0;
	u64 setup_pmc_init_us = 0;
	u64 setup_dsa_ctx_init_us = 0;
	u64 setup_create_page_pipe_us = 0;
	u64 setup_save_vmas_us = 0;
	u64 setup_stream_layout_us = 0;
	u64 setup_stream_start_rpc_us = 0;
	u64 setup_open_page_xfer_us = 0;
	u64 setup_detect_pid_reuse_us = 0;
	u64 setup_t0;
	u64 setup_t1;

	pr_info("\n");
	pr_info("Dumping pages (type: %d pid: %d)\n", CR_FD_PAGES, item->pid->real);
	pr_info("----------------------------------------\n");

	timing_start(TIME_MEMDUMP);
	memdump_timeline_switch(timeline, MEMDUMP_PHASE_SETUP);
	setup_start_us = dsa_wall_now_us();

	pr_debug("   Private vmas %lu/%lu pages\n", vma_area_list->nr_priv_pages_longest, vma_area_list->nr_priv_pages);

	/*
	 * Step 0 -- prepare
	 */

	pmc_size = max(vma_area_list->nr_priv_pages_longest, vma_area_list->nr_shared_pages_longest);
	setup_t0 = dsa_wall_now_us();
	if (pmc_init(&pmc, item->pid->real, &vma_area_list->h, pmc_size * PAGE_SIZE))
		return -1;
	setup_t1 = dsa_wall_now_us();
	setup_pmc_init_us = dsa_wall_delta_us(setup_t0, setup_t1);

	dsa_ctx = xzalloc(sizeof(*dsa_ctx));
	if (!dsa_ctx)
		goto out;

	dsa_ctx->shared_fd = -1;
	dsa_ctx->shared_buf = MAP_FAILED;

	async_regular = dsa_strict && !mdc->pre_dump && !mdc->lazy;
	dsa_desc_scan_active = dsa_strict && !mdc->pre_dump && !mdc->lazy;

	if (dsa_desc_scan_active) {
		setup_t0 = dsa_wall_now_us();
		ret = dsa_dump_ctx_init(dsa_ctx, item->pid->real);
		setup_t1 = dsa_wall_now_us();
		setup_dsa_ctx_init_us = dsa_wall_delta_us(setup_t0, setup_t1);
		if (ret)
			goto out;

		dsa_sc.ctl = ctl;
		dsa_sc.args = args;
		dsa_sc.dsa_ctx = dsa_ctx;
		dsa_sc.timeline = timeline;
	}

	if (!(mdc->pre_dump || mdc->lazy))
		/*
		 * Chunk mode pushes pages portion by portion. This mode
		 * only works when we don't need to keep pp for later
		 * use, i.e. on non-lazy non-predump.
		 */
		cpp_flags |= PP_CHUNK_MODE;
	if (dsa_strict)
		cpp_flags |= PP_DSA_SINGLE_PIPE;
	{
		struct iovec *pp_iovs = mdc->lazy ? NULL : pargs_iovs(args);

		if (dsa_strict)
			pp_iovs = NULL;
		setup_t0 = dsa_wall_now_us();
		pp = create_page_pipe(vma_area_list->nr_priv_pages, pp_iovs, cpp_flags);
		setup_t1 = dsa_wall_now_us();
		setup_create_page_pipe_us = dsa_wall_delta_us(setup_t0, setup_t1);
	}
	if (!pp)
		goto out;

	if (dsa_desc_scan_active) {
		struct page_pipe_buf *first_ppb;

		if (list_empty(&pp->bufs)) {
			ret = -1;
			goto out_pp;
		}

		first_ppb = list_first_entry(&pp->bufs, struct page_pipe_buf, l);
		dsa_sc.dsa_pipe_fd = first_ppb->p[1];
		dsa_sc.args_nr_vmas_saved = args->nr_vmas;
		dsa_sc.args_add_prot_saved = args->add_prot;
		dsa_sc.args_off_saved = args->off;
		dsa_sc.args_vmas_sz = args->nr_vmas * sizeof(struct parasite_vma_entry);
		if (dsa_sc.args_vmas_sz) {
			setup_t0 = dsa_wall_now_us();
			dsa_sc.args_vmas_saved = xmalloc(dsa_sc.args_vmas_sz);
			if (!dsa_sc.args_vmas_saved) {
				ret = -1;
				goto out_pp;
			}
			memcpy(dsa_sc.args_vmas_saved, pargs_vmas(args),
			       dsa_sc.args_vmas_sz);
			setup_t1 = dsa_wall_now_us();
			setup_save_vmas_us = dsa_wall_delta_us(setup_t0, setup_t1);
		}

		setup_t0 = dsa_wall_now_us();
		if (dsa_stream_layout_init(&dsa_sc)) {
			ret = -1;
			goto out_pp;
		}
		setup_t1 = dsa_wall_now_us();
		setup_stream_layout_us = dsa_wall_delta_us(setup_t0, setup_t1);
		dsa_desc_scan_reset_batch(&dsa_sc);
		setup_t0 = dsa_wall_now_us();
		if (dsa_stream_start_rpc(&dsa_sc)) {
			ret = -1;
			goto out_pp;
		}
		setup_t1 = dsa_wall_now_us();
		setup_stream_start_rpc_us = dsa_wall_delta_us(setup_t0, setup_t1);
		dsa_desc_scan_ready = true;
	}

	if (!mdc->pre_dump) {
		/*
		 * Regular dump -- create xfer object and send pages to it
		 * right here. For pre-dumps the pp will be taken by the
		 * caller and handled later.
		 */
		setup_t0 = dsa_wall_now_us();
		ret = open_page_xfer(&xfer, CR_FD_PAGEMAP, vpid(item));
		setup_t1 = dsa_wall_now_us();
		setup_open_page_xfer_us = dsa_wall_delta_us(setup_t0, setup_t1);
		if (ret < 0)
			goto out_pp;

		xfer.transfer_lazy = !mdc->lazy;
	} else {
		ret = check_parent_page_xfer(CR_FD_PAGEMAP, vpid(item));
		if (ret < 0)
			goto out_pp;

		if (ret)
			xfer.parent = NULL + 1;
	}

	if (xfer.parent) {
		setup_t0 = dsa_wall_now_us();
		possible_pid_reuse = detect_pid_reuse(item, mdc->stat, mdc->parent_ie);
		setup_t1 = dsa_wall_now_us();
		setup_detect_pid_reuse_us = dsa_wall_delta_us(setup_t0, setup_t1);
		if (possible_pid_reuse == -1)
			goto out_xfer;
	}

	setup_end_us = dsa_wall_now_us();
	setup_total_us = dsa_wall_delta_us(setup_start_us, setup_end_us);
	setup_accounted_us = setup_pmc_init_us + setup_dsa_ctx_init_us +
		setup_create_page_pipe_us + setup_save_vmas_us +
		setup_stream_layout_us + setup_stream_start_rpc_us +
		setup_open_page_xfer_us + setup_detect_pid_reuse_us;
	pr_info("MEMDUMP_SETUP_DETAIL: pid=%d mode=%s total_us=%llu pmc_init_us=%llu dsa_ctx_init_us=%llu create_page_pipe_us=%llu save_vmas_us=%llu stream_layout_us=%llu stream_start_rpc_us=%llu open_page_xfer_us=%llu detect_pid_reuse_us=%llu other_us=%llu\n",
		item->pid->real, dsa_desc_scan_active ? "dsa" : "base",
		(unsigned long long)setup_total_us,
		(unsigned long long)setup_pmc_init_us,
		(unsigned long long)setup_dsa_ctx_init_us,
		(unsigned long long)setup_create_page_pipe_us,
		(unsigned long long)setup_save_vmas_us,
		(unsigned long long)setup_stream_layout_us,
		(unsigned long long)setup_stream_start_rpc_us,
		(unsigned long long)setup_open_page_xfer_us,
		(unsigned long long)setup_detect_pid_reuse_us,
		(unsigned long long)(setup_total_us >= setup_accounted_us ?
			setup_total_us - setup_accounted_us : 0));

	/*
	 * Step 1 -- generate the pagemap
	 */
	args->off = 0;
	has_parent = !!xfer.parent && !possible_pid_reuse;
	if (mdc->parent_ie)
		parent_predump_mode = mdc->parent_ie->pre_dump_mode;

	if (dsa_desc_scan_active) {
		temp_cdf_dump_task_boundary();
	}

	memdump_timeline_switch(timeline, MEMDUMP_PHASE_SCAN_BUILD);
	list_for_each_entry(vma_area, &vma_area_list->h, list) {
		if (vma_area_is(vma_area, VMA_AREA_GUARD))
			continue;

		if (dsa_desc_scan_active)
			ret = generate_vma_iovs_dsa_desc_scan(item, vma_area, pp,
						      &pmc, has_parent,
						      mdc->pre_dump,
						      parent_predump_mode,
						      &dsa_sc);
		else
			ret = generate_vma_iovs(item, vma_area, pp, &xfer, args, ctl,
						&pmc, has_parent, mdc->pre_dump,
						parent_predump_mode, timeline);
		if (ret < 0)
			goto out_xfer;
	}

	if (dsa_desc_scan_active) {
		dsa_desc_scan_raw_flush(&dsa_sc);
	}

	if (dsa_desc_scan_active)
		pr_info("DSA desc-scan mode enabled for pid %d\n", item->pid->real);

	if (dsa_desc_scan_active && dsa_desc_scan_ready) {
		memdump_timeline_switch(timeline, MEMDUMP_PHASE_DSA_RPC);
		ret = dsa_stream_finish(&dsa_sc);
		if (ret < 0)
			goto out_xfer;
		pr_info("DSA_DESC_SEQ: total=%llu out_of_order=%llu discontinuity=%llu\n",
			(unsigned long long)dsa_sc.desc_seq_total,
			(unsigned long long)dsa_sc.desc_seq_out_of_order,
			(unsigned long long)dsa_sc.desc_seq_discont);
	}

	if (mdc->lazy) {
		memcpy(pargs_iovs(args), pp->iovs, sizeof(struct iovec) * pp->nr_iovs);
	}

	/*
	 * Faking drain_pages for pre-dump here. Actual drain_pages for pre-dump
	 * will happen after task unfreezing in cr_pre_dump_finish(). This is
	 * actual optimization which reduces time for which process was frozen
	 * during pre-dump.
	 */
	if (mdc->pre_dump && opts.pre_dump_mode == PRE_DUMP_READ) {
		ret = 0;
	} else if (dsa_desc_scan_active) {
		if (async_regular) {
			memdump_timeline_switch(timeline, MEMDUMP_PHASE_ASYNC_START);
			if (dsa_strict) {
				dsa_sanitize_page_pipe(pp);
			}
			if (dsa_strict) {
				ret = dsa_validate_page_pipe(pp);
				if (ret) {
					ret = -1;
					goto out_xfer;
				}
			}
			ret = defer_mem_dump_async_xfer(item, pp, &xfer, dsa_ctx);
			if (!ret) {
				async_started = true;
				dsa_ctx_deferred = true;
			}
		} else {
			memdump_timeline_switch(timeline, MEMDUMP_PHASE_IMAGE_WRITE);
			ret = xfer_pages(pp, &xfer);
		}
	} else if (async_regular) {
		/*
		 * Regular dump: drain pages first, then start async writer.
		 * This keeps pipe content stable while preserving post-drain overlap.
		 */
		memdump_timeline_switch(timeline, MEMDUMP_PHASE_BASE_RPC);
		ret = drain_pages(pp, ctl, args);
		if (!ret) {
			memdump_timeline_switch(timeline, MEMDUMP_PHASE_ASYNC_START);
			if (dsa_strict) {
				dsa_sanitize_page_pipe(pp);
			}
			if (dsa_strict) {
				ret = dsa_validate_page_pipe(pp);
				if (ret) {
					ret = -1;
					goto out_xfer;
				}
			}
			ret = start_mem_dump_async_xfer(item, pp, &xfer);
			if (!ret)
				async_started = true;
		}
	} else {
		/*
		 * For pre-dump or lazy dump, use legacy sequential drain_pages + xfer_pages.
		 */
		memdump_timeline_switch(timeline, MEMDUMP_PHASE_BASE_RPC);
		ret = drain_pages(pp, ctl, args);
		if (!ret) {
			memdump_timeline_switch(timeline, MEMDUMP_PHASE_IMAGE_WRITE);
			ret = xfer_pages(pp, &xfer);
		}
	}
	if (ret)
		goto out_xfer;

	timing_stop(TIME_MEMDUMP);

	/*
	 * Step 4 -- clean up
	 */

	memdump_timeline_switch(timeline, MEMDUMP_PHASE_DIRTY_RESET);
	ret = task_reset_dirty_track(item->pid->real);
	if (ret)
		goto out_xfer;
	exit_code = 0;

	/* Success path intentionally keeps async writer running. */
out_xfer:
	memdump_timeline_switch(timeline, MEMDUMP_PHASE_CLEANUP);
	if (ret && async_started) {
		int wait_ret;

		memdump_timeline_switch(timeline, MEMDUMP_PHASE_ASYNC_WAIT);
		wait_ret = parasite_dump_pages_seized_wait(item);
		memdump_timeline_switch(timeline, MEMDUMP_PHASE_CLEANUP);
		if (!wait_ret) {
			async_started = false;
			async_cleaned = true;
		} else if (!ret) {
			ret = wait_ret;
		}
	}

	if (!mdc->pre_dump && !async_started && !async_cleaned)
		xfer.close(&xfer);
out_pp:
	if (ret) {
		if (!async_cleaned && !async_started)
			destroy_page_pipe(pp);
	} else if (!async_started && !(mdc->pre_dump || mdc->lazy)) {
		destroy_page_pipe(pp);
	} else if (mdc->pre_dump || mdc->lazy) {
		dmpi(item)->mem_pp = pp;
	}
out:
	if (dsa_desc_scan_ready && dsa_sc.rpc_started) {
		dsa_shared_store_u32(&dsa_sc.stream_hdr->error, (u32)-EIO);
		dsa_shared_store_u32(&dsa_sc.stream_hdr->finish, 1);
		(void)dsa_stream_join_rpc(&dsa_sc);
	}
	xfree(dsa_sc.args_vmas_saved);
	if (dsa_ctx && !dsa_ctx_deferred) {
		int fini_ret;

		fini_ret = dsa_dump_ctx_fini(dsa_ctx);
		if (!exit_code && fini_ret)
			exit_code = fini_ret;
		xfree(dsa_ctx);
	}
	pmc_fini(&pmc);
	pr_info("----------------------------------------\n");
	return exit_code;
}

int parasite_dump_pages_seized(struct pstree_item *item, struct vm_area_list *vma_area_list, struct mem_dump_ctl *mdc,
			       struct parasite_ctl *ctl)
{
	int ret = -1;
	bool reprotect_vmas = false;
	struct parasite_dump_pages_args *pargs;
	struct memdump_timeline timeline;

	memdump_timeline_begin(&timeline, item->pid->real,
				       MEMDUMP_PHASE_PROTECT_VMAS);
	pargs = prep_dump_pages_args(ctl, vma_area_list, mdc->pre_dump);

	/*
	 * Add PROT_READ protection for all VMAs we're about to
	 * dump if they don't have one. Otherwise we'll not be
	 * able to read the memory contents.
	 *
	 * Afterwards -- reprotect memory back.
	 *
	 * This step is required for "splice" mode pre-dump and dump.
	 * Skip this step for "read" mode pre-dump.
	 * "read" mode pre-dump delegates processing of non-PROT_READ
	 * regions to dump stage. Adding PROT_READ works fine for
	 * static processing (target process frozen during pre-dump)
	 * and fails for dynamic as explained below.
	 *
	 * Consider following sequence of instances to reason, why
	 * not to add PROT_READ in "read" mode pre-dump ?
	 *
	 *	CRIU- "read" pre-dump		    Target Process
	 *
	 *					1. Creates mapping M
	 *					   without PROT_READ
	 * 2. CRIU freezes target
	 *    process
	 * 3. Collect the mappings
	 * 4. Add PROT_READ to M
	 *    (non-PROT_READ region)
	 * 5. CRIU unfreezes target
	 *    process
	 *					6. Add flag PROT_READ
	 *					   to mapping M
	 *					7. Revoke flag PROT_READ
	 *					   from mapping M
	 * 8. process_vm_readv tries
	 *    to copy mapping M
	 *    (believing M have
	 *     PROT_READ flag)
	 * 9. syscall fails to copy
	 *    data from M
	 */

	if (!mdc->pre_dump || opts.pre_dump_mode == PRE_DUMP_SPLICE) {
		pargs->add_prot = PROT_READ;
		ret = compel_rpc_call_sync(PARASITE_CMD_MPROTECT_VMAS, ctl);
		if (ret) {
			pr_err("Can't dump unprotect vmas with parasite\n");
			goto out;
		}
		reprotect_vmas = true;
	}

	memdump_timeline_switch(&timeline, MEMDUMP_PHASE_SETUP);
	if (fault_injected(FI_DUMP_PAGES)) {
		pr_err("fault: Dump VMA pages failure!\n");
		ret = -1;
		goto out;
	}

	ret = __parasite_dump_pages_seized(item, pargs, vma_area_list, mdc, ctl,
					       &timeline);
	if (ret) {
		pr_err("Can't dump page with parasite\n");
		/* Parasite will unprotect VMAs after fail in fini() */
		goto out;
	}

	if (reprotect_vmas) {
		memdump_timeline_switch(&timeline, MEMDUMP_PHASE_RESTORE_VMAS);
		pargs->add_prot = 0;
		if (compel_rpc_call_sync(PARASITE_CMD_MPROTECT_VMAS, ctl)) {
			pr_err("Can't rollback unprotected vmas with parasite\n");
			ret = -1;
		}
	}

out:
	memdump_timeline_finish(&timeline, ret, dsa_dump_enabled(),
				 dmpi(item)->mem_async != NULL);
	return ret;
}

int prepare_mm_pid(struct pstree_item *i)
{
	pid_t pid = vpid(i);
	int ret = -1, vn = 0;
	struct cr_img *img;
	struct rst_info *ri = rsti(i);

	img = open_image(CR_FD_MM, O_RSTR, pid);
	if (!img)
		return -1;

	ret = pb_read_one_eof(img, &ri->mm, PB_MM);
	close_image(img);
	if (ret <= 0)
		return ret;

	if (collect_special_file(ri->mm->exe_file_id) == NULL)
		return -1;

	pr_debug("Found %zd VMAs in image\n", ri->mm->n_vmas);
	img = NULL;
	if (ri->mm->n_vmas == 0) {
		/*
		 * Old image. Read VMAs from vma-.img
		 */
		img = open_image(CR_FD_VMAS, O_RSTR, pid);
		if (!img)
			return -1;
	}

	while (vn < ri->mm->n_vmas || img != NULL) {
		struct vma_area *vma;

		ret = -1;
		vma = alloc_vma_area();
		if (!vma)
			break;

		ri->vmas.nr++;
		if (!img)
			vma->e = ri->mm->vmas[vn++];
		else {
			ret = pb_read_one_eof(img, &vma->e, PB_VMA);
			if (ret <= 0) {
				xfree(vma);
				close_image(img);
				img = NULL;
				break;
			}
		}
		list_add_tail(&vma->list, &ri->vmas.h);

		if (vma_area_is_private(vma, kdat.task_size)) {
			ri->vmas.rst_priv_size += vma_area_len(vma);
			if (vma_has_guard_gap_hidden(vma))
				ri->vmas.rst_priv_size += PAGE_SIZE;
		}

		pr_info("vma 0x%" PRIx64 " 0x%" PRIx64 "\n", vma->e->start, vma->e->end);

		if (vma_area_is(vma, VMA_ANON_SHARED))
			ret = collect_shmem(pid, vma);
		else if (vma_area_is(vma, VMA_FILE_PRIVATE) || vma_area_is(vma, VMA_FILE_SHARED))
			ret = collect_filemap(vma);
		else if (vma_area_is(vma, VMA_AREA_SOCKET))
			ret = collect_socket_map(vma);
		else
			ret = 0;
		if (ret)
			break;
	}

	if (img)
		close_image(img);
	return ret;
}

static inline bool check_cow_vmas(struct vma_area *vma, struct vma_area *pvma)
{
	/*
	 * VMAs that _may_[1] have COW-ed pages should ...
	 *
	 * [1] I say "may" because whether or not particular pages are
	 * COW-ed is determined later in restore_priv_vma_content() by
	 * memcmp'aring the contents.
	 */

	/* ... coincide by start/stop pair (start is checked by caller) */
	if (vma->e->end != pvma->e->end)
		return false;
	/* ... both be private (and thus have space in premmaped area) */
	if (!vma_area_is_private(vma, kdat.task_size))
		return false;
	if (!vma_area_is_private(pvma, kdat.task_size))
		return false;
	/* ... but not hugetlb mappings */
	if (vma->e->flags & MAP_HUGETLB || pvma->e->flags & MAP_HUGETLB)
		return false;
	/* ... have growsdown and anon flags coincide */
	if ((vma->e->flags ^ pvma->e->flags) & (MAP_GROWSDOWN | MAP_ANONYMOUS))
		return false;
	/* ... belong to the same file if being filemap */
	if (!(vma->e->flags & MAP_ANONYMOUS) && vma->e->shmid != pvma->e->shmid)
		return false;

	pr_debug("Found two COW VMAs @0x%" PRIx64 "-0x%" PRIx64 "\n", vma->e->start, pvma->e->end);
	return true;
}

static inline bool vma_inherited(struct vma_area *vma)
{
	return (vma->pvma != NULL && vma->pvma != VMA_COW_ROOT);
}

static void prepare_cow_vmas_for(struct vm_area_list *vmas, struct vm_area_list *pvmas)
{
	struct vma_area *vma, *pvma;

	vma = list_first_entry(&vmas->h, struct vma_area, list);
	pvma = list_first_entry(&pvmas->h, struct vma_area, list);

	while (1) {
		if ((vma->e->start == pvma->e->start) && check_cow_vmas(vma, pvma)) {
			vma->pvma = pvma;
			if (pvma->pvma == NULL)
				pvma->pvma = VMA_COW_ROOT;
		}

		/* <= here to shift from matching VMAs and ... */
		while (vma->e->start <= pvma->e->start) {
			vma = vma_next(vma);
			if ((&vma->list == &vmas->h) || vma_area_is(vma, VMA_AREA_GUARD))
				return;
		}

		/* ... no == here since we must stop on matching pair */
		while (pvma->e->start < vma->e->start) {
			pvma = vma_next(pvma);
			if ((&pvma->list == &pvmas->h) || vma_area_is(pvma, VMA_AREA_GUARD))
				return;
		}
	}
}

void prepare_cow_vmas(void)
{
	struct pstree_item *pi;

	for_each_pstree_item(pi) {
		struct pstree_item *ppi;
		struct vm_area_list *vmas, *pvmas;

		ppi = pi->parent;
		if (!ppi)
			continue;

		vmas = &rsti(pi)->vmas;
		if (vmas->nr == 0) /* Zombie */
			continue;

		pvmas = &rsti(ppi)->vmas;
		if (pvmas->nr == 0) /* zombies cannot have kids,
				     * but helpers can (and do) */
			continue;

		if (rsti(pi)->mm->exe_file_id != rsti(ppi)->mm->exe_file_id)
			/*
			 * Tasks running different executables have
			 * close to zero chance of having cow-ed areas
			 * and actually kernel never creates such.
			 */
			continue;

		prepare_cow_vmas_for(vmas, pvmas);
	}
}

/* Map a private vma, if it is not mapped by a parent yet */
static int premap_private_vma(struct pstree_item *t, struct vma_area *vma, void **tgt_addr)
{
	int ret;
	void *addr;
	unsigned long nr_pages, size;

	nr_pages = vma_entry_len(vma->e) / PAGE_SIZE;
	vma->page_bitmap = xzalloc(BITS_TO_LONGS(nr_pages) * sizeof(long));
	if (vma->page_bitmap == NULL)
		return -1;

	/*
	 * A grow-down VMA has a guard page, which protect a VMA below it.
	 * So one more page is mapped here to restore content of the first page
	 */
	if (vma_has_guard_gap_hidden(vma))
		vma->e->start -= PAGE_SIZE;

	size = vma_entry_len(vma->e);

	if (!vma_inherited(vma)) {
		int flag = 0;
		/*
		 * The respective memory area was NOT found in the parent.
		 * Map a new one.
		 */

		/*
		 * Restore AIO ring buffer content to temporary anonymous area.
		 * This will be placed in io_setup'ed AIO in restore_aio_ring().
		 */
		if (vma_entry_is(vma->e, VMA_AREA_AIORING))
			flag |= MAP_ANONYMOUS;
		else if (vma_area_is(vma, VMA_FILE_PRIVATE)) {
			ret = vma->vm_open(vpid(t), vma);
			if (ret < 0) {
				pr_err("Can't fixup VMA's fd\n");
				return -1;
			}
		}

		/*
		 * All mappings here get PROT_WRITE regardless of whether we
		 * put any data into it or not, because this area will get
		 * mremap()-ed (branch below) so we MIGHT need to have WRITE
		 * bits there. Ideally we'd check for the whole COW-chain
		 * having any data in.
		 */
		addr = mmap(*tgt_addr, size, vma->e->prot | PROT_WRITE, vma->e->flags | MAP_FIXED | flag, vma->e->fd,
			    vma->e->pgoff);

		if (addr == MAP_FAILED) {
			pr_perror("Unable to map ANON_VMA");
			return -1;
		}
	} else {
		void *paddr;

		/*
		 * The area in question can be COWed with the parent. Remap the
		 * parent area. Note, that it has already being passed through
		 * the restore_priv_vma_content() call and thus may have some
		 * pages in it.
		 */

		paddr = decode_pointer(vma->pvma->premmaped_addr);
		if (vma_has_guard_gap_hidden(vma))
			paddr -= PAGE_SIZE;

		addr = mremap(paddr, size, size, MREMAP_FIXED | MREMAP_MAYMOVE, *tgt_addr);
		if (addr != *tgt_addr) {
			pr_perror("Unable to remap a private vma");
			return -1;
		}
	}

	vma->e->status |= VMA_PREMMAPED;
	vma->premmaped_addr = (unsigned long)addr;
	pr_debug("\tpremap %#016" PRIx64 "-%#016" PRIx64 " -> %016lx\n", vma->e->start, vma->e->end,
		 (unsigned long)addr);

	if (vma_has_guard_gap_hidden(vma)) { /* Skip guard page */
		vma->e->start += PAGE_SIZE;
		vma->premmaped_addr += PAGE_SIZE;
	}

	if (vma_area_is(vma, VMA_FILE_PRIVATE))
		vma->vm_open = NULL; /* prevent from 2nd open in prepare_vmas */

	*tgt_addr += size;
	return 0;
}

static inline bool vma_force_premap(struct vma_area *vma, struct list_head *head)
{
	/*
	 * Shadow stack VMAs cannot be mmap()ed, they must be created using
	 * map_shadow_stack() system call.
	 * Premap them to reserve virtual address space and populate them
	 * to have there contents available for later copying.
	 */
	if (vma_area_is(vma, VMA_AREA_SHSTK))
		return true;

	/*
	 * On kernels with 4K guard pages, growsdown VMAs
	 * always have one guard page at the
	 * beginning and sometimes this page contains data.
	 * In case the VMA is premmaped, we premmap one page
	 * larger VMA. In case of in place restore we can only
	 * do this if the VMA in question is not "guarded" by
	 * some other VMA.
	 */
	if (vma->e->flags & MAP_GROWSDOWN) {
		if (vma->list.prev != head) {
			struct vma_area *prev;

			prev = list_entry(vma->list.prev, struct vma_area, list);
			if (prev->e->end == vma->e->start) {
				pr_debug("Force premmap for 0x%" PRIx64 ":0x%" PRIx64 "\n", vma->e->start, vma->e->end);
				return true;
			}
		}
	}

	return false;
}

/*
 * Ensure for s390x that vma is below task size on restore system
 */
static int task_size_check(pid_t pid, VmaEntry *entry)
{
#ifdef __s390x__
	if (entry->end <= kdat.task_size)
		return 0;
	pr_err("Can't restore high memory region %lx-%lx because kernel does only support vmas up to %lx\n",
	       entry->start, entry->end, kdat.task_size);
	return -1;
#else
	return 0;
#endif
}

static int premap_priv_vmas(struct pstree_item *t, struct vm_area_list *vmas, void **at, struct page_read *pr)
{
	struct vma_area *vma;
	unsigned long pstart = 0;
	int ret = 0;
	LIST_HEAD(empty);

	filemap_ctx_init(true);

	list_for_each_entry(vma, &vmas->h, list) {
		if (vma_area_is(vma, VMA_AREA_GUARD))
			continue;

		if (task_size_check(vpid(t), vma->e)) {
			ret = -1;
			break;
		}
		if (pstart > vma->e->start) {
			ret = -1;
			pr_err("VMA-s are not sorted in the image file\n");
			break;
		}
		pstart = vma->e->start;

		if (!vma_area_is_private(vma, kdat.task_size))
			continue;

		if (vma->e->flags & MAP_HUGETLB)
			continue;

		/* VMA offset may change due to plugin so we cannot premap */
		if (vma->e->status & VMA_EXT_PLUGIN)
			continue;

		if (vma->pvma == NULL && pr->pieok && !vma_force_premap(vma, &vmas->h)) {
			/*
			 * VMA in question is not shared with anyone. We'll
			 * restore it with its contents in restorer.
			 * Now let's check whether we need to map it with
			 * PROT_WRITE or not.
			 */
			do {
				if (pr->pe->vaddr + pr->pe->nr_pages * PAGE_SIZE <= vma->e->start)
					continue;
				if (pr->pe->vaddr >= vma->e->end)
					vma->e->status |= VMA_NO_PROT_WRITE;
				break;
			} while (pr->advance(pr));

			continue;
		}

		ret = premap_private_vma(t, vma, at);

		if (ret < 0)
			break;
	}

	filemap_ctx_fini();

	return ret;
}

static int restore_priv_vma_content(struct pstree_item *t, struct page_read *pr)
{
	struct vma_area *vma;
	int ret = 0;
	struct list_head *vmas = &rsti(t)->vmas.h;
	struct list_head *vma_io = &rsti(t)->vma_io;

	unsigned int nr_restored = 0;
	unsigned int nr_shared = 0;
	unsigned int nr_dropped = 0;
	unsigned int nr_compared = 0;
	unsigned int nr_enqueued = 0;
	unsigned int nr_lazy = 0;
	unsigned long va;

	vma = list_first_entry(vmas, struct vma_area, list);
	rsti(t)->pages_img_id = pr->pages_img_id;

	/*
	 * Read page contents.
	 */
	while (1) {
		unsigned long off, i, nr_pages;

		ret = pr->advance(pr);
		if (ret <= 0)
			break;

		va = (unsigned long)decode_pointer(pr->pe->vaddr);
		nr_pages = pr->pe->nr_pages;

		/*
		 * This means that userfaultfd is used to load the pages
		 * on demand.
		 */
		if (opts.lazy_pages && pagemap_lazy(pr->pe)) {
			pr_debug("Lazy restore skips %ld pages at %lx\n", nr_pages, va);
			pr->skip_pages(pr, nr_pages * PAGE_SIZE);
			nr_lazy += nr_pages;
			continue;
		}

		for (i = 0; i < nr_pages; i++) {
			unsigned char buf[PAGE_SIZE];
			void *p;

			/*
			 * The lookup is over *all* possible VMAs
			 * read from image file.
			 */
			while (va >= vma->e->end) {
				if (vma->list.next == vmas)
					goto err_addr;
				vma = vma_next(vma);
			}

			/*
			 * Make sure the page address is inside existing VMA
			 * and the VMA it refers to still private one, since
			 * there is no guarantee that the data from pagemap is
			 * valid.
			 */
			if (va < vma->e->start)
				goto err_addr;
			else if (unlikely(!vma_area_is_private(vma, kdat.task_size))) {
				pr_err("Trying to restore page for non-private VMA\n");
				goto err_addr;
			}

			if (!vma_area_is(vma, VMA_PREMMAPED)) {
				unsigned long len = min_t(unsigned long, (nr_pages - i) * PAGE_SIZE, vma->e->end - va);

				if (vma->e->status & VMA_NO_PROT_WRITE) {
					pr_debug("VMA 0x%" PRIx64 ":0x%" PRIx64 " RO %#lx:%lu IO\n", vma->e->start,
						 vma->e->end, va, nr_pages);
					BUG();
				}

				if (pagemap_enqueue_iovec(pr, (void *)va, len, vma_io))
					return -1;

				pr->skip_pages(pr, len);

				va += len;
				len >>= PAGE_SHIFT;
				nr_restored += len;
				i += len - 1;

				nr_enqueued++;
				continue;
			}

			/*
			 * Otherwise to the COW restore
			 */

			off = (va - vma->e->start) / PAGE_SIZE;
			p = decode_pointer((off)*PAGE_SIZE + vma->premmaped_addr);

			set_bit(off, vma->page_bitmap);
			if (vma_inherited(vma)) {
				clear_bit(off, vma->pvma->page_bitmap);

				ret = pr->read_pages(pr, va, 1, buf, 0);
				if (ret < 0)
					goto err_read;

				va += PAGE_SIZE;
				nr_compared++;

				if (memcmp(p, buf, PAGE_SIZE) == 0) {
					nr_shared++; /* the page is cowed */
					continue;
				}

				nr_restored++;
				memcpy(p, buf, PAGE_SIZE);
			} else {
				int nr;

				/*
				 * Try to read as many pages as possible at once.
				 *
				 * Within the t pagemap we still have
				 * nr_pages - i pages (not all, as we might have
				 * switched VMA above), within the t VMA
				 * we have at most (vma->end - t_addr) bytes.
				 */

				nr = min_t(int, nr_pages - i, (vma->e->end - va) / PAGE_SIZE);

				ret = pr->read_pages(pr, va, nr, p, PR_ASYNC);
				if (ret < 0)
					goto err_read;

				va += nr * PAGE_SIZE;
				nr_restored += nr;
				i += nr - 1;

				bitmap_set(vma->page_bitmap, off + 1, nr - 1);
			}
		}
	}

err_read:
	if (pr->sync(pr))
		return -1;

	pr->close(pr);
	if (ret < 0)
		return ret;

	/* Remove pages, which were not shared with a child */
	list_for_each_entry(vma, vmas, list) {
		unsigned long size, i = 0;
		void *addr = decode_pointer(vma->premmaped_addr);

		if (vma_area_is(vma, VMA_AREA_GUARD))
			continue;

		if (!vma_inherited(vma))
			continue;

		size = vma_entry_len(vma->e) / PAGE_SIZE;
		while (1) {
			/* Find all pages, which are not shared with this child */
			i = find_next_bit(vma->pvma->page_bitmap, size, i);

			if (i >= size)
				break;

			ret = madvise(addr + PAGE_SIZE * i, PAGE_SIZE, MADV_DONTNEED);
			if (ret < 0) {
				pr_perror("madvise failed");
				return -1;
			}
			i++;
			nr_dropped++;
		}
	}

	cnt_add(CNT_PAGES_COMPARED, nr_compared);
	cnt_add(CNT_PAGES_SKIPPED_COW, nr_shared);
	cnt_add(CNT_PAGES_RESTORED, nr_restored);

	pr_info("nr_restored_pages: %d\n", nr_restored);
	pr_info("nr_shared_pages:   %d\n", nr_shared);
	pr_info("nr_dropped_pages:  %d\n", nr_dropped);
	pr_info("nr_enqueued:       %d\n", nr_enqueued);
	pr_info("nr_lazy:           %d\n", nr_lazy);

	return 0;

err_addr:
	pr_err("Page entry address %lx outside of VMA %lx-%lx\n", va, (long)vma->e->start, (long)vma->e->end);
	return -1;
}

static int maybe_disable_thp(struct pstree_item *t, struct page_read *pr)
{
	/*
	 * There is no need to disable it if the page read doesn't
	 * have parent. In this case VMA will be empty until
	 * userfaultfd_register, so there would be no pages to
	 * collapse. And, once we register the VMA with uffd,
	 * khugepaged will skip it.
	 */
	if (!(opts.lazy_pages && page_read_has_parent(pr)))
		return 0;

	if (!kdat.has_thp_disable)
		pr_warn("Disabling transparent huge pages. "
			"It may affect performance!\n");

	/*
	 * temporarily disable THP to avoid collapse of pages
	 * in the areas that will be monitored by uffd
	 */
	if (prctl(PR_SET_THP_DISABLE, 1, 0, 0, 0)) {
		pr_perror("Cannot disable THP");
		return -1;
	}

	return 0;
}

int prepare_mappings(struct pstree_item *t)
{
	int ret = 0;
	void *addr;
	struct vm_area_list *vmas;
	struct page_read pr;

	void *old_premmapped_addr = NULL;
	unsigned long old_premmapped_len;

	vmas = &rsti(t)->vmas;
	if (vmas->nr == 0) /* Zombie */
		goto out;

	/* Reserve a place for mapping private vma-s one by one */
	addr = mmap(NULL, vmas->rst_priv_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	if (addr == MAP_FAILED) {
		ret = -1;
		pr_perror("Unable to reserve memory (%lu bytes)", vmas->rst_priv_size);
		goto out;
	}

	old_premmapped_addr = rsti(t)->premmapped_addr;
	old_premmapped_len = rsti(t)->premmapped_len;
	rsti(t)->premmapped_addr = addr;
	rsti(t)->premmapped_len = vmas->rst_priv_size;

	ret = open_page_read(vpid(t), &pr, PR_TASK);
	if (ret <= 0)
		return -1;

	if (maybe_disable_thp(t, &pr))
		return -1;

	pr.advance(&pr); /* shift to the 1st iovec */

	ret = premap_priv_vmas(t, vmas, &addr, &pr);
	if (ret < 0)
		goto out;

	pr.reset(&pr);

	ret = restore_priv_vma_content(t, &pr);
	if (ret < 0)
		goto out;

	if (old_premmapped_addr) {
		ret = munmap(old_premmapped_addr, old_premmapped_len);
		if (ret < 0)
			pr_perror("Unable to unmap %p(%lx)", old_premmapped_addr, old_premmapped_len);
	}

	/*
	 * Not all VMAs were premmaped. Find out the unused tail of the
	 * premapped area and unmap it.
	 */
	old_premmapped_len = addr - rsti(t)->premmapped_addr;
	if (old_premmapped_len < rsti(t)->premmapped_len) {
		unsigned long tail;

		tail = rsti(t)->premmapped_len - old_premmapped_len;
		ret = munmap(addr, tail);
		if (ret < 0)
			pr_perror("Unable to unmap %p(%lx)", addr, tail);
		rsti(t)->premmapped_len = old_premmapped_len;
		pr_info("Shrunk premap area to %p(%lx)\n", rsti(t)->premmapped_addr, rsti(t)->premmapped_len);
	}

out:
	return ret;
}

bool vma_has_guard_gap_hidden(struct vma_area *vma)
{
	return kdat.stack_guard_gap_hidden && (vma->e->flags & MAP_GROWSDOWN);
}

/*
 * A guard page must be unmapped after restoring content and
 * forking children to restore COW memory.
 */
int unmap_guard_pages(struct pstree_item *t)
{
	struct vma_area *vma;
	struct list_head *vmas = &rsti(t)->vmas.h;

	if (!kdat.stack_guard_gap_hidden)
		return 0;

	list_for_each_entry(vma, vmas, list) {
		if (!vma_area_is(vma, VMA_PREMMAPED))
			continue;

		if (vma->e->flags & MAP_GROWSDOWN) {
			void *addr = decode_pointer(vma->premmaped_addr);

			if (munmap(addr - PAGE_SIZE, PAGE_SIZE)) {
				pr_perror("Can't unmap guard page");
				return -1;
			}
		}
	}

	return 0;
}

int open_vmas(struct pstree_item *t)
{
	int pid = vpid(t);
	struct vma_area *vma;
	struct vm_area_list *vmas = &rsti(t)->vmas;

	filemap_ctx_init(false);

	list_for_each_entry(vma, &vmas->h, list) {
		if (!vma_area_is(vma, VMA_AREA_REGULAR) || !vma->vm_open)
			continue;

		pr_info("Opening %#016" PRIx64 "-%#016" PRIx64 " %#016" PRIx64 " (%x) vma\n", vma->e->start,
			vma->e->end, vma->e->pgoff, vma->e->status);

		if (vma->vm_open(pid, vma)) {
			pr_err("`- Can't open vma\n");
			return -1;
		}

		/*
		 * File mappings have vm_open set to open_filemap which, in
		 * turn, puts the VMA_CLOSE bit itself. For all the rest we
		 * need to put it by hands, so that the restorer closes the fd
		 */
		if (!(vma_area_is(vma, VMA_FILE_PRIVATE) || vma_area_is(vma, VMA_FILE_SHARED)))
			vma->e->status |= VMA_CLOSE;
	}

	filemap_ctx_fini();

	return 0;
}

static int prepare_vma_ios(struct pstree_item *t, struct task_restore_args *ta)
{
	struct cr_img *pages;

	/*
	 * We optimize the case when rsti(t)->vma_io is empty.
	 *
	 * This is useful when using the image streamer, where all VMAs are
	 * premapped (pr->pieok is false). This avoids re-opening the
	 * CR_FD_PAGES file, which may only be readable only once.
	 */
	if (list_empty(&rsti(t)->vma_io)) {
		ta->vma_ios = NULL;
		ta->vma_ios_n = 0;
		ta->vma_ios_fd = -1;
		return 0;
	}

	/*
	 * If auto-dedup is on we need RDWR mode to be able to punch holes in
	 * the input files (in restorer.c)
	 */
	pages = open_image(CR_FD_PAGES, opts.auto_dedup ? O_RDWR : O_RSTR, rsti(t)->pages_img_id);
	if (!pages)
		return -1;

	ta->vma_ios_fd = img_raw_fd(pages);
	return pagemap_render_iovec(&rsti(t)->vma_io, ta);
}

int prepare_vmas(struct pstree_item *t, struct task_restore_args *ta)
{
	struct vma_area *vma;
	struct vm_area_list *vmas = &rsti(t)->vmas;

	ta->vmas = (VmaEntry *)rst_mem_align_cpos(RM_PRIVATE);
	ta->vmas_n = vmas->nr;

	list_for_each_entry(vma, &vmas->h, list) {
		VmaEntry *vme;

		vme = rst_mem_alloc(sizeof(*vme), RM_PRIVATE);
		if (!vme)
			return -1;

		/*
		 * Copy VMAs to private rst memory so that it's able to
		 * walk them and m(un|re)map.
		 */
		*vme = *vma->e;

		if (vma_area_is(vma, VMA_PREMMAPED))
			vma_premmaped_start(vme) = vma->premmaped_addr;
	}

	return prepare_vma_ios(t, ta);
}

int collect_madv_guards(pid_t pid, struct vm_area_list *vma_area_list)
{
	int pagemap_fd = -1;
	struct page_region *regs = NULL;
	long regs_len = 0;
	int i, ret = -1;

	struct pm_scan_arg args = {
		.size = sizeof(struct pm_scan_arg),
		.flags = 0,
		.start = 0,
		.end = kdat.task_size,
		.walk_end = 0,
		.vec_len = 1000, /* this should be enough for most cases */
		.max_pages = 0,
		.category_mask = PAGE_IS_GUARD,
		.return_mask = PAGE_IS_GUARD,
	};

	if (!kdat.has_pagemap_scan_guard_pages) {
		ret = 0;
		goto out;
	}

	pagemap_fd = open_proc(pid, "pagemap");
	if (pagemap_fd < 0)
		goto out;

	regs = xmalloc(args.vec_len * sizeof(struct page_region));
	if (!regs)
		goto out;
	args.vec = (long)regs;

	do {
		/* start from where we finished the last time */
		args.start = args.walk_end;
		regs_len = ioctl(pagemap_fd, PAGEMAP_SCAN, &args);
		if (regs_len == -1) {
			pr_perror("PAGEMAP_SCAN");
			goto out;
		}

		for (i = 0; i < regs_len; i++) {
			struct vma_area *vma;

			BUG_ON(!(regs[i].categories & PAGE_IS_GUARD));

			vma = alloc_vma_area();
			if (!vma)
				goto out;

			vma->e->start = regs[i].start;
			vma->e->end = regs[i].end;
			vma->e->status = VMA_AREA_GUARD;

			list_add_tail(&vma->list, &vma_area_list->h);
			vma_area_list->nr++;
		}
	} while (args.walk_end != kdat.task_size);

	ret = 0;

out:
	xfree(regs);
	if (pagemap_fd >= 0)
		close(pagemap_fd);
	return ret;
}
