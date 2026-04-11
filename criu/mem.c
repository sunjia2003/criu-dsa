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
#define DSA_BATCH_TARGET_US_DEFAULT	2000U
#define DSA_BATCH_TARGET_US_MIN	200U
#define MEM_DUMP_ASYNC_MIN_PAGES_DEFAULT	4096U

struct dsa_dump_ctx;

struct mem_dump_async {
	pthread_t tid;
	struct page_pipe *pp;
	struct page_xfer xfer;
	int xfer_ret;
	int pid;
	bool dsa_live_defer;
	struct dsa_dump_ctx *dsa_ctx_deferred;
};
#define DSA_BATCH_TARGET_US_MAX	500000U
#define DSA_BATCH_LIMIT_MIN_DEFAULT	128U
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

static __maybe_unused unsigned int dsa_batch_target_us(void)
{
	return dsa_parse_env_u32("CRIU_DSA_BATCH_TARGET_US",
				 DSA_BATCH_TARGET_US_DEFAULT,
				 DSA_BATCH_TARGET_US_MIN,
				 DSA_BATCH_TARGET_US_MAX);
}

static __maybe_unused unsigned int dsa_batch_limit_min(void)
{
	return dsa_parse_env_u32("CRIU_DSA_BATCH_MIN_DESC",
				 DSA_BATCH_LIMIT_MIN_DEFAULT,
				 1,
				 DSA_DUMP_BATCH_SIZE);
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

static unsigned int mem_dump_async_min_pages(void)
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

static bool dsa_populate_read_enabled(void)
{
	const char *env;

	env = getenv("CRIU_DSA_POPULATE_READ");
	if (!env)
		return false;

	return atoi(env) > 0;
}

static int dsa_open_pidfd(pid_t pid)
{
#ifdef SYS_pidfd_open
	return syscall(SYS_pidfd_open, pid, 0);
#else
	errno = ENOSYS;
	return -1;
#endif
}

static void dsa_try_populate_read_batch(int pidfd, u64 *src_addrs,
					u32 *copy_lens, unsigned int nr)
{
#ifdef SYS_process_madvise
	struct iovec iovs[DSA_DUMP_BATCH_SIZE];
	unsigned int i;
	ssize_t advised;
	size_t total = 0;

	if (pidfd < 0 || !nr)
		return;

	if (nr > DSA_DUMP_BATCH_SIZE)
		nr = DSA_DUMP_BATCH_SIZE;

	for (i = 0; i < nr; i++) {
		iovs[i].iov_base = (void *)(unsigned long)src_addrs[i];
		iovs[i].iov_len = copy_lens[i];
		total += copy_lens[i];
	}

	advised = syscall(SYS_process_madvise, pidfd, iovs, nr,
			 MADV_POPULATE_READ, 0);
	if (advised < 0) {
		pr_debug("DSA populate_read skipped: %d\n", errno);
		return;
	}

	if ((size_t)advised < total)
		pr_debug("DSA populate_read partial: %zd/%zu\n", advised, total);
#else
	(void)pidfd;
	(void)src_addrs;
	(void)copy_lens;
	(void)nr;
#endif
}

static bool dsa_dump_enabled(void)
{
	const char *env;

	env = getenv("CRIU_DSA_DUMP");
	if (!env)
		return false;

	return atoi(env) > 0;
}

static bool dsa_desc_scan_enabled(void)
{
	const char *env;

	env = getenv("CRIU_DSA_DESC_SCAN");
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
	int pidfd;
	bool do_populate_read;
	bool shared_from_before_freeze;
	bool shared_fds_sent;
	bool shared_hugetlb;
	u32 shared_degrade_cnt;
	size_t shared_buf_size;
	int wq_count;
	char wq_paths[DSA_DUMP_MAX_WQ][64];
	struct {
		pthread_t tid;
		pthread_mutex_t lock;
		pthread_cond_t cond;
		bool started;
		bool inited;
		bool stop;
		bool busy;
		bool fatal;
		int fatal_errno;
		int pipe_fd;
		struct list_head queue;
	} replay;
};

static void dsa_replay_ctx_init(struct dsa_dump_ctx *ctx);
static int dsa_replay_wait_idle(struct dsa_dump_ctx *ctx);
static void dsa_replay_stop(struct dsa_dump_ctx *ctx);

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

	ctx->do_populate_read = dsa_populate_read_enabled();
	if (ctx->do_populate_read) {
		ctx->pidfd = dsa_open_pidfd(target_pid);
		if (ctx->pidfd < 0)
			pr_debug("DSA populate_read disabled: can't open pidfd for %d\n",
				 target_pid);
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

	if (dsa_replay_wait_idle(ctx)) {
		pr_err("DSA replay wait failed during ctx fini\n");
		ret = -1;
	}
	dsa_replay_stop(ctx);

	if (ctx->shared_buf != MAP_FAILED && !ctx->shared_from_before_freeze)
		munmap(ctx->shared_buf, ctx->shared_buf_size);
	if (ctx->shared_fd >= 0)
		close(ctx->shared_fd);
	if (ctx->pidfd >= 0)
		close(ctx->pidfd);

	ctx->shared_fd = -1;
	ctx->shared_buf = MAP_FAILED;
	ctx->pidfd = -1;
	ctx->shared_from_before_freeze = false;

	return ret;
}

struct dsa_replay_task {
	struct list_head l;
	u32 data_off;
	u32 data_bytes;
	u32 batch_id;
};

static int dsa_vmsplice_to_pipe(int pipe_fd, void *buf, size_t len, u32 batch_id)
{
	size_t done = 0;

	while (done < len) {
		struct iovec iov = {
			.iov_base = (char *)buf + done,
			.iov_len = len - done,
		};
		ssize_t ret = vmsplice(pipe_fd, &iov, 1,
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
	ctx->replay.started = false;
	ctx->replay.inited = true;
	ctx->replay.stop = false;
	ctx->replay.busy = false;
	ctx->replay.fatal = false;
	ctx->replay.fatal_errno = 0;
	ctx->replay.pipe_fd = -1;
	INIT_LIST_HEAD(&ctx->replay.queue);
	pthread_mutex_init(&ctx->replay.lock, NULL);
	pthread_cond_init(&ctx->replay.cond, NULL);
}

static void dsa_replay_ctx_destroy(struct dsa_dump_ctx *ctx)
{
	if (!ctx->replay.inited)
		return;
	ctx->replay.inited = false;
	pthread_cond_destroy(&ctx->replay.cond);
	pthread_mutex_destroy(&ctx->replay.lock);
}

static void *dsa_replay_thread(void *arg)
{
	struct dsa_dump_ctx *ctx = arg;

	workload_bind_scope(WORK_SCOPE_MEM_DSA_REPLAY);

	for (;;) {
		struct dsa_replay_task *task;
		int ret;

		pthread_mutex_lock(&ctx->replay.lock);
		while (list_empty(&ctx->replay.queue) && !ctx->replay.stop &&
		       !ctx->replay.fatal)
			pthread_cond_wait(&ctx->replay.cond, &ctx->replay.lock);

		if ((ctx->replay.stop || ctx->replay.fatal) &&
		    list_empty(&ctx->replay.queue)) {
			pthread_mutex_unlock(&ctx->replay.lock);
			break;
		}

		task = list_first_entry(&ctx->replay.queue,
					 struct dsa_replay_task, l);
		list_del(&task->l);
		ctx->replay.busy = true;
		pthread_mutex_unlock(&ctx->replay.lock);

		ret = dsa_vmsplice_to_pipe(ctx->replay.pipe_fd,
					   (u8 *)ctx->shared_buf + task->data_off,
					   task->data_bytes, task->batch_id);
		if (ret) {
			pthread_mutex_lock(&ctx->replay.lock);
			ctx->replay.fatal = true;
			ctx->replay.fatal_errno = errno ? errno : EIO;
			while (!list_empty(&ctx->replay.queue)) {
				struct dsa_replay_task *tmp;
				tmp = list_first_entry(&ctx->replay.queue,
							struct dsa_replay_task, l);
				list_del(&tmp->l);
				xfree(tmp);
			}
			ctx->replay.busy = false;
			pthread_cond_broadcast(&ctx->replay.cond);
			pthread_mutex_unlock(&ctx->replay.lock);
			xfree(task);
			break;
		}

		pthread_mutex_lock(&ctx->replay.lock);
		ctx->replay.busy = false;
		pthread_cond_broadcast(&ctx->replay.cond);
		pthread_mutex_unlock(&ctx->replay.lock);
		xfree(task);
	}

	workload_unbind_scope();

	return NULL;
}

static int dsa_replay_start(struct dsa_dump_ctx *ctx, int pipe_fd)
{
	if (ctx->replay.started) {
		if (ctx->replay.pipe_fd != pipe_fd) {
			pr_err("DSA replay pipe mismatch: %d vs %d\n",
			       ctx->replay.pipe_fd, pipe_fd);
			return -1;
		}
		return 0;
	}

	ctx->replay.pipe_fd = pipe_fd;
	if (pthread_create(&ctx->replay.tid, NULL, dsa_replay_thread, ctx)) {
		pr_err("Can't create DSA replay thread\n");
		ctx->replay.pipe_fd = -1;
		return -1;
	}
	ctx->replay.started = true;
	return 0;
}

static int dsa_replay_enqueue(struct dsa_dump_ctx *ctx, u32 data_off,
			      u32 data_bytes, u32 batch_id, int pipe_fd)
{
	struct dsa_replay_task *task;

	if (ctx->replay.fatal) {
		pr_err("DSA replay in fatal state (errno=%d)\n",
		       ctx->replay.fatal_errno);
		return -1;
	}

	if (dsa_replay_start(ctx, pipe_fd))
		return -1;

	task = xzalloc(sizeof(*task));
	if (!task)
		return -1;

	task->data_off = data_off;
	task->data_bytes = data_bytes;
	task->batch_id = batch_id;

	pthread_mutex_lock(&ctx->replay.lock);
	list_add_tail(&task->l, &ctx->replay.queue);
	pthread_cond_signal(&ctx->replay.cond);
	pthread_mutex_unlock(&ctx->replay.lock);

	return 0;
}

static int dsa_replay_wait_idle(struct dsa_dump_ctx *ctx)
{
	if (!ctx->replay.inited || !ctx->replay.started)
		return 0;

	pthread_mutex_lock(&ctx->replay.lock);
	while (!ctx->replay.fatal &&
	       (ctx->replay.busy || !list_empty(&ctx->replay.queue)))
		pthread_cond_wait(&ctx->replay.cond, &ctx->replay.lock);

	if (ctx->replay.fatal) {
		pthread_mutex_unlock(&ctx->replay.lock);
		pr_err("DSA replay failed (errno=%d)\n", ctx->replay.fatal_errno);
		return -1;
	}

	pthread_mutex_unlock(&ctx->replay.lock);
	return 0;
}

static void dsa_replay_stop(struct dsa_dump_ctx *ctx)
{
	if (!ctx->replay.inited || !ctx->replay.started) {
		dsa_replay_ctx_destroy(ctx);
		return;
	}

	pthread_mutex_lock(&ctx->replay.lock);
	ctx->replay.stop = true;
	pthread_cond_broadcast(&ctx->replay.cond);
	pthread_mutex_unlock(&ctx->replay.lock);

	pthread_join(ctx->replay.tid, NULL);
	ctx->replay.started = false;
	ctx->replay.pipe_fd = -1;
	dsa_replay_ctx_destroy(ctx);
}

struct dsa_batch_stats {
	u64 total_bytes;
	u64 total_desc;
	u32 rpc_calls;
	u32 le_1m;
	u32 le_4m;
	u32 le_16m;
	u32 gt_16m;
	u32 submit_degrade_calls;
	size_t max_bytes;
	size_t min_bytes;
	u32 max_desc;
	u32 min_desc;
	u64 submit_enqcmd;
	u64 submit_write;
	u64 map_populate_fallbacks;
	u64 prefault_us;
	u64 submit_us;
	u64 poll_us;
	u64 max_prefault_us;
	u64 min_prefault_us;
	u64 max_submit_us;
	u64 min_submit_us;
	u64 max_poll_us;
	u64 min_poll_us;
	u64 setup_us;
	u64 setup_shared_us;
	u64 setup_wq_us;
	u64 setup_shared_recv_fd_us;
	u64 setup_shared_mmap_us;
	u64 setup_wq_recv_fd_us;
	u64 setup_wq_open_us;
	u64 setup_wq_mmap_us;
	u64 cleanup_munmap_us;
	u64 cleanup_close_us;
	u64 max_setup_us;
	u64 min_setup_us;
};

struct dsa_desc_scan_ctx {
	struct parasite_ctl *ctl;
	struct parasite_dump_pages_args *args;
	struct dsa_dump_ctx *dsa_ctx;

	bool do_populate_read;
	int pidfd;
	int dsa_pipe_fd;
	bool send_shared_fds;

	u64 *batch_src_addr;
	u32 *batch_copy_len;
	size_t batch_cap;

	unsigned int args_nr_vmas_saved;
	unsigned int args_add_prot_saved;
	unsigned int args_off_cur;
	void *args_tail_saved;
	size_t args_tail_sz;

	u32 desc_count;
	size_t batch_bytes;
	u64 desc_seq_out_of_order;
	u64 desc_seq_discont;
	u64 desc_seq_total;
	struct dsa_batch_stats stats;
};

static void dsa_batch_stats_init(struct dsa_batch_stats *stats)
{
	memset(stats, 0, sizeof(*stats));
	stats->min_bytes = SIZE_MAX;
	stats->min_desc = UINT_MAX;
	stats->min_prefault_us = ULLONG_MAX;
	stats->min_submit_us = ULLONG_MAX;
	stats->min_poll_us = ULLONG_MAX;
	stats->min_setup_us = ULLONG_MAX;
}

static void dsa_batch_stats_add(struct dsa_batch_stats *stats,
				size_t batch_bytes, u32 desc_count,
				const struct parasite_dsa_dump_pages_args *dargs)
{
	stats->total_bytes += batch_bytes;
	stats->total_desc += desc_count;

	if (batch_bytes > stats->max_bytes)
		stats->max_bytes = batch_bytes;
	if (batch_bytes < stats->min_bytes)
		stats->min_bytes = batch_bytes;

	if (desc_count > stats->max_desc)
		stats->max_desc = desc_count;
	if (desc_count < stats->min_desc)
		stats->min_desc = desc_count;

	if (batch_bytes <= (1U << 20))
		stats->le_1m++;
	else if (batch_bytes <= (4U << 20))
		stats->le_4m++;
	else if (batch_bytes <= (16U << 20))
		stats->le_16m++;
	else
		stats->gt_16m++;

	stats->submit_enqcmd += dargs->submit_enqcmd;
	stats->submit_write += dargs->submit_write;
	stats->map_populate_fallbacks += dargs->map_populate_fallbacks;
	stats->prefault_us += dargs->prefault_us;
	stats->submit_us += dargs->submit_us;
	stats->poll_us += dargs->poll_us;
	stats->setup_us += dargs->setup_us;
	stats->setup_shared_us += dargs->setup_shared_us;
	stats->setup_wq_us += dargs->setup_wq_us;
	stats->setup_shared_recv_fd_us += dargs->setup_shared_recv_fd_us;
	stats->setup_shared_mmap_us += dargs->setup_shared_mmap_us;
	stats->setup_wq_recv_fd_us += dargs->setup_wq_recv_fd_us;
	stats->setup_wq_open_us += dargs->setup_wq_open_us;
	stats->setup_wq_mmap_us += dargs->setup_wq_mmap_us;
	stats->cleanup_munmap_us += dargs->cleanup_munmap_us;
	stats->cleanup_close_us += dargs->cleanup_close_us;
	if (dargs->prefault_us > stats->max_prefault_us)
		stats->max_prefault_us = dargs->prefault_us;
	if (dargs->prefault_us < stats->min_prefault_us)
		stats->min_prefault_us = dargs->prefault_us;
	if (dargs->submit_us > stats->max_submit_us)
		stats->max_submit_us = dargs->submit_us;
	if (dargs->submit_us < stats->min_submit_us)
		stats->min_submit_us = dargs->submit_us;
	if (dargs->poll_us > stats->max_poll_us)
		stats->max_poll_us = dargs->poll_us;
	if (dargs->poll_us < stats->min_poll_us)
		stats->min_poll_us = dargs->poll_us;
	if (dargs->setup_us > stats->max_setup_us)
		stats->max_setup_us = dargs->setup_us;
	if (dargs->setup_us < stats->min_setup_us)
		stats->min_setup_us = dargs->setup_us;
	if (dargs->submit_write)
		stats->submit_degrade_calls++;
}

static void dsa_batch_stats_log(const struct dsa_batch_stats *stats,
				const struct dsa_dump_ctx *ctx)
{
	u64 avg_prefault_us;
	u64 min_prefault_us;
	u64 avg_submit_us;
	u64 avg_poll_us;
	u64 avg_submit_poll_us;
	u64 min_submit_us;
	u64 min_poll_us;
	u64 avg_setup_us;
	u64 avg_setup_shared_us;
	u64 avg_setup_wq_us;
	u64 avg_setup_shared_recv_fd_us;
	u64 avg_setup_shared_mmap_us;
	u64 avg_setup_wq_recv_fd_us;
	u64 avg_setup_wq_open_us;
	u64 avg_setup_wq_mmap_us;
	u64 avg_cleanup_munmap_us;
	u64 avg_cleanup_close_us;
	u64 min_setup_us;

	if (!stats->rpc_calls)
		return;

	avg_prefault_us = stats->prefault_us / stats->rpc_calls;
	avg_submit_us = stats->submit_us / stats->rpc_calls;
	avg_poll_us = stats->poll_us / stats->rpc_calls;
	avg_submit_poll_us = (stats->submit_us + stats->poll_us) /
		stats->rpc_calls;
	avg_setup_us = stats->setup_us / stats->rpc_calls;
	avg_setup_shared_us = stats->setup_shared_us / stats->rpc_calls;
	avg_setup_wq_us = stats->setup_wq_us / stats->rpc_calls;
	avg_setup_shared_recv_fd_us = stats->setup_shared_recv_fd_us /
		stats->rpc_calls;
	avg_setup_shared_mmap_us = stats->setup_shared_mmap_us /
		stats->rpc_calls;
	avg_setup_wq_recv_fd_us = stats->setup_wq_recv_fd_us /
		stats->rpc_calls;
	avg_setup_wq_open_us = stats->setup_wq_open_us / stats->rpc_calls;
	avg_setup_wq_mmap_us = stats->setup_wq_mmap_us / stats->rpc_calls;
	avg_cleanup_munmap_us = stats->cleanup_munmap_us / stats->rpc_calls;
	avg_cleanup_close_us = stats->cleanup_close_us / stats->rpc_calls;
	min_prefault_us = stats->min_prefault_us == ULLONG_MAX ? 0 :
		stats->min_prefault_us;
	min_submit_us = stats->min_submit_us == ULLONG_MAX ? 0 :
		stats->min_submit_us;
	min_poll_us = stats->min_poll_us == ULLONG_MAX ? 0 :
		stats->min_poll_us;
	min_setup_us = stats->min_setup_us == ULLONG_MAX ? 0 :
		stats->min_setup_us;

	pr_info("DSA batch stats: calls=%u avg_bytes=%llu avg_desc=%llu min_bytes=%zu max_bytes=%zu min_desc=%u max_desc=%u bins[<=1M:%u <=4M:%u <=16M:%u >16M:%u]\n",
		stats->rpc_calls,
		(unsigned long long)(stats->total_bytes / stats->rpc_calls),
		(unsigned long long)(stats->total_desc / stats->rpc_calls),
		stats->min_bytes, stats->max_bytes,
		stats->min_desc, stats->max_desc,
		stats->le_1m, stats->le_4m, stats->le_16m, stats->gt_16m);
	pr_info("DSA submit stats: calls=%u enqcmd_desc=%llu write_desc=%llu submit_degrade_calls=%u map_populate_fallbacks=%llu shared_mem_mode=%s shared_mem_degrades=%u\n",
		stats->rpc_calls,
		(unsigned long long)stats->submit_enqcmd,
		(unsigned long long)stats->submit_write,
		stats->submit_degrade_calls,
		(unsigned long long)stats->map_populate_fallbacks,
		ctx->shared_hugetlb ? "hugetlb" : "normal_memfd",
		ctx->shared_degrade_cnt);
	pr_info("DSA prefault stats: calls=%u total_us=%llu avg_us=%llu min_us=%llu max_us=%llu\n",
		stats->rpc_calls,
		(unsigned long long)stats->prefault_us,
		(unsigned long long)avg_prefault_us,
		(unsigned long long)min_prefault_us,
		(unsigned long long)stats->max_prefault_us);
	pr_info("DSA submit/poll stats: calls=%u submit_total_us=%llu poll_total_us=%llu submit_poll_total_us=%llu avg_submit_us=%llu avg_poll_us=%llu avg_submit_poll_us=%llu min_submit_us=%llu max_submit_us=%llu min_poll_us=%llu max_poll_us=%llu\n",
		stats->rpc_calls,
		(unsigned long long)stats->submit_us,
		(unsigned long long)stats->poll_us,
		(unsigned long long)(stats->submit_us + stats->poll_us),
		(unsigned long long)avg_submit_us,
		(unsigned long long)avg_poll_us,
		(unsigned long long)avg_submit_poll_us,
		(unsigned long long)min_submit_us,
		(unsigned long long)stats->max_submit_us,
		(unsigned long long)min_poll_us,
		(unsigned long long)stats->max_poll_us);
	pr_info("DSA setup stats: calls=%u setup_total_us=%llu shared_total_us=%llu wq_total_us=%llu avg_setup_us=%llu avg_shared_us=%llu avg_wq_us=%llu min_setup_us=%llu max_setup_us=%llu\n",
		stats->rpc_calls,
		(unsigned long long)stats->setup_us,
		(unsigned long long)stats->setup_shared_us,
		(unsigned long long)stats->setup_wq_us,
		(unsigned long long)avg_setup_us,
		(unsigned long long)avg_setup_shared_us,
		(unsigned long long)avg_setup_wq_us,
		(unsigned long long)min_setup_us,
		(unsigned long long)stats->max_setup_us);
	pr_info("DSA setup breakdown: calls=%u shared_recv_fd_total_us=%llu shared_mmap_total_us=%llu wq_recv_fd_total_us=%llu wq_open_total_us=%llu wq_mmap_total_us=%llu cleanup_munmap_total_us=%llu cleanup_close_total_us=%llu avg_shared_recv_fd_us=%llu avg_shared_mmap_us=%llu avg_wq_recv_fd_us=%llu avg_wq_open_us=%llu avg_wq_mmap_us=%llu avg_cleanup_munmap_us=%llu avg_cleanup_close_us=%llu\n",
		stats->rpc_calls,
		(unsigned long long)stats->setup_shared_recv_fd_us,
		(unsigned long long)stats->setup_shared_mmap_us,
		(unsigned long long)stats->setup_wq_recv_fd_us,
		(unsigned long long)stats->setup_wq_open_us,
		(unsigned long long)stats->setup_wq_mmap_us,
		(unsigned long long)stats->cleanup_munmap_us,
		(unsigned long long)stats->cleanup_close_us,
		(unsigned long long)avg_setup_shared_recv_fd_us,
		(unsigned long long)avg_setup_shared_mmap_us,
		(unsigned long long)avg_setup_wq_recv_fd_us,
		(unsigned long long)avg_setup_wq_open_us,
		(unsigned long long)avg_setup_wq_mmap_us,
		(unsigned long long)avg_cleanup_munmap_us,
		(unsigned long long)avg_cleanup_close_us);
}

static int dsa_flush_one_batch(struct parasite_ctl *ctl,
			       struct parasite_dump_pages_args *args,
			       struct dsa_dump_ctx *ctx,
			       bool do_populate_read, int pidfd,
			       u64 *batch_src_addr, u32 *batch_copy_len,
			       u32 desc_count, size_t batch_bytes,
			       u32 data_off, bool is_last_batch,
			       int dsa_pipe_fd, bool *send_shared_fds,
			       unsigned int args_nr_vmas_saved,
			       unsigned int args_add_prot_saved,
			       unsigned int args_off_cur,
			       void *args_tail_saved, size_t args_tail_sz,
			       struct dsa_batch_stats *stats);

static void dsa_desc_scan_reset_batch(struct dsa_desc_scan_ctx *sc)
{
	sc->desc_count = 0;
	sc->batch_bytes = 0;
}

static int dsa_desc_scan_ensure_cap(struct dsa_desc_scan_ctx *sc, u32 desc_idx)
{
	void *tmp;
	size_t new_cap;

	if (desc_idx < sc->batch_cap)
		return 0;

	new_cap = sc->batch_cap ? sc->batch_cap * 2 : 128;
	while (desc_idx >= new_cap)
		new_cap *= 2;

	tmp = xrealloc(sc->batch_src_addr, new_cap * sizeof(*sc->batch_src_addr));
	if (!tmp)
		return -1;
	sc->batch_src_addr = tmp;

	tmp = xrealloc(sc->batch_copy_len, new_cap * sizeof(*sc->batch_copy_len));
	if (!tmp)
		return -1;
	sc->batch_copy_len = tmp;
	sc->batch_cap = new_cap;

	return 0;
}

static int dsa_desc_scan_batch_append(struct dsa_desc_scan_ctx *sc,
				      u64 src_addr, u32 copy_len,
				      bool is_last)
{
	struct parasite_dsa_shm_hdr *shm_hdr;
	struct dsa_dump_descriptor *shm_desc;
	u8 *shared_u8;
	u32 next_desc_count;
	u32 desc_bytes;
	u32 data_off;
	u32 merge_idx = 0;
	size_t copy_budget;
	bool merge_prev;

	shared_u8 = sc->dsa_ctx->shared_buf;
	shm_desc = (struct dsa_dump_descriptor *)(shared_u8 +
						  sizeof(struct parasite_dsa_shm_hdr));

	retry_append:
	merge_prev = false;
	next_desc_count = sc->desc_count + 1;

	if (sc->desc_count > 0) {
		u64 prev_src = shm_desc[sc->desc_count - 1].src_addr;
		u32 prev_len = shm_desc[sc->desc_count - 1].copy_len;
		u64 expected = prev_src + prev_len;

		/* Keep each desc bounded even when source pages are contiguous. */
		if (src_addr == expected && prev_len <= UINT_MAX - copy_len &&
		    prev_len + copy_len <= DSA_DESC_SCAN_MAX_COPY_LEN) {
			merge_prev = true;
			next_desc_count = sc->desc_count;
			merge_idx = sc->desc_count - 1;
		}
	}

	desc_bytes = next_desc_count * sizeof(struct dsa_dump_descriptor);
	data_off = round_up(sizeof(struct parasite_dsa_shm_hdr) + desc_bytes,
			    DSA_SHARED_DATA_ALIGN);

	if (data_off >= sc->dsa_ctx->shared_buf_size)
		return -1;

	if (sc->batch_bytes >= sc->dsa_ctx->shared_buf_size - data_off)
		goto need_flush;

	copy_budget = sc->dsa_ctx->shared_buf_size - data_off - sc->batch_bytes;
	if (copy_len > copy_budget)
		goto need_flush;

	if (sc->desc_count > 0) {
		u64 prev_src = shm_desc[sc->desc_count - 1].src_addr;
		u32 prev_len = shm_desc[sc->desc_count - 1].copy_len;
		u64 expected = prev_src + prev_len;

		sc->desc_seq_total++;
		if (src_addr < prev_src)
			sc->desc_seq_out_of_order++;
		else if (src_addr != expected)
			sc->desc_seq_discont++;
	}

	if (merge_prev) {
		shm_desc[merge_idx].copy_len += copy_len;
		sc->batch_copy_len[merge_idx] += copy_len;
	} else {
		if (dsa_desc_scan_ensure_cap(sc, sc->desc_count))
			return -1;

		shm_desc[sc->desc_count].src_addr = src_addr;
		shm_desc[sc->desc_count].copy_len = copy_len;
		shm_desc[sc->desc_count].reserved0 = 0;

		sc->batch_src_addr[sc->desc_count] = src_addr;
		sc->batch_copy_len[sc->desc_count] = copy_len;

		sc->desc_count = next_desc_count;
	}
	sc->batch_bytes += copy_len;

	if (!is_last)
		return 0;

	/* Last append will be flushed by caller. */
	return 0;

	need_flush:
	if (!sc->desc_count)
		return -1;

	desc_bytes = sc->desc_count * sizeof(struct dsa_dump_descriptor);
	data_off = round_up(sizeof(struct parasite_dsa_shm_hdr) + desc_bytes,
			    DSA_SHARED_DATA_ALIGN);

	if (data_off >= sc->dsa_ctx->shared_buf_size ||
	    sc->batch_bytes > sc->dsa_ctx->shared_buf_size - data_off)
		return -1;

	shm_hdr = (struct parasite_dsa_shm_hdr *)sc->dsa_ctx->shared_buf;
	memset(shm_hdr, 0, sizeof(*shm_hdr));
	shm_hdr->magic = PARASITE_DSA_SHM_HDR_MAGIC;
	shm_hdr->version = PARASITE_DSA_SHM_HDR_VERSION;
	shm_hdr->desc_bytes = desc_bytes;
	shm_hdr->desc_count = sc->desc_count;
	shm_hdr->data_off = data_off;
	shm_hdr->data_bytes = sc->batch_bytes;

	if (dsa_flush_one_batch(sc->ctl, sc->args, sc->dsa_ctx,
				sc->do_populate_read, sc->pidfd,
				sc->batch_src_addr, sc->batch_copy_len,
				sc->desc_count, sc->batch_bytes, data_off,
				false, sc->dsa_pipe_fd,
				&sc->send_shared_fds,
				sc->args_nr_vmas_saved,
				sc->args_add_prot_saved,
				sc->args_off_cur,
				sc->args_tail_saved,
				sc->args_tail_sz,
				&sc->stats))
		return -1;

	dsa_desc_scan_reset_batch(sc);
	goto retry_append;
}

static int dsa_desc_scan_flush_last(struct dsa_desc_scan_ctx *sc)
{
	struct parasite_dsa_shm_hdr *shm_hdr;
	u32 desc_bytes;
	u32 data_off;

	if (!sc->desc_count)
		return 0;

	desc_bytes = sc->desc_count * sizeof(struct dsa_dump_descriptor);
	data_off = round_up(sizeof(struct parasite_dsa_shm_hdr) + desc_bytes,
			    DSA_SHARED_DATA_ALIGN);

	if (data_off >= sc->dsa_ctx->shared_buf_size ||
	    sc->batch_bytes > sc->dsa_ctx->shared_buf_size - data_off)
		return -1;

	shm_hdr = (struct parasite_dsa_shm_hdr *)sc->dsa_ctx->shared_buf;
	memset(shm_hdr, 0, sizeof(*shm_hdr));
	shm_hdr->magic = PARASITE_DSA_SHM_HDR_MAGIC;
	shm_hdr->version = PARASITE_DSA_SHM_HDR_VERSION;
	shm_hdr->desc_bytes = desc_bytes;
	shm_hdr->desc_count = sc->desc_count;
	shm_hdr->data_off = data_off;
	shm_hdr->data_bytes = sc->batch_bytes;

	if (dsa_flush_one_batch(sc->ctl, sc->args, sc->dsa_ctx,
				sc->do_populate_read, sc->pidfd,
				sc->batch_src_addr, sc->batch_copy_len,
				sc->desc_count, sc->batch_bytes, data_off,
				true, sc->dsa_pipe_fd,
				&sc->send_shared_fds,
				sc->args_nr_vmas_saved,
				sc->args_add_prot_saved,
				sc->args_off_cur,
				sc->args_tail_saved,
				sc->args_tail_sz,
				&sc->stats))
		return -1;

	dsa_desc_scan_reset_batch(sc);
	return 0;
}

static int dsa_flush_one_batch(struct parasite_ctl *ctl,
			       struct parasite_dump_pages_args *args,
			       struct dsa_dump_ctx *ctx,
			       bool do_populate_read, int pidfd,
			       u64 *batch_src_addr, u32 *batch_copy_len,
			       u32 desc_count, size_t batch_bytes,
			       u32 data_off, bool is_last_batch,
			       int dsa_pipe_fd, bool *send_shared_fds,
			       unsigned int args_nr_vmas_saved,
			       unsigned int args_add_prot_saved,
			       unsigned int args_off_cur,
			       void *args_tail_saved, size_t args_tail_sz,
			       struct dsa_batch_stats *stats)
{
	struct parasite_dsa_dump_pages_args *dargs;
	unsigned int j;
	int ret;

	dargs = xzalloc(sizeof(*dargs));
	if (!dargs)
		return -1;

	dargs->shared_buf_addr = 0;
	dargs->shared_buf_size = ctx->shared_buf_size;
	dargs->hdr_off = 0;
	dargs->buf_write_offset = data_off;
	dargs->batch_id = ++stats->rpc_calls;
	dargs->is_last_batch = is_last_batch;
	dargs->wq_count = ctx->wq_count;
	dargs->use_shared_buf_fd = *send_shared_fds ? 1 : 0;
	dargs->use_wq_fd = 0;
	dargs->wq_policy = DSA_WQ_POLICY_LPT;
	for (j = 0; j < (unsigned int)ctx->wq_count; j++) {
		size_t path_len;

		path_len = strnlen(ctx->wq_paths[j], sizeof(dargs->wq_paths[j]) - 1);
		memcpy(dargs->wq_paths[j], ctx->wq_paths[j], path_len);
		dargs->wq_paths[j][path_len] = '\0';
	}

	if (do_populate_read)
		dsa_try_populate_read_batch(pidfd, batch_src_addr,
					 batch_copy_len, desc_count);

	workload_switch_scope(WORK_SCOPE_MEM_DSA_RPC);
	timing_start(TIME_DSA_RPC);
	ret = parasite_dsa_dump_pages_seized(ctl, dargs, ctx->shared_fd, NULL,
					     ctx->wq_count);
	timing_stop(TIME_DSA_RPC);
	workload_switch_scope(WORK_SCOPE_MEM_DSA_BATCH_BUILD);

	args->nr_vmas = args_nr_vmas_saved;
	args->add_prot = args_add_prot_saved;
	args->off = args_off_cur;
	if (args_tail_saved)
		memcpy(pargs_vmas(args), args_tail_saved, args_tail_sz);

	if (ret) {
		pr_err("DSA page dump RPC failed: ret=%d op_ret=%d failed_idx=%d status=%u completed=%u copied=%u\n",
		       ret, dargs->op_ret, dargs->failed_idx,
		       dargs->failed_status, dargs->completed_count,
		       dargs->total_copied);
		goto out;
	}

	pr_info("DSA_BATCH_MODE: batch_id=%u submit_enqcmd=%u submit_write=%u map_populate_fallbacks=%u setup_us=%llu setup_shared_us=%llu setup_wq_us=%llu setup_shared_recv_fd_us=%llu setup_shared_mmap_us=%llu setup_wq_recv_fd_us=%llu setup_wq_open_us=%llu setup_wq_mmap_us=%llu cleanup_munmap_us=%llu cleanup_close_us=%llu prefault_us=%llu submit_us=%llu poll_us=%llu submit_poll_us=%llu\n",
		dargs->batch_id, dargs->submit_enqcmd,
		dargs->submit_write, dargs->map_populate_fallbacks,
		(unsigned long long)dargs->setup_us,
		(unsigned long long)dargs->setup_shared_us,
		(unsigned long long)dargs->setup_wq_us,
		(unsigned long long)dargs->setup_shared_recv_fd_us,
		(unsigned long long)dargs->setup_shared_mmap_us,
		(unsigned long long)dargs->setup_wq_recv_fd_us,
		(unsigned long long)dargs->setup_wq_open_us,
		(unsigned long long)dargs->setup_wq_mmap_us,
		(unsigned long long)dargs->cleanup_munmap_us,
		(unsigned long long)dargs->cleanup_close_us,
		(unsigned long long)dargs->prefault_us,
		(unsigned long long)dargs->submit_us,
		(unsigned long long)dargs->poll_us,
		(unsigned long long)(dargs->submit_us + dargs->poll_us));
	if (dargs->submit_write)
		pr_info("DSA_DEGRADE: category=submit from=enqcmd to=write batch_id=%u submit_enqcmd=%u submit_write=%u\n",
			dargs->batch_id, dargs->submit_enqcmd,
			dargs->submit_write);

	*send_shared_fds = false;
	ctx->shared_fds_sent = true;

	if (dargs->total_copied != batch_bytes ||
	    dargs->new_buf_offset != data_off + batch_bytes) {
		pr_err("DSA copied size mismatch: expected copied=%zu off=%u got copied=%u off=%u\n",
		       batch_bytes, data_off + (u32)batch_bytes,
		       dargs->total_copied, dargs->new_buf_offset);
		ret = -1;
		goto out;
	}

	if (dsa_replay_enqueue(ctx, data_off, batch_bytes,
			     dargs->batch_id, dsa_pipe_fd)) {
		pr_err("DSA replay enqueue failed (batch=%u)\n",
		       dargs->batch_id);
		ret = -1;
		goto out;
	}

	dsa_batch_stats_add(stats, batch_bytes, desc_count, dargs);

	if (!is_last_batch) {
		workload_switch_scope(WORK_SCOPE_MEM_DSA_REPLAY);
		ret = dsa_replay_wait_idle(ctx);
		workload_switch_scope(WORK_SCOPE_MEM_DSA_BATCH_BUILD);
		if (ret) {
			pr_err("DSA replay wait failed before next batch\n");
			ret = -1;
			goto out;
		}
	}

	out:
	xfree(dargs);
	return ret;
}

/*
 * Return values:
 *  0  - DSA path used successfully.
 *  1  - DSA path unavailable, caller should use legacy drain path.
 * <0  - DSA path selected but failed.
 */
static int drain_pages_dsa(struct page_pipe *pp, struct parasite_ctl *ctl,
			   struct parasite_dump_pages_args *args, pid_t target_pid,
			   struct dsa_dump_ctx *ctx)
{
	struct page_pipe_buf *cur_ppb;
	int ret = 0;
	bool do_populate_read;
	int pidfd;
	void *shared_buf;
	unsigned int cur_seg_off;
	unsigned int cur_seg_pos;
	unsigned int args_off_cur;
	unsigned int cur_ppb_off;
	u32 desc_count;
	int dsa_pipe_fd = -1;
	u64 *batch_src_addr = NULL;
	u32 *batch_copy_len = NULL;
	size_t batch_cap = 0;
	size_t batch_bytes;
	size_t rem;
	size_t max_chunk;
	size_t len;
	size_t args_tail_sz;
	struct parasite_dsa_shm_hdr *shm_hdr;
	struct dsa_dump_descriptor *shm_desc;
	struct iovec *src_iov;
	u8 *shared_u8;
	u32 desc_bytes;
	u32 data_off;
	size_t copy_budget;
	void *args_tail_saved = NULL;
	unsigned int args_nr_vmas_saved;
	unsigned int args_add_prot_saved;
	unsigned int args_off_saved;
	bool send_shared_fds;
	size_t shared_buf_size;
	struct dsa_batch_stats stats;

	if (!ctx)
		return -1;

	if (!dsa_dump_enabled())
		return 1;

	workload_switch_scope(WORK_SCOPE_MEM_DSA_CTX_INIT);
	ret = dsa_dump_ctx_init(ctx, target_pid);
	if (ret) {
		workload_switch_scope(WORK_SCOPE_MEM_DUMP_MISC);
		return ret;
	}

	workload_switch_scope(WORK_SCOPE_MEM_DSA_BATCH_BUILD);

	args_nr_vmas_saved = args->nr_vmas;
	args_add_prot_saved = args->add_prot;
	args_off_saved = args->off;
	args_off_cur = args_off_saved;

	do_populate_read = ctx->do_populate_read;
	pidfd = ctx->pidfd;

	shared_buf_size = ctx->shared_buf_size;
	shared_buf = ctx->shared_buf;
	shared_u8 = shared_buf;
	send_shared_fds = !ctx->shared_fds_sent;
	dsa_batch_stats_init(&stats);

	/*
	 * DSA RPC reuses parasite args area and overwrites its beginning.
	 * Preserve dump vma/iov payload so legacy fallback and next batches
	 * can safely use PARASITE_CMD_DUMPPAGES arguments.
	 */
	args_tail_sz = args->nr_vmas * sizeof(struct parasite_vma_entry) +
		      pp->nr_iovs * sizeof(struct iovec);
	if (args_tail_sz) {
		args_tail_saved = xmalloc(args_tail_sz);
		if (!args_tail_saved)
			return -1;
		memcpy(args_tail_saved, pargs_vmas(args), args_tail_sz);
	}

	debug_show_page_pipe(pp);
	if (list_empty(&pp->bufs)) {
		ret = 0;
		goto out;
	}

	cur_ppb = list_first_entry(&pp->bufs, struct page_pipe_buf, l);
	cur_ppb_off = args_off_cur;
	cur_seg_off = 0;
	cur_seg_pos = 0;

	while (cur_ppb) {
		desc_count = 0;
		batch_bytes = 0;
		shm_desc = (struct dsa_dump_descriptor *)(shared_u8 +
					 sizeof(struct parasite_dsa_shm_hdr));

		while (cur_ppb) {
			src_iov = pp->iovs + cur_ppb_off;

			while (cur_seg_off < cur_ppb->nr_segs &&
			       cur_seg_pos >= src_iov[cur_seg_off].iov_len) {
				cur_seg_off++;
				cur_seg_pos = 0;
			}

			if (cur_seg_off >= cur_ppb->nr_segs) {
				args_off_cur = cur_ppb_off + cur_ppb->nr_segs;
				if (list_is_last(&cur_ppb->l, &pp->bufs)) {
					cur_ppb = NULL;
					break;
				}

				cur_ppb = list_entry(cur_ppb->l.next,
						     struct page_pipe_buf, l);
				cur_ppb_off = args_off_cur;
				cur_seg_off = 0;
				cur_seg_pos = 0;
				continue;
			}

			if (dsa_pipe_fd < 0)
				dsa_pipe_fd = cur_ppb->p[1];
			else if (cur_ppb->p[1] != dsa_pipe_fd) {
				pr_err("DSA strict expects single pipe, got %d vs %d\n",
				       dsa_pipe_fd, cur_ppb->p[1]);
				ret = -1;
				goto out;
			}

			desc_bytes = (desc_count + 1) * sizeof(struct dsa_dump_descriptor);
			data_off = round_up(sizeof(struct parasite_dsa_shm_hdr) + desc_bytes,
					    DSA_SHARED_DATA_ALIGN);
			if (data_off >= shared_buf_size)
				break;

			if (batch_bytes >= shared_buf_size - data_off)
				break;

			copy_budget = shared_buf_size - data_off - batch_bytes;
			if (!copy_budget)
				break;

			rem = src_iov[cur_seg_off].iov_len - cur_seg_pos;
			max_chunk = copy_budget;
			len = rem;
			if (len > (size_t)UINT_MAX)
				len = (size_t)UINT_MAX;
			if (len > max_chunk)
				len = max_chunk;
			if (!len)
				break;

			shm_desc[desc_count].src_addr = (u64)(unsigned long)
				((char *)src_iov[cur_seg_off].iov_base + cur_seg_pos);
			shm_desc[desc_count].copy_len = (u32)len;
			shm_desc[desc_count].reserved0 = 0;

			if (do_populate_read) {
				if (desc_count >= batch_cap) {
					size_t new_cap = batch_cap ? batch_cap * 2 : 128;
					void *tmp;

					tmp = xrealloc(batch_src_addr,
							 new_cap * sizeof(*batch_src_addr));
					if (!tmp) {
						ret = -1;
						goto out;
					}
					batch_src_addr = tmp;
					tmp = xrealloc(batch_copy_len,
							 new_cap * sizeof(*batch_copy_len));
					if (!tmp) {
						ret = -1;
						goto out;
					}
					batch_copy_len = tmp;
					batch_cap = new_cap;
				}
				batch_src_addr[desc_count] =
					shm_desc[desc_count].src_addr;
				batch_copy_len[desc_count] =
					shm_desc[desc_count].copy_len;
			}

			batch_bytes += len;
			cur_seg_pos += len;
			desc_count++;
		}

		if (!desc_count) {
			if (!cur_ppb)
				break;

			pr_err("DSA batch build failed: shared buffer too small\n");
			ret = -1;
			goto out;
		}

		desc_bytes = desc_count * sizeof(struct dsa_dump_descriptor);
		data_off = round_up(sizeof(struct parasite_dsa_shm_hdr) + desc_bytes,
				    DSA_SHARED_DATA_ALIGN);
		if (data_off >= shared_buf_size ||
		    batch_bytes > shared_buf_size - data_off) {
			pr_err("DSA shared layout overflow: data_off=%u batch_bytes=%zu buf_size=%zu\n",
			       data_off, batch_bytes, shared_buf_size);
			ret = -1;
			goto out;
		}

		shm_hdr = (struct parasite_dsa_shm_hdr *)shared_buf;
		memset(shm_hdr, 0, sizeof(*shm_hdr));
		shm_hdr->magic = PARASITE_DSA_SHM_HDR_MAGIC;
		shm_hdr->version = PARASITE_DSA_SHM_HDR_VERSION;
		shm_hdr->desc_bytes = desc_bytes;
		shm_hdr->desc_count = desc_count;
		shm_hdr->data_off = data_off;
		shm_hdr->data_bytes = batch_bytes;

		ret = dsa_flush_one_batch(ctl, args, ctx, do_populate_read,
					  pidfd, batch_src_addr,
					  batch_copy_len, desc_count,
					  batch_bytes, data_off,
					  cur_ppb == NULL,
					  dsa_pipe_fd,
					  &send_shared_fds,
					  args_nr_vmas_saved,
					  args_add_prot_saved,
					  args_off_cur,
					  args_tail_saved,
					  args_tail_sz,
					  &stats);
		if (ret)
			goto out;
	}

	args->off = args_off_cur;
	dsa_batch_stats_log(&stats, ctx);

	ret = 0;
out:
	xfree(batch_src_addr);
	xfree(batch_copy_len);
	xfree(args_tail_saved);

	args->nr_vmas = args_nr_vmas_saved;
	args->add_prot = args_add_prot_saved;

	if (ret < 0)
		args->off = args_off_cur;

	workload_switch_scope(WORK_SCOPE_MEM_DUMP_MISC);

	return ret;
}

static int drain_pages(struct page_pipe *pp, struct parasite_ctl *ctl,
		       struct parasite_dump_pages_args *args, pid_t target_pid,
		       bool allow_dsa, struct dsa_dump_ctx *dsa_ctx)
{
	struct page_pipe_buf *ppb;
	unsigned int args_off;
	int ret = 0;
	int dsa_ret = 1;
	bool dsa_strict = dsa_dump_enabled();

	args_off = args->off;

	if (allow_dsa && dsa_strict) {
		dsa_ret = drain_pages_dsa(pp, ctl, args, target_pid, dsa_ctx);
		if (dsa_ret) {
			pr_err("DSA strict drain failed: ret=%d\n", dsa_ret);
			return (dsa_ret > 0) ? -EIO : dsa_ret;
		}
		workload_switch_scope(WORK_SCOPE_MEM_DUMP_MISC);
		return 0;
	}

	workload_switch_scope(WORK_SCOPE_MEM_DRAIN_BASE_RPC);

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
			workload_switch_scope(WORK_SCOPE_MEM_DUMP_MISC);
			return -1;
		}
		ret = compel_util_send_fd(ctl, ppb->p[1]);
		if (ret) {
			workload_switch_scope(WORK_SCOPE_MEM_DUMP_MISC);
			return -1;
		}

		ret = compel_rpc_sync(PARASITE_CMD_DUMPPAGES, ctl);
		if (ret < 0) {
			workload_switch_scope(WORK_SCOPE_MEM_DUMP_MISC);
			return -1;
		}

		args_off += args->nr_segs;
	}

	args->off = args_off;
	workload_switch_scope(WORK_SCOPE_MEM_DUMP_MISC);

	return 0;
}

static int xfer_pages(struct page_pipe *pp, struct page_xfer *xfer)
{
	int ret;

	/*
	 * Step 3 -- write pages into image (or delay writing for
	 *           pre-dump action (see pre_dump_one_task)
	 */
	workload_switch_scope(WORK_SCOPE_MEM_WRITE_SYNC);
	timing_start(TIME_MEMWRITE);
	ret = page_xfer_dump_pages(xfer, pp);
	timing_stop(TIME_MEMWRITE);
	workload_switch_scope(WORK_SCOPE_MEM_DUMP_MISC);

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

	workload_bind_scope(WORK_SCOPE_MEM_WRITE_ASYNC);

	pr_debug("Async memwrite: start for pid %d\n", async->pid);
	timing_start(TIME_MEMWRITE);
	async->xfer_ret = page_xfer_dump_pages(&async->xfer, async->pp);
	timing_stop(TIME_MEMWRITE);
	pr_debug("Async memwrite: done for pid %d ret=%d\n", async->pid,
		 async->xfer_ret);

	workload_unbind_scope();

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
	async->pid = item->pid->real;
	async->dsa_live_defer = false;
	async->dsa_ctx_deferred = NULL;

	if (pthread_create(&async->tid, NULL, mem_dump_async_xfer_thread, async)) {
		pr_err("Can't create async memwrite thread for pid %d\n",
		       item->pid->real);
		xfree(async);
		return -1;
	}

	dmpi(item)->mem_async = async;
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
	int ret;

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
	int ret = 0;
	int dsa_ret;

	async = dmpi(item)->mem_async;
	if (!async)
		return 0;

	workload_switch_scope(WORK_SCOPE_MEM_WRITE_WAIT);
	timing_start(TIME_ASYNC_WAIT);
	if (pthread_join(async->tid, NULL)) {
		timing_stop(TIME_ASYNC_WAIT);
		pr_err("Can't join async memwrite thread for pid %d\n", async->pid);
		/*
		 * Thread state is unknown here, don't release shared resources
		 * to avoid use-after-free if it is still running.
		 */
		workload_switch_scope(WORK_SCOPE_MEM_DUMP_MISC);
		return -1;
	}

	if (!ret && async->xfer_ret)
		ret = async->xfer_ret;

	dsa_ret = dsa_deferred_ctx_finalize(async);
	if (!ret && dsa_ret)
		ret = dsa_ret;

	async->xfer.close(&async->xfer);
	destroy_page_pipe(async->pp);
	dmpi(item)->mem_async = NULL;
	xfree(async);
	timing_stop(TIME_ASYNC_WAIT);
	workload_switch_scope(WORK_SCOPE_MEM_DUMP_MISC);

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
			     int parent_predump_mode, bool allow_dsa,
			     struct dsa_dump_ctx *dsa_ctx)
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
	workload_switch_scope(WORK_SCOPE_MEM_SCAN_IOV);
	ret = generate_iovs(item, vma, pp, pmc, &vaddr, has_parent);
	workload_switch_scope(WORK_SCOPE_MEM_DUMP_MISC);
	if (ret == -EAGAIN) {
		BUG_ON(!(pp->flags & PP_CHUNK_MODE));

		ret = drain_pages(pp, ctl, args, item->pid->real, allow_dsa,
				  dsa_ctx);
		if (!ret)
			ret = xfer_pages(pp, xfer);
		if (!ret) {
			page_pipe_reinit(pp);
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
			vaddr = page_info.next - PAGE_SIZE;
			continue;
		}

		if (vma_entry_can_be_lazy(vma->e) && !is_stack(item, vaddr))
			ppb_flags |= PPB_LAZY;

		if (has_parent && page_in_parent(page_info.softdirty)) {
			ret = page_pipe_add_hole(pp, vaddr, PP_HOLE_PARENT);
			st = 0;
		} else {
			ret = page_pipe_add_page_unbounded(pp, vaddr, ppb_flags);
			if (!ret) {
				ret = dsa_desc_scan_batch_append(sc,
					(u64)(unsigned long)vaddr,
					PAGE_SIZE, false);
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
	workload_switch_scope(WORK_SCOPE_MEM_SCAN_IOV);
	ret = generate_iovs_dsa_desc_scan(item, vma, pp, pmc, &vaddr,
					 has_parent, sc);
	workload_switch_scope(WORK_SCOPE_MEM_DUMP_MISC);

	if (ret == -EAGAIN) {
		pr_err("DSA desc-scan got unexpected EAGAIN\n");
		return -1;
	}

	return ret;
}

static int __parasite_dump_pages_seized(struct pstree_item *item, struct parasite_dump_pages_args *args,
					struct vm_area_list *vma_area_list, struct mem_dump_ctl *mdc,
					struct parasite_ctl *ctl)
{
	pmc_t pmc = PMC_INIT;
	struct page_pipe *pp;
	struct vma_area *vma_area;
	struct page_xfer xfer = { .parent = NULL };
	int ret, exit_code = -1;
	unsigned cpp_flags = 0;
	unsigned long pmc_size;
	int possible_pid_reuse = 0;
	bool has_parent;
	bool async_regular = false;
	bool async_started = false;
	bool async_cleaned = false;
	bool dsa_populate_read = false;
	bool dsa_strict = dsa_dump_enabled();
	bool dsa_desc_scan = dsa_strict && dsa_desc_scan_enabled();
	bool dsa_desc_scan_active = false;
	bool dsa_live_mode = false;
	bool allow_dsa = dsa_strict;
	bool dsa_desc_scan_ready = false;
	bool dsa_ctx_deferred = false;
	struct dsa_dump_ctx *dsa_ctx;
	struct dsa_desc_scan_ctx dsa_sc = {
		.dsa_pipe_fd = -1,
	};
	int parent_predump_mode = -1;

	pr_info("\n");
	pr_info("Dumping pages (type: %d pid: %d)\n", CR_FD_PAGES, item->pid->real);
	pr_info("----------------------------------------\n");

	timing_start(TIME_MEMDUMP);

	pr_debug("   Private vmas %lu/%lu pages\n", vma_area_list->nr_priv_pages_longest, vma_area_list->nr_priv_pages);

	/*
	 * Step 0 -- prepare
	 */

	pmc_size = max(vma_area_list->nr_priv_pages_longest, vma_area_list->nr_shared_pages_longest);
	if (pmc_init(&pmc, item->pid->real, &vma_area_list->h, pmc_size * PAGE_SIZE))
		return -1;

	dsa_ctx = xzalloc(sizeof(*dsa_ctx));
	if (!dsa_ctx)
		goto out;

	dsa_ctx->shared_fd = -1;
	dsa_ctx->shared_buf = MAP_FAILED;
	dsa_ctx->pidfd = -1;

	dsa_populate_read = dsa_strict && dsa_populate_read_enabled();
	async_regular = dsa_strict && !mdc->pre_dump && !mdc->lazy &&
			vma_area_list->nr_priv_pages >= mem_dump_async_min_pages();
	dsa_desc_scan_active = dsa_desc_scan && !mdc->pre_dump && !mdc->lazy;
	dsa_live_mode = dsa_desc_scan_active && async_regular;

	if (dsa_desc_scan_active) {
		workload_switch_scope(WORK_SCOPE_MEM_DSA_CTX_INIT);
		ret = dsa_dump_ctx_init(dsa_ctx, item->pid->real);
		if (ret) {
			workload_switch_scope(WORK_SCOPE_MEM_DUMP_MISC);
			goto out;
		}
		workload_switch_scope(WORK_SCOPE_MEM_DUMP_MISC);

		dsa_sc.ctl = ctl;
		dsa_sc.args = args;
		dsa_sc.dsa_ctx = dsa_ctx;
		dsa_sc.do_populate_read = dsa_ctx->do_populate_read;
		dsa_sc.pidfd = dsa_ctx->pidfd;
		dsa_sc.send_shared_fds = !dsa_ctx->shared_fds_sent;
		dsa_sc.args_nr_vmas_saved = args->nr_vmas;
		dsa_sc.args_add_prot_saved = args->add_prot;
		dsa_sc.args_off_cur = 0;
		dsa_sc.args_tail_sz = 0;
		dsa_sc.args_tail_saved = NULL;
		dsa_sc.batch_src_addr = NULL;
		dsa_sc.batch_copy_len = NULL;
		dsa_sc.batch_cap = 0;
		dsa_desc_scan_reset_batch(&dsa_sc);
		dsa_batch_stats_init(&dsa_sc.stats);

		dsa_desc_scan_ready = true;
	}

	/*
	 * Populate+DSA+deferred async memwrite can hit pipe lifetime races.
	 * Keep async enabled, but use legacy drain in this specific combo.
	 */
	if (async_regular && dsa_populate_read) {
		pr_err("DSA strict: populate_read + async is unsupported\n");
		ret = -1;
		goto out;
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
		pp = create_page_pipe(vma_area_list->nr_priv_pages, pp_iovs, cpp_flags);
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

		dsa_sc.args_tail_sz = args->nr_vmas * sizeof(struct parasite_vma_entry) +
				      pp->nr_iovs * sizeof(struct iovec);
		if (dsa_sc.args_tail_sz) {
			dsa_sc.args_tail_saved = xmalloc(dsa_sc.args_tail_sz);
			if (!dsa_sc.args_tail_saved) {
				ret = -1;
				goto out_pp;
			}
			memcpy(dsa_sc.args_tail_saved, pargs_vmas(args),
			       dsa_sc.args_tail_sz);
		}
	}

	if (!mdc->pre_dump) {
		/*
		 * Regular dump -- create xfer object and send pages to it
		 * right here. For pre-dumps the pp will be taken by the
		 * caller and handled later.
		 */
		ret = open_page_xfer(&xfer, CR_FD_PAGEMAP, vpid(item));
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
		possible_pid_reuse = detect_pid_reuse(item, mdc->stat, mdc->parent_ie);
		if (possible_pid_reuse == -1)
			goto out_xfer;
	}

	/*
	 * Step 1 -- generate the pagemap
	 */
	args->off = 0;
	has_parent = !!xfer.parent && !possible_pid_reuse;
	if (mdc->parent_ie)
		parent_predump_mode = mdc->parent_ie->pre_dump_mode;

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
						parent_predump_mode, allow_dsa,
						dsa_ctx);
		if (ret < 0)
			goto out_xfer;
	}

	if (dsa_desc_scan_active)
		pr_info("DSA desc-scan mode enabled for pid %d\n", item->pid->real);

	if (dsa_desc_scan_active && dsa_desc_scan_ready) {
		ret = dsa_desc_scan_flush_last(&dsa_sc);
		if (ret < 0)
			goto out_xfer;
		pr_info("DSA_DESC_SEQ: total=%llu out_of_order=%llu discontinuity=%llu\n",
			(unsigned long long)dsa_sc.desc_seq_total,
			(unsigned long long)dsa_sc.desc_seq_out_of_order,
			(unsigned long long)dsa_sc.desc_seq_discont);
		dsa_batch_stats_log(&dsa_sc.stats, dsa_ctx);
	}

	if (mdc->lazy)
		memcpy(pargs_iovs(args), pp->iovs, sizeof(struct iovec) * pp->nr_iovs);

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
			if (dsa_strict)
				dsa_sanitize_page_pipe(pp);
			if (dsa_strict && dsa_validate_page_pipe(pp)) {
				ret = -1;
				goto out_xfer;
			}
			ret = start_mem_dump_async_xfer(item, pp, &xfer);
			if (!ret) {
				async_started = true;
				if (dsa_live_mode && dmpi(item)->mem_async) {
					dmpi(item)->mem_async->dsa_live_defer = true;
					dmpi(item)->mem_async->dsa_ctx_deferred = dsa_ctx;
					dsa_ctx_deferred = true;
				}
			}
		} else {
			ret = xfer_pages(pp, &xfer);
		}
	} else if (async_regular) {
		/*
		 * Regular dump: drain pages first, then start async writer.
		 * This keeps pipe content stable while preserving post-drain overlap.
		 */
		ret = drain_pages(pp, ctl, args, item->pid->real, allow_dsa,
				  dsa_ctx);
		if (!ret) {
			if (dsa_strict)
				dsa_sanitize_page_pipe(pp);
			if (dsa_strict && dsa_validate_page_pipe(pp)) {
				ret = -1;
				goto out_xfer;
			}
			ret = start_mem_dump_async_xfer(item, pp, &xfer);
			if (!ret)
				async_started = true;
		}
	} else {
		/*
		 * For pre-dump or lazy dump, use legacy sequential drain_pages + xfer_pages.
		 */
		ret = drain_pages(pp, ctl, args, item->pid->real, allow_dsa,
				  dsa_ctx);
		if (!ret)
			ret = xfer_pages(pp, &xfer);
	}
	if (ret)
		goto out_xfer;

	timing_stop(TIME_MEMDUMP);

	/*
	 * Step 4 -- clean up
	 */

	ret = task_reset_dirty_track(item->pid->real);
	if (ret)
		goto out_xfer;
	exit_code = 0;

	/* Success path intentionally keeps async writer running. */
out_xfer:
	if (ret && async_started) {
		int wait_ret;

		wait_ret = parasite_dump_pages_seized_wait(item);
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
	if (dsa_desc_scan_ready) {
		xfree(dsa_sc.batch_src_addr);
		xfree(dsa_sc.batch_copy_len);
		xfree(dsa_sc.args_tail_saved);
	}
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
	int ret;
	struct parasite_dump_pages_args *pargs;

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
			return ret;
		}
	}

	if (fault_injected(FI_DUMP_PAGES)) {
		pr_err("fault: Dump VMA pages failure!\n");
		return -1;
	}

	ret = __parasite_dump_pages_seized(item, pargs, vma_area_list, mdc, ctl);
	if (ret) {
		pr_err("Can't dump page with parasite\n");
		/* Parasite will unprotect VMAs after fail in fini() */
		return ret;
	}

	if (!mdc->pre_dump || opts.pre_dump_mode == PRE_DUMP_SPLICE) {
		pargs->add_prot = 0;
		if (compel_rpc_call_sync(PARASITE_CMD_MPROTECT_VMAS, ctl)) {
			pr_err("Can't rollback unprotected vmas with parasite\n");
			ret = -1;
		}
	}

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
