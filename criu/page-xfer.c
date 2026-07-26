#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/falloc.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <dirent.h>
#include <linux/idxd.h>
#include <linux/perf_event.h>
#include <time.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#if defined(__x86_64__) || defined(__i386__)
#include <immintrin.h>
#define HOT_FG_HAVE_X86_SIMD 1
#endif

#undef LOG_PREFIX
#define LOG_PREFIX "page-xfer: "

#include "types.h"
#include "crtools.h"
#include "cr_options.h"
#include "servicefd.h"
#include "image.h"
#include "page-xfer.h"
#include "page-pipe.h"
#include "util.h"
#include "protobuf.h"
#include "images/pagemap.pb-c.h"
#include "fcntl.h"
#include "pstree.h"
#include "parasite-syscall.h"
#include "parasite.h"
#include "rst_info.h"
#include "stats.h"
#include "tls.h"
#include "vma.h"
#include "kerndat.h"

#define HOT_APPLY_SCRATCH_PAGES 32
#define HOT_DSA_PORTAL_MAP_SIZE 0x1000UL
#define HOT_DSA_MAX_WQ 16
#define HOT_DSA_COMPARE_INFLIGHT 128
#define HOT_DSA_MAX_ENQ_RETRY 1000000U
#define HOT_DSA_MAX_POLL_RETRY 1000000U
#define HOT_DSA_COMPLETION_TIMEOUT_NS (5ULL * 1000ULL * 1000ULL * 1000ULL)
#define CDP_DSA_COMPLETION_TIMEOUT_EXIT 124
#define HOT_FG_HYBRID_CHUNK_BYTES (2UL * 1024UL * 1024UL)
#define HOT_FG_OUTPUT_META_MAX 256U
#define HOT_FG_OUTPUT_LOGICAL_BYTES (2U * 1024U * 1024U)
#define HOT_FG_OUTPUT_WRITE_BYTES (64U * 1024U)

enum hot_fg_compare_backend {
	HOT_FG_COMPARE_DSA = 0,
	HOT_FG_COMPARE_MEMCMP,
	HOT_FG_COMPARE_SCALAR64,
	HOT_FG_COMPARE_SIMD_AVX2,
	HOT_FG_COMPARE_SIMD_AVX512,
	HOT_FG_COMPARE_HYBRID_DEMAND,
	HOT_FG_COMPARE_VALIDATE,
};

static int page_server_sk = -1;

static bool dsa_debug_enabled(void)
{
	static int enabled = -1;
	const char *value = getenv("CRIU_DSA_DEBUG");

	if (enabled >= 0)
		return enabled;

	enabled = value && (!strcmp(value, "1") || !strcasecmp(value, "true") ||
				    !strcasecmp(value, "yes"));
	return enabled;
}

static bool dsa_profile_enabled(void)
{
	static int enabled = -1;
	const char *value = getenv("CRIU_DSA_PROFILE");

	if (enabled >= 0)
		return enabled;

	enabled = value && (!strcmp(value, "1") || !strcasecmp(value, "true") ||
				    !strcasecmp(value, "yes"));
	return enabled;
}

static int dsa_compare_breakdown_mode(void)
{
	static int mode = -2;
	const char *value = getenv("CRIU_DSA_COMPARE_BREAKDOWN");

	if (mode != -2)
		return mode;

	if (!value || !value[0] || !strcmp(value, "0") ||
	    !strcasecmp(value, "false") || !strcasecmp(value, "off"))
		return mode = 0;
	if (!strcmp(value, "1") || !strcasecmp(value, "true") ||
	    !strcasecmp(value, "yes"))
		return mode = 1;
	return mode = -1;
}

struct hot_apply_extent {
	bool valid;
	u32 flags;
	int fd_type;
	unsigned long img_id;
	u32 pages_id;
	unsigned long seq;
	unsigned long vaddr;
	unsigned long len;
	off_t append_offset;
	bool has_append;
	char seg_file[PATH_MAX];
	off_t seg_off;
	bool has_seg;
};

/* Built while frozen; opening/mapping backing files is deferred until thaw. */
struct hot_vma_plan {
	unsigned long start;
	unsigned long end;
};

/* Fine-grained raw capture has already materialized hot state before this
 * plan is built.  Keep pagemap records separately so validation and protobuf
 * packing can be done in ordered passes without changing the on-disk wire
 * format. */
struct hot_pagemap_plan_entry {
	unsigned long vaddr;
	unsigned long len;
	u32 flags;
};

struct hot_prq_profile_source {
	char iommu[32];
	int pg_req_fd;
	int irq_task_fd;
	int irq;
	pid_t irq_tid;
};

struct hot_apply_ctx {
	bool enabled;
	bool memstore;
	bool fine_grained;
	bool profile;
	bool compare_breakdown;
	enum hot_fg_compare_backend fg_compare_backend;
	bool finished;
	int pipefd[2];
	int append_fd;
	int extent_fd;
	int manifest_fd;
	int fg_idx_fd;
	int fg_dat_fd;
	off_t fg_dat_off;
	int fd_type;
	unsigned long img_id;
	u32 pages_id;
	u32 current_pages_id;
	const char *manifest_path;
	const char *memory_manifest_path;
	const char *memory_next_path;
	const char *current_dir;
	const char *hot_root;
	unsigned long next_seq;
	struct hot_apply_extent *entries;
	size_t nr_entries;
	size_t entries_cap;
	struct hot_memstore_seg *old_memstore;
	size_t nr_old_memstore;
	size_t old_memstore_cursor;
	struct hot_vma_segment *vma_segments;
	size_t nr_vma_segments;
	size_t vma_segments_cap;
	size_t vma_segment_cursor;
	struct hot_vma_plan *vma_plans;
	size_t nr_vma_plans;
	size_t vma_plans_cap;
	struct hot_pagemap_plan_entry *pagemap_plan;
	size_t nr_pagemap_plan;
	size_t pagemap_plan_cap;
	/* Semantic accounting for the deferred pagemap stream.  Keep these on
	 * even without profiling: they guard the sidecar-to-pagemap contract. */
	u64 pagemap_plan_input_records;
	u64 pagemap_plan_present_pages;
	u64 pagemap_plan_fg_pages;
	bool vmas_materialized;
	bool post_thaw_ready;
	bool pre_freeze_ready;
	bool parent_view_loaded;
	size_t pending_index;
	uint64_t append_bytes;
	uint64_t memstore_bytes;
	uint64_t memstore_segments;
	uint64_t fg_pages;
	uint64_t fg_patch_pages;
	uint64_t fg_full_pages;
	uint64_t fg_patch_bytes;
	uint64_t fg_compare_ops;
	uint64_t fg_copy_ops;
	uint64_t append_time_us;
	uint64_t append_prepare_us;
	uint64_t append_tee_us;
	uint64_t append_splice_us;
	uint64_t append_enqueue_wait_us;
	uint64_t worker_wait_us;
	uint64_t worker_join_us;
	uint64_t worker_queue_max;
	uint64_t worker_pipe_size;
	uint64_t reorder_time_us;
	uint64_t moved_pages;
	uint64_t moved_ranges;
	uint64_t range_count;
	uint64_t max_range_pages;
	uint64_t patch_pages;
	uint64_t patch_ranges;
	uint64_t scratch_uses;
	uint64_t scratch_bytes;
	uint64_t dsa_copy_pages;
	uint64_t dsa_copy_ranges;
	uint64_t dsa_copy_bytes;
	uint64_t dsa_submit_us;
	uint64_t dsa_poll_us;
	uint64_t dsa_enqcmd;
	uint64_t dsa_submit_batches;
	uint64_t dsa_max_batch_ranges;
	uint64_t ready_scan_us;
	uint64_t ready_rounds;
	uint64_t ready_empty_rounds;
	uint64_t reorder_load_old_us;
	uint64_t reorder_fill_sources_us;
	uint64_t reorder_seek_us;
	uint64_t reorder_dsa_open_us;
	uint64_t reorder_mmap_us;
	uint64_t reorder_move_us;
	uint64_t reorder_unmap_us;
	uint64_t reorder_truncate_us;
	uint64_t reorder_rewrite_pagemap_us;
	uint64_t move_alloc_us;
	uint64_t move_build_ranges_us;
	uint64_t move_live_counts_us;
	uint64_t move_schedule_us;
	void *map;
	size_t map_size;
	off_t file_size;
	int dsa_wq_count;
	int dsa_wq_fds[HOT_DSA_MAX_WQ];
	void *dsa_portals[HOT_DSA_MAX_WQ];
	unsigned long dsa_portal_offset[HOT_DSA_MAX_WQ];
	unsigned int dsa_next_wq;
	u32 dsa_max_transfer_size;
	struct hot_apply_extent pending;
	/* Aggregate-only profile data.  It is populated only when
	 * CRIU_DSA_PROFILE=1; no timer is read from page/range/descriptor loops. */
	bool profile_started;
	bool profile_emitted;
	u64 profile_total_start_us;
	u64 profile_post_prepare_us;
	u64 profile_materialize_us;
	u64 profile_raw_index_us;
	u64 profile_span_build_us;
	u64 profile_compare_wall_us;
	u64 profile_compare_cpu_us;
	u64 profile_sidecar_emit_us;
	u64 profile_compare_engine_wall_us;
	u64 profile_compare_engine_cpu_us;
	u64 profile_parent_prefault_wall_us;
	u64 profile_parent_prefault_cpu_us;
	u64 profile_compare_core_wall_us;
	u64 profile_compare_core_cpu_us;
	u64 profile_output_wall_us;
	u64 profile_output_start_us;
	u64 profile_hot_apply_us;
	u64 profile_pagemap_us;
	u64 profile_finish_us;
	u64 profile_raw_pages;
	u64 profile_raw_bytes;
	u64 profile_capture_runs;
	u64 profile_span_pages;
	u64 profile_spans;
	u64 profile_max_span_pages;
	u64 profile_compare_enq_retries;
	u64 profile_compare_poll_sweeps;
	u64 profile_compare_not_ready;
	u64 profile_compare_max_active;
	u64 profile_completions_harvested;
	u64 profile_completion_timeout_count;
	u64 profile_max_completion_age_us;
	u64 profile_write_units;
	u64 profile_write_unit_max_us;
	u64 profile_memcmp_calls;
	u64 profile_memcmp_requested_bytes;
	u64 profile_memcmp_scalar_bytes;
	u64 profile_scalar64_calls;
	u64 profile_scalar64_word_ops;
	u64 profile_scalar64_refine_bytes;
	u64 profile_scalar64_tail_bytes;
	u64 profile_scalar64_bytes_examined;
	u64 profile_simd_vector_ops;
	u64 profile_simd_bytes_examined;
	u64 profile_hybrid_dsa_claim_spans;
	u64 profile_hybrid_dsa_claim_pages;
	u64 profile_hybrid_cpu_claim_spans;
	u64 profile_hybrid_cpu_claim_pages;
	u64 profile_hybrid_cpu_waves;
	u64 profile_hybrid_dsa_to_cpu_handoff_spans;
	u64 profile_hybrid_dsa_to_cpu_handoff_pages;
	u64 profile_hybrid_dsa_to_cpu_handoff_remaining_bytes;
	u64 profile_hybrid_unclaimed_empty_count;
	struct hot_prq_profile_source profile_prq_sources[HOT_DSA_MAX_WQ];
	u32 profile_nr_prq_sources;
	bool profile_prq_available;
	bool profile_prq_active;
	u64 profile_prq_pg_requests;
	u64 profile_prq_thread_cpu_us;
	int profile_prq_setup_errno;
	u64 profile_prefault_spans;
	u64 profile_prefault_pages;
	u64 profile_parent_pages;
	u64 profile_patch_ranges;
	u64 profile_idx_writes;
	u64 profile_dat_writes;
	u64 profile_dat_writevs;
	u64 profile_hot_pwrite_ops;
	u64 profile_hot_pwrite_bytes;
	u64 profile_hot_mprotect_ops;
	u64 profile_hot_memcpy_bytes;
	u64 profile_pagemap_iovs;
	u64 profile_pagemap_flushes;
	u64 profile_pagemap_bytes;
	u64 profile_pagemap_plan_us;
	u64 profile_parent_validate_us;
	u64 profile_pagemap_pack_us;
};

/* There is exactly one DSA checkpoint in a daemon arena lease.  The context is
 * built before collect_pstree and transferred to its page_xfer after pages_id
 * becomes known; it never contains target-VMA-dependent output state. */
static struct hot_apply_ctx *hot_apply_prepared;

static void hot_apply_abort(struct page_xfer *xfer);

struct hot_old_range {
	unsigned long vaddr;
	unsigned long len;
	off_t off;
};

struct hot_move_range {
	off_t src_page;
	off_t dst_page;
	size_t nr_pages;
	bool pending;
	bool scratch;
	bool patch;
};

struct hot_page_source {
	off_t src_page;
	bool patch;
};

struct hot_vma_segment {
	unsigned long start;
	unsigned long end;
	off_t off;
	int fd;
	void *map;
	size_t map_size;
	bool map_writable;
	bool reuses_parent;
	char file[PATH_MAX];
};

static uint64_t hot_now_us(void)
{
	struct timespec ts;

	if (!dsa_debug_enabled())
		return 0;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000ULL + ts.tv_nsec / 1000ULL;
}

static u64 dsa_profile_wall_now_us(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts))
		return 0;
	return (u64)ts.tv_sec * 1000000ULL + ts.tv_nsec / 1000ULL;
}

static u64 dsa_profile_thread_now_us(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts))
		return 0;
	return (u64)ts.tv_sec * 1000000ULL + ts.tv_nsec / 1000ULL;
}

static u64 dsa_profile_delta_us(u64 begin, u64 end)
{
	return begin && end >= begin ? end - begin : 0;
}

static bool dsa_hot_apply_enabled(void)
{
	const char *enabled = getenv("CRIU_DSA_HOT_APPLY");
	const char *current = getenv("CRIU_DSA_HOT_CURRENT_DIR");
	const char *root = getenv("CRIU_DSA_HOT_ROOT");
	const char *dsa = getenv("CRIU_DSA_DUMP");

	return enabled && strcmp(enabled, "1") == 0 &&
	       ((current && current[0]) || (root && root[0])) &&
	       dsa && strcmp(dsa, "1") == 0;
}

static inline int hot_dsa_enqcmd(void *portal_slot, const void *desc)
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

static inline void hot_dsa_cpu_relax(void)
{
#if defined(__x86_64__)
	asm volatile("pause" ::: "memory");
#else
	asm volatile("" ::: "memory");
#endif
}

static u64 hot_dsa_watchdog_now_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts))
		return 0;
	return (u64)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static void hot_dsa_prefault_range(void *addr, unsigned long bytes, bool write)
{
	volatile char *p = addr;
	unsigned long i;
	volatile char sink = 0;

	if (!addr || !bytes)
		return;

	for (i = 0; i < bytes; i += PAGE_SIZE) {
		sink ^= p[i];
		if (write)
			p[i] = p[i];
	}
	sink ^= p[bytes - 1];
	if (write)
		p[bytes - 1] = p[bytes - 1];

	(void)sink;
}

static int hot_read_small_file(const char *path, char *buf, size_t len)
{
	int fd;
	ssize_t ret;

	if (!len)
		return -1;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;

	ret = read(fd, buf, len - 1);
	close(fd);
	if (ret <= 0)
		return -1;

	buf[ret] = '\0';
	return 0;
}

static void hot_trim_line(char *value)
{
	size_t len;

	if (!value)
		return;
	len = strlen(value);
	while (len && (value[len - 1] == '\n' || value[len - 1] == '\r' ||
		       value[len - 1] == ' ' || value[len - 1] == '\t'))
		value[--len] = '\0';
}

static int hot_perf_event_open(struct perf_event_attr *attr, pid_t pid, int cpu)
{
	return syscall(__NR_perf_event_open, attr, pid, cpu, -1,
		       PERF_FLAG_FD_CLOEXEC);
}

static void hot_prq_profile_init(struct hot_apply_ctx *ctx)
{
	size_t i;

	ctx->profile_nr_prq_sources = 0;
	ctx->profile_prq_available = false;
	ctx->profile_prq_active = false;
	ctx->profile_prq_pg_requests = 0;
	ctx->profile_prq_thread_cpu_us = 0;
	ctx->profile_prq_setup_errno = 0;
	for (i = 0; i < ARRAY_SIZE(ctx->profile_prq_sources); i++) {
		ctx->profile_prq_sources[i].pg_req_fd = -1;
		ctx->profile_prq_sources[i].irq_task_fd = -1;
		ctx->profile_prq_sources[i].irq = -1;
		ctx->profile_prq_sources[i].irq_tid = -1;
	}
}

static void hot_prq_profile_close(struct hot_apply_ctx *ctx)
{
	size_t i;

	if (!ctx)
		return;
	for (i = 0; i < ctx->profile_nr_prq_sources; i++) {
		struct hot_prq_profile_source *source =
			&ctx->profile_prq_sources[i];

		if (source->pg_req_fd >= 0) {
			if (ctx->profile_prq_active)
				ioctl(source->pg_req_fd, PERF_EVENT_IOC_DISABLE, 0);
			close(source->pg_req_fd);
			source->pg_req_fd = -1;
		}
		if (source->irq_task_fd >= 0) {
			if (ctx->profile_prq_active)
				ioctl(source->irq_task_fd, PERF_EVENT_IOC_DISABLE, 0);
			close(source->irq_task_fd);
			source->irq_task_fd = -1;
		}
	}
	ctx->profile_prq_active = false;
	ctx->profile_prq_available = false;
}

static int hot_prq_profile_wq_iommu(const char *path, char *iommu,
				    size_t iommu_len)
{
	const char *name = strrchr(path, '/');
	char sysfs[PATH_MAX];
	char resolved[PATH_MAX];
	char iommu_link[PATH_MAX];
	char iommu_real[PATH_MAX];
	char *slash;
	const char *base;

	if (!name || !name[1] || !iommu || iommu_len < 6)
		return -1;
	name++;
	if (snprintf(sysfs, sizeof(sysfs), "/sys/bus/dsa/devices/%s", name) >=
		    (int)sizeof(sysfs) ||
	    !realpath(sysfs, resolved))
		return -1;

	/* .../<PCI BDF>/dsaN/wqN.M -> .../<PCI BDF> */
	slash = strrchr(resolved, '/');
	if (!slash)
		return -1;
	*slash = '\0';
	slash = strrchr(resolved, '/');
	if (!slash)
		return -1;
	*slash = '\0';
	if (snprintf(iommu_link, sizeof(iommu_link), "%s/iommu", resolved) >=
		    (int)sizeof(iommu_link) ||
	    !realpath(iommu_link, iommu_real))
		return -1;
	base = strrchr(iommu_real, '/');
	base = base ? base + 1 : iommu_real;
	if (strncmp(base, "dmar", 4) || !base[4] ||
	    snprintf(iommu, iommu_len, "%s", base) >= (int)iommu_len)
		return -1;
	return 0;
}

static int hot_prq_profile_find_irq(const char *iommu)
{
	char expected[64];
	char *line = NULL;
	size_t cap = 0;
	FILE *file;
	int irq = -1;

	if (snprintf(expected, sizeof(expected), "%s-prq", iommu) >=
	    (int)sizeof(expected))
		return -1;
	file = fopen("/proc/interrupts", "r");
	if (!file)
		return -1;
	while (getline(&line, &cap, file) >= 0) {
		char *end = line + strlen(line);
		char *token;
		char *colon;
		char *parsed_end;
		long parsed;

		while (end > line && (end[-1] == '\n' || end[-1] == '\r' ||
				      end[-1] == ' ' || end[-1] == '\t'))
			*--end = '\0';
		token = end;
		while (token > line && token[-1] != ' ' && token[-1] != '\t')
			token--;
		if (strcmp(token, expected))
			continue;
		colon = strchr(line, ':');
		if (!colon)
			continue;
		errno = 0;
		parsed = strtol(line, &parsed_end, 10);
		if (errno || parsed_end != colon || parsed < 0 || parsed > INT_MAX)
			continue;
		irq = (int)parsed;
		break;
	}
	free(line);
	fclose(file);
	return irq;
}

static pid_t hot_prq_profile_find_irq_tid(int irq, const char *iommu)
{
	char expected[64];
	char truncated[16];
	DIR *dir;
	struct dirent *de;
	pid_t found = -1;

	if (snprintf(expected, sizeof(expected), "irq/%d-%s-prq", irq, iommu) >=
	    (int)sizeof(expected))
		return -1;
	memcpy(truncated, expected, sizeof(truncated) - 1);
	truncated[sizeof(truncated) - 1] = '\0';
	dir = opendir("/proc");
	if (!dir)
		return -1;
	while ((de = readdir(dir))) {
		char comm_path[PATH_MAX];
		char comm[64];
		char *end;
		long tid;

		if (!de->d_name[0] ||
		    strspn(de->d_name, "0123456789") != strlen(de->d_name))
			continue;
		errno = 0;
		tid = strtol(de->d_name, &end, 10);
		if (errno || *end || tid <= 0 || tid > INT_MAX)
			continue;
		if (snprintf(comm_path, sizeof(comm_path), "/proc/%s/comm",
			     de->d_name) >= (int)sizeof(comm_path) ||
		    hot_read_small_file(comm_path, comm, sizeof(comm)))
			continue;
		hot_trim_line(comm);
		/* Current kernels retain the complete 16-character IRQ name;
		 * older TASK_COMM_LEN layouts may expose only its first 15. */
		if (strcmp(comm, expected) && strcmp(comm, truncated))
			continue;
		found = (pid_t)tid;
		break;
	}
	closedir(dir);
	return found;
}

static int hot_prq_profile_parse_pmu(const char *iommu, u32 *type, int *cpu,
				     u64 *config)
{
	char path[PATH_MAX];
	char value[128];
	char *end;
	char *event_group;
	char *event;
	unsigned long parsed_type;
	unsigned long parsed_cpu;
	unsigned long long parsed_group;
	unsigned long long parsed_event;

	if (snprintf(path, sizeof(path),
		     "/sys/bus/event_source/devices/%s/format/event", iommu) >=
		    (int)sizeof(path) ||
	    hot_read_small_file(path, value, sizeof(value)))
		return -1;
	hot_trim_line(value);
	if (strcmp(value, "config:0-27"))
		return -1;
	if (snprintf(path, sizeof(path),
		     "/sys/bus/event_source/devices/%s/format/event_group",
		     iommu) >= (int)sizeof(path) ||
	    hot_read_small_file(path, value, sizeof(value)))
		return -1;
	hot_trim_line(value);
	if (strcmp(value, "config:28-31"))
		return -1;

	if (snprintf(path, sizeof(path),
		     "/sys/bus/event_source/devices/%s/type", iommu) >=
		    (int)sizeof(path) ||
	    hot_read_small_file(path, value, sizeof(value)))
		return -1;
	errno = 0;
	parsed_type = strtoul(value, &end, 0);
	if (errno || end == value || parsed_type > UINT_MAX)
		return -1;
	if (snprintf(path, sizeof(path),
		     "/sys/bus/event_source/devices/%s/cpumask", iommu) >=
		    (int)sizeof(path) ||
	    hot_read_small_file(path, value, sizeof(value)))
		return -1;
	errno = 0;
	parsed_cpu = strtoul(value, &end, 10);
	if (errno || end == value || parsed_cpu > INT_MAX)
		return -1;

	if (snprintf(path, sizeof(path),
		     "/sys/bus/event_source/devices/%s/events/pg_req_posted",
		     iommu) >= (int)sizeof(path) ||
	    hot_read_small_file(path, value, sizeof(value)))
		return -1;
	event_group = strstr(value, "event_group=");
	event = strstr(value, "event=");
	if (!event_group || !event)
		return -1;
	errno = 0;
	parsed_group = strtoull(event_group + strlen("event_group="), &end, 0);
	if (errno || end == event_group + strlen("event_group=") ||
	    parsed_group > 0xf)
		return -1;
	errno = 0;
	parsed_event = strtoull(event + strlen("event="), &end, 0);
	if (errno || end == event + strlen("event=") ||
	    parsed_event > 0x0fffffffULL)
		return -1;

	*type = (u32)parsed_type;
	*cpu = (int)parsed_cpu;
	*config = (parsed_group << 28) | parsed_event;
	return 0;
}

static int hot_prq_profile_add_source(struct hot_apply_ctx *ctx,
				      const char *iommu)
{
	struct hot_prq_profile_source *source;
	struct perf_event_attr attr = {};
	u32 type;
	u64 config;
	int cpu;
	size_t i;

	for (i = 0; i < ctx->profile_nr_prq_sources; i++) {
		if (!strcmp(ctx->profile_prq_sources[i].iommu, iommu))
			return 0;
	}
	if (ctx->profile_nr_prq_sources >= ARRAY_SIZE(ctx->profile_prq_sources)) {
		errno = E2BIG;
		return -1;
	}
	if (hot_prq_profile_parse_pmu(iommu, &type, &cpu, &config)) {
		errno = ENODEV;
		return -1;
	}

	source = &ctx->profile_prq_sources[ctx->profile_nr_prq_sources];
	if (snprintf(source->iommu, sizeof(source->iommu), "%s", iommu) >=
	    (int)sizeof(source->iommu)) {
		errno = ENAMETOOLONG;
		return -1;
	}
	source->irq = hot_prq_profile_find_irq(iommu);
	if (source->irq < 0) {
		errno = ENODEV;
		return -1;
	}
	source->irq_tid = hot_prq_profile_find_irq_tid(source->irq, iommu);
	if (source->irq_tid < 0) {
		errno = ESRCH;
		return -1;
	}

	attr.type = type;
	attr.size = sizeof(attr);
	attr.config = config;
	attr.disabled = 1;
	source->pg_req_fd = hot_perf_event_open(&attr, -1, cpu);
	if (source->pg_req_fd < 0)
		return -1;

	memset(&attr, 0, sizeof(attr));
	attr.type = PERF_TYPE_SOFTWARE;
	attr.size = sizeof(attr);
	attr.config = PERF_COUNT_SW_TASK_CLOCK;
	attr.disabled = 1;
	source->irq_task_fd = hot_perf_event_open(&attr, source->irq_tid, -1);
	if (source->irq_task_fd < 0) {
		int saved_errno = errno;

		close(source->pg_req_fd);
		source->pg_req_fd = -1;
		errno = saved_errno;
		return -1;
	}
	ctx->profile_nr_prq_sources++;
	return 0;
}

static void hot_prq_profile_setup(struct hot_apply_ctx *ctx,
				  char paths[HOT_DSA_MAX_WQ][64], int nr)
{
	char iommu[32];
	int i;

	if (!ctx->profile || !ctx->fine_grained)
		return;
	for (i = 0; i < nr; i++) {
		if (hot_prq_profile_wq_iommu(paths[i], iommu, sizeof(iommu)) ||
		    hot_prq_profile_add_source(ctx, iommu)) {
			int saved_errno = errno ? errno : ENODEV;

			pr_warn("DSA PRQ profile unavailable stage=setup wq=%s errno=%d\n",
				paths[i], saved_errno);
			ctx->profile_prq_setup_errno = saved_errno;
			hot_prq_profile_close(ctx);
			ctx->profile_nr_prq_sources = 0;
			return;
		}
	}
	if (!ctx->profile_nr_prq_sources) {
		ctx->profile_prq_setup_errno = ENODEV;
		pr_warn("DSA PRQ profile unavailable stage=setup errno=%d\n",
			ctx->profile_prq_setup_errno);
		return;
	}
	ctx->profile_prq_available = true;
}

static int hot_prq_profile_start(struct hot_apply_ctx *ctx)
{
	size_t i;

	if (!ctx->profile_prq_available)
		return 0;
	ctx->profile_prq_pg_requests = 0;
	ctx->profile_prq_thread_cpu_us = 0;
	for (i = 0; i < ctx->profile_nr_prq_sources; i++) {
		struct hot_prq_profile_source *source =
			&ctx->profile_prq_sources[i];

		if (ioctl(source->pg_req_fd, PERF_EVENT_IOC_RESET, 0) ||
		    ioctl(source->irq_task_fd, PERF_EVENT_IOC_RESET, 0) ||
		    ioctl(source->pg_req_fd, PERF_EVENT_IOC_ENABLE, 0) ||
		    ioctl(source->irq_task_fd, PERF_EVENT_IOC_ENABLE, 0))
			goto err;
	}
	ctx->profile_prq_active = true;
	return 0;
err:
	ctx->profile_prq_setup_errno = errno ? errno : EIO;
	pr_warn("DSA PRQ profile unavailable stage=start errno=%d\n",
		ctx->profile_prq_setup_errno);
	for (i = 0; i < ctx->profile_nr_prq_sources; i++) {
		ioctl(ctx->profile_prq_sources[i].pg_req_fd,
		      PERF_EVENT_IOC_DISABLE, 0);
		ioctl(ctx->profile_prq_sources[i].irq_task_fd,
		      PERF_EVENT_IOC_DISABLE, 0);
	}
	ctx->profile_prq_available = false;
	ctx->profile_prq_active = false;
	return -1;
}

static int hot_prq_profile_stop(struct hot_apply_ctx *ctx)
{
	u64 pg_requests = 0;
	u64 task_ns = 0;
	size_t i;

	if (!ctx->profile_prq_available || !ctx->profile_prq_active)
		return 0;
	for (i = 0; i < ctx->profile_nr_prq_sources; i++) {
		struct hot_prq_profile_source *source =
			&ctx->profile_prq_sources[i];

		if (ioctl(source->pg_req_fd, PERF_EVENT_IOC_DISABLE, 0) ||
		    ioctl(source->irq_task_fd, PERF_EVENT_IOC_DISABLE, 0))
			goto err;
	}
	ctx->profile_prq_active = false;
	for (i = 0; i < ctx->profile_nr_prq_sources; i++) {
		struct hot_prq_profile_source *source =
			&ctx->profile_prq_sources[i];
		u64 value;

		if (read(source->pg_req_fd, &value, sizeof(value)) !=
		    (ssize_t)sizeof(value))
			goto err;
		pg_requests += value;
		if (read(source->irq_task_fd, &value, sizeof(value)) !=
		    (ssize_t)sizeof(value))
			goto err;
		task_ns += value;
	}
	ctx->profile_prq_pg_requests = pg_requests;
	ctx->profile_prq_thread_cpu_us = task_ns / 1000ULL;
	return 0;
err:
	ctx->profile_prq_setup_errno = errno ? errno : EIO;
	pr_warn("DSA PRQ profile unavailable stage=stop errno=%d\n",
		ctx->profile_prq_setup_errno);
	for (i = 0; i < ctx->profile_nr_prq_sources; i++) {
		ioctl(ctx->profile_prq_sources[i].pg_req_fd,
		      PERF_EVENT_IOC_DISABLE, 0);
		ioctl(ctx->profile_prq_sources[i].irq_task_fd,
		      PERF_EVENT_IOC_DISABLE, 0);
	}
	ctx->profile_prq_available = false;
	ctx->profile_prq_active = false;
	ctx->profile_prq_pg_requests = 0;
	ctx->profile_prq_thread_cpu_us = 0;
	return -1;
}

static int hot_dsa_collect_workqueues(char paths[HOT_DSA_MAX_WQ][64])
{
	DIR *dir;
	struct dirent *de;
	int nr = 0;
	int i;

	for (i = 0; i < HOT_DSA_MAX_WQ; i++)
		paths[i][0] = '\0';

	dir = opendir("/dev/dsa");
	if (!dir)
		return 0;

	while ((de = readdir(dir)) && nr < HOT_DSA_MAX_WQ) {
		char type_path[160];
		char state_path[160];
		char type_buf[32];
		char state_buf[32];
		int n;

		if (strncmp(de->d_name, "wq", 2))
			continue;

		n = snprintf(type_path, sizeof(type_path),
			     "/sys/bus/dsa/devices/%s/type", de->d_name);
		if (n < 0 || n >= (int)sizeof(type_path))
			continue;
		n = snprintf(state_path, sizeof(state_path),
			     "/sys/bus/dsa/devices/%s/state", de->d_name);
		if (n < 0 || n >= (int)sizeof(state_path))
			continue;

		if (hot_read_small_file(type_path, type_buf, sizeof(type_buf)))
			continue;
		if (strncmp(type_buf, "user", 4))
			continue;
		if (hot_read_small_file(state_path, state_buf, sizeof(state_buf)))
			continue;
		if (strncmp(state_buf, "enabled", 7))
			continue;

		n = snprintf(paths[nr], sizeof(paths[nr]), "/dev/dsa/%s", de->d_name);
		if (n < 0 || n >= (int)sizeof(paths[nr]))
			continue;
		nr++;
	}

	closedir(dir);
	return nr;
}

static int hot_dsa_wq_max_transfer(const char *path, u32 *max_xfer)
{
	const char *name = strrchr(path, '/');
	char sysfs[PATH_MAX];
	char value[64];
	char device[64];
	char *end = NULL;
	unsigned long long parsed;
	const char *suffix;
	size_t suffix_len;

	if (!name || !name[1] || !max_xfer)
		return -1;
	name++;
	if (snprintf(sysfs, sizeof(sysfs),
		     "/sys/bus/dsa/devices/%s/max_transfer_size", name) >=
	    (int)sizeof(sysfs) || hot_read_small_file(sysfs, value, sizeof(value))) {
		/* WQ attributes are inherited from the device on older accel-config
		 * layouts.  This is the same WQ capability, not an alternate path. */
		if (strncmp(name, "wq", 2))
			return -1;
		suffix = name + 2;
		suffix_len = strcspn(suffix, ".");
		if (!suffix_len || suffix_len >= sizeof(device) - 4)
			return -1;
		if (snprintf(device, sizeof(device), "dsa%.*s", (int)suffix_len,
			     suffix) >= (int)sizeof(device) ||
		    snprintf(sysfs, sizeof(sysfs),
			     "/sys/bus/dsa/devices/%s/max_transfer_size", device) >=
		    (int)sizeof(sysfs) || hot_read_small_file(sysfs, value, sizeof(value)))
			return -1;
	}

	errno = 0;
	parsed = strtoull(value, &end, 0);
	if (errno || end == value || parsed < PAGE_SIZE || parsed > UINT_MAX)
		return -1;
	*max_xfer = (u32)parsed;
	return 0;
}

static int hot_dsa_wq_supports_compare(const char *path)
{
	const char *name = strrchr(path, '/');
	const char *suffix;
	size_t suffix_len;
	char device[64];
	char sysfs[PATH_MAX];
	char value[512];
	char *last_word;
	char *end = NULL;
	unsigned long op_cap;

	if (!name || !name[1])
		return -1;
	name++;
	if (strncmp(name, "wq", 2))
		return -1;
	suffix = name + 2;
	suffix_len = strcspn(suffix, ".");
	if (!suffix_len || suffix_len >= sizeof(device) - 4 ||
	    snprintf(device, sizeof(device), "dsa%.*s", (int)suffix_len,
		     suffix) >= (int)sizeof(device) ||
	    snprintf(sysfs, sizeof(sysfs), "/sys/bus/dsa/devices/%s/op_cap",
		     device) >= (int)sizeof(sysfs) ||
	    hot_read_small_file(sysfs, value, sizeof(value)))
		return -1;

	/* accel-config prints op_cap most-significant word first; DSA COMPARE is
	 * opcode 5, hence lives in the final (least-significant) word. */
	last_word = strrchr(value, ',');
	last_word = last_word ? last_word + 1 : value;
	errno = 0;
	op_cap = strtoul(last_word, &end, 16);
	if (errno || end == last_word ||
	    !(op_cap & (1UL << DSA_OPCODE_COMPARE)))
		return -1;
	return 0;
}

static int hot_dsa_wq_supports_demand_paging(const char *path)
{
	const char *name = strrchr(path, '/');
	char sysfs[PATH_MAX];
	char value[32];

	if (!name || !name[1])
		return -1;
	name++;
	if (snprintf(sysfs, sizeof(sysfs),
		     "/sys/bus/dsa/devices/%s/block_on_fault", name) >=
		    (int)sizeof(sysfs) ||
	    hot_read_small_file(sysfs, value, sizeof(value)) || value[0] != '1')
		return -1;
	if (snprintf(sysfs, sizeof(sysfs),
		     "/sys/bus/dsa/devices/%s/ats_disable", name) >=
		    (int)sizeof(sysfs) ||
	    hot_read_small_file(sysfs, value, sizeof(value)) || value[0] != '0')
		return -1;
	return 0;
}

static void hot_dsa_close(struct hot_apply_ctx *ctx)
{
	int i;

	hot_prq_profile_close(ctx);
	for (i = 0; i < ctx->dsa_wq_count; i++) {
		if (ctx->dsa_portals[i] && ctx->dsa_portals[i] != MAP_FAILED)
			munmap(ctx->dsa_portals[i], HOT_DSA_PORTAL_MAP_SIZE);
		ctx->dsa_portals[i] = MAP_FAILED;

		if (ctx->dsa_wq_fds[i] >= 0)
			close(ctx->dsa_wq_fds[i]);
		ctx->dsa_wq_fds[i] = -1;
	}

	ctx->dsa_wq_count = 0;
}

static int hot_dsa_open(struct hot_apply_ctx *ctx)
{
	char paths[HOT_DSA_MAX_WQ][64];
	int nr;
	int i;
	u32 max_xfer = UINT_MAX;

	for (i = 0; i < HOT_DSA_MAX_WQ; i++) {
		ctx->dsa_wq_fds[i] = -1;
		ctx->dsa_portals[i] = MAP_FAILED;
		ctx->dsa_portal_offset[i] = 0;
	}

	nr = hot_dsa_collect_workqueues(paths);
	if (nr <= 0) {
		pr_err("DSA hot apply requires DSA reorder, but no enabled user WQ is available\n");
		return -1;
	}

	for (i = 0; i < nr; i++) {
		u32 wq_max_xfer;

		if (hot_dsa_wq_supports_compare(paths[i])) {
			pr_err("DSA hot apply WQ/device doesn't advertise COMPARE: %s\n",
			       paths[i]);
			goto err;
		}
		if (ctx->fg_compare_backend == HOT_FG_COMPARE_HYBRID_DEMAND &&
		    hot_dsa_wq_supports_demand_paging(paths[i])) {
			pr_err("DSA hybrid-demand requires block_on_fault=1 and ats_disable=0: %s\n",
			       paths[i]);
			goto err;
		}
		if (hot_dsa_wq_max_transfer(paths[i], &wq_max_xfer)) {
			pr_err("DSA hot apply can't determine max transfer size for %s\n",
			       paths[i]);
			goto err;
		}
		if (wq_max_xfer < max_xfer)
			max_xfer = wq_max_xfer;
		ctx->dsa_wq_fds[i] = open(paths[i], O_RDWR | O_CLOEXEC);
		if (ctx->dsa_wq_fds[i] < 0) {
			pr_perror("DSA hot apply can't open workqueue %s", paths[i]);
			goto err;
		}

		ctx->dsa_portals[i] = mmap(NULL, HOT_DSA_PORTAL_MAP_SIZE,
					   PROT_WRITE, MAP_SHARED | MAP_POPULATE,
					   ctx->dsa_wq_fds[i], 0);
		if (ctx->dsa_portals[i] == MAP_FAILED) {
			pr_perror("DSA hot apply can't mmap workqueue portal %s", paths[i]);
			goto err;
		}
	}

	ctx->dsa_wq_count = nr;
	ctx->dsa_next_wq = 0;
	ctx->dsa_max_transfer_size = max_xfer;
	hot_prq_profile_setup(ctx, paths, nr);
	pr_info("DSA hot apply opened %d DSA workqueues max_xfer=%u\n", nr,
		ctx->dsa_max_transfer_size);
	return 0;

err:
	ctx->dsa_wq_count = nr;
	hot_dsa_close(ctx);
	return -1;
}

#if 0
static int hot_apply_remap_current(struct hot_apply_ctx *ctx, off_t need_size)
{
	size_t map_size;
	void *map;

	if (need_size < 0)
		return -1;

	map_size = hot_align_up_size((size_t)need_size, PAGE_SIZE);
	if (!map_size)
		map_size = PAGE_SIZE;

	if (ctx->map && ctx->map != MAP_FAILED && ctx->map_size >= map_size) {
		if (need_size > ctx->file_size)
			ctx->file_size = need_size;
		return 0;
	}

	if (ftruncate(ctx->append_fd, (off_t)map_size)) {
		pr_perror("DSA hot apply can't extend current pages for mmap");
		return -1;
	}

	map = mmap(NULL, map_size, PROT_READ | PROT_WRITE, MAP_SHARED,
		   ctx->append_fd, 0);
	if (map == MAP_FAILED) {
		pr_perror("DSA hot apply can't mmap current pages for DSA reorder");
		return -1;
	}

	if (ctx->map && ctx->map != MAP_FAILED)
		munmap(ctx->map, ctx->map_size);

	ctx->map = map;
	ctx->map_size = map_size;
	ctx->file_size = need_size;
	return 0;
}
#endif

static void hot_apply_unmap_current(struct hot_apply_ctx *ctx)
{
	if (ctx->map && ctx->map != MAP_FAILED)
		munmap(ctx->map, ctx->map_size);
	ctx->map = MAP_FAILED;
	ctx->map_size = 0;
	ctx->file_size = 0;
}

#if 0
static int hot_dsa_copy_bytes(struct hot_apply_ctx *ctx, off_t src, off_t dst,
			      unsigned long bytes)
{
	struct dsa_hw_desc desc __attribute__((aligned(64)));
	volatile struct dsa_completion_record comp __attribute__((aligned(32)));
	uint32_t retry_count;
	uint32_t poll_count;
	unsigned int wq_idx;
	unsigned long off;
	unsigned long portal_mask;
	void *slot;
	uint64_t start_us = 0;
	uint64_t end_us = 0;

	if (!bytes)
		return 0;
	if (src < 0 || dst < 0 || (uint64_t)bytes > UINT_MAX) {
		pr_err("DSA hot apply invalid copy src=%" PRId64 " dst=%" PRId64 " bytes=%lu\n",
		       (int64_t)src, (int64_t)dst, bytes);
		return -1;
	}
	if (!ctx->map || ctx->map == MAP_FAILED ||
	    (size_t)src + bytes > ctx->map_size ||
	    (size_t)dst + bytes > ctx->map_size) {
		pr_err("DSA hot apply copy outside mmap src=%" PRId64 " dst=%" PRId64 " bytes=%lu map=%zu\n",
		       (int64_t)src, (int64_t)dst, bytes, ctx->map_size);
		return -1;
	}
	if (ctx->dsa_wq_count <= 0) {
		pr_err("DSA hot apply has no DSA workqueue for reorder copy\n");
		return -1;
	}

	wq_idx = ctx->dsa_next_wq++ % (unsigned int)ctx->dsa_wq_count;
	portal_mask = ((unsigned long)ctx->dsa_portals[wq_idx]) & ~0xfffUL;

	memset(&desc, 0, sizeof(desc));
	memset((void *)&comp, 0, sizeof(comp));

	hot_dsa_prefault_range((char *)ctx->map + src, bytes, false);
	hot_dsa_prefault_range((char *)ctx->map + dst, bytes, true);

	desc.opcode = DSA_OPCODE_MEMMOVE;
	desc.flags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR | IDXD_OP_FLAG_BOF;
	desc.src_addr = (uint64_t)(unsigned long)((char *)ctx->map + src);
	desc.dst_addr = (uint64_t)(unsigned long)((char *)ctx->map + dst);
	desc.xfer_size = (uint32_t)bytes;
	desc.completion_addr = (uint64_t)(unsigned long)&comp;

	start_us = hot_now_us();
	for (retry_count = 0; retry_count < HOT_DSA_MAX_ENQ_RETRY; retry_count++) {
		off = ((ctx->dsa_portal_offset[wq_idx]++ << 6) & 0xfffUL);
		slot = (void *)(portal_mask | off);
		if (hot_dsa_enqcmd(slot, &desc) == 0) {
			ctx->dsa_enqcmd++;
			break;
		}
		hot_dsa_cpu_relax();
	}
	end_us = hot_now_us();
	if (end_us > start_us)
		ctx->dsa_submit_us += end_us - start_us;

	if (retry_count == HOT_DSA_MAX_ENQ_RETRY) {
		pr_err("DSA hot apply enqcmd timed out\n");
		return -1;
	}

	start_us = hot_now_us();
	for (poll_count = 0; poll_count < HOT_DSA_MAX_POLL_RETRY; poll_count++) {
		uint8_t status = comp.status;
		uint8_t code = (uint8_t)DSA_COMP_STATUS(status);

		if (status != 0 && code != DSA_COMP_NONE) {
			end_us = hot_now_us();
			if (end_us > start_us)
				ctx->dsa_poll_us += end_us - start_us;
			if (code == DSA_COMP_SUCCESS || code == DSA_COMP_SUCCESS_PRED)
				return 0;
			pr_err("DSA hot apply completion failed status=%u code=%u\n",
			       status, code);
			return -1;
		}
		hot_dsa_cpu_relax();
	}

	end_us = hot_now_us();
	if (end_us > start_us)
		ctx->dsa_poll_us += end_us - start_us;
	pr_err("DSA hot apply completion timed out\n");
	return -1;
}
#endif

static int hot_dsa_submit_ptr(struct hot_apply_ctx *ctx, uint8_t opcode,
			      const void *src, const void *src2, void *dst,
			      unsigned int bytes, uint8_t *result,
			      uint32_t *bytes_completed)
{
	struct dsa_hw_desc desc __attribute__((aligned(64)));
	volatile struct dsa_completion_record comp __attribute__((aligned(32)));
	uint32_t retry_count;
	uint32_t poll_count;
	unsigned int wq_idx;
	unsigned long off;
	unsigned long portal_mask;
	void *slot;
	uint64_t start_us;
	uint64_t end_us;

	if (!bytes || ctx->dsa_wq_count <= 0) {
		pr_err("DSA fine-grained op has no DSA workqueue or zero length\n");
		return -1;
	}
	if (opcode != DSA_OPCODE_COMPARE && opcode != DSA_OPCODE_MEMMOVE) {
		pr_err("DSA fine-grained unsupported opcode=%u\n", opcode);
		return -1;
	}

	wq_idx = ctx->dsa_next_wq++ % (unsigned int)ctx->dsa_wq_count;
	portal_mask = ((unsigned long)ctx->dsa_portals[wq_idx]) & ~0xfffUL;

	memset(&desc, 0, sizeof(desc));
	memset((void *)&comp, 0, sizeof(comp));

	desc.opcode = opcode;
	desc.flags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR | IDXD_OP_FLAG_BOF;
	desc.src_addr = (uint64_t)(unsigned long)src;
	desc.xfer_size = bytes;
	desc.completion_addr = (uint64_t)(unsigned long)&comp;
	if (opcode == DSA_OPCODE_COMPARE) {
		desc.src2_addr = (uint64_t)(unsigned long)src2;
		hot_dsa_prefault_range((void *)src, bytes, false);
		hot_dsa_prefault_range((void *)src2, bytes, false);
	} else {
		desc.dst_addr = (uint64_t)(unsigned long)dst;
		hot_dsa_prefault_range((void *)src, bytes, false);
		hot_dsa_prefault_range(dst, bytes, true);
	}

	start_us = hot_now_us();
	for (retry_count = 0; retry_count < HOT_DSA_MAX_ENQ_RETRY; retry_count++) {
		off = ((ctx->dsa_portal_offset[wq_idx]++ << 6) & 0xfffUL);
		slot = (void *)(portal_mask | off);
		if (hot_dsa_enqcmd(slot, &desc) == 0) {
			ctx->dsa_enqcmd++;
			break;
		}
		hot_dsa_cpu_relax();
	}
	end_us = hot_now_us();
	if (end_us > start_us)
		ctx->dsa_submit_us += end_us - start_us;

	if (retry_count == HOT_DSA_MAX_ENQ_RETRY) {
		pr_err("DSA fine-grained enqcmd timed out opcode=%u\n", opcode);
		return -1;
	}

	start_us = hot_now_us();
	for (poll_count = 0; poll_count < HOT_DSA_MAX_POLL_RETRY; poll_count++) {
		uint8_t status = comp.status;
		uint8_t code = (uint8_t)DSA_COMP_STATUS(status);

		if (status != 0 && code != DSA_COMP_NONE) {
			end_us = hot_now_us();
			if (end_us > start_us)
				ctx->dsa_poll_us += end_us - start_us;
			if (code == DSA_COMP_SUCCESS || code == DSA_COMP_SUCCESS_PRED) {
				if (result)
					*result = comp.result;
				if (bytes_completed)
					*bytes_completed = comp.bytes_completed;
				return 0;
			}
			pr_err("DSA fine-grained completion failed opcode=%u status=%u code=%u\n",
			       opcode, status, code);
			return -1;
		}
		hot_dsa_cpu_relax();
	}

	end_us = hot_now_us();
	if (end_us > start_us)
		ctx->dsa_poll_us += end_us - start_us;
	pr_err("DSA fine-grained completion timed out opcode=%u\n", opcode);
	return -1;
}

static int hot_dsa_compare_first_diff(struct hot_apply_ctx *ctx,
				      const void *a, const void *b,
				      unsigned int bytes,
				      bool *equal,
				      unsigned int *first_diff)
{
	uint8_t result = 0;
	uint32_t completed = 0;

	if (hot_dsa_submit_ptr(ctx, DSA_OPCODE_COMPARE, a, b, NULL, bytes,
			       &result, &completed))
		return -1;
	if (ctx->profile)
		ctx->fg_compare_ops++;
	if (result == 0) {
		*equal = true;
		*first_diff = bytes;
		return 0;
	}
	if (completed >= bytes) {
		pr_err("DSA fine-grained compare returned invalid first_diff=%u bytes=%u\n",
		       completed, bytes);
		return -1;
	}
	*equal = false;
	*first_diff = completed;
	return 0;
}

#if 0
static int hot_dsa_alloc_aligned(void **ptr, size_t align, size_t size)
{
	int ret;

	*ptr = NULL;
	ret = posix_memalign(ptr, align, size);
	if (ret) {
		errno = ret;
		pr_perror("DSA hot apply can't allocate aligned buffer");
		return -1;
	}
	memset(*ptr, 0, size);
	return 0;
}

static int hot_dsa_submit_range_batch(struct hot_apply_ctx *ctx,
				      struct hot_move_range *ranges,
				      size_t *batch, size_t batch_count)
{
	struct dsa_hw_desc *descs = NULL;
	volatile struct dsa_completion_record *comps = NULL;
	size_t *submitted = NULL;
	size_t submitted_count = 0;
	uint64_t start_us = 0;
	uint64_t end_us = 0;
	size_t i;
	int ret = -1;

	if (!batch_count)
		return 0;
	if (ctx->dsa_wq_count <= 0) {
		pr_err("DSA hot apply has no DSA workqueue for batch copy\n");
		return -1;
	}

	if (hot_dsa_alloc_aligned((void **)&descs, 64,
				  batch_count * sizeof(descs[0])))
		goto out;
	if (hot_dsa_alloc_aligned((void **)&comps, 32,
				  batch_count * sizeof(comps[0])))
		goto out;
	submitted = xmalloc(batch_count * sizeof(submitted[0]));
	if (!submitted)
		goto out;

	for (i = 0; i < batch_count; i++) {
		struct hot_move_range *r = &ranges[batch[i]];
		unsigned long bytes;
		off_t src;
		off_t dst;

		if (r->src_page == r->dst_page)
			continue;
		if (r->nr_pages > UINT_MAX / PAGE_SIZE) {
			pr_err("DSA hot apply range too large for DSA xfer: pages=%zu\n",
			       r->nr_pages);
			goto submit_done;
		}

		bytes = (unsigned long)r->nr_pages * PAGE_SIZE;
		src = r->src_page * PAGE_SIZE;
		dst = r->dst_page * PAGE_SIZE;

		if (src < 0 || dst < 0 ||
		    (size_t)src + bytes > ctx->map_size ||
		    (size_t)dst + bytes > ctx->map_size) {
			pr_err("DSA hot apply batch copy outside mmap src=%" PRId64 " dst=%" PRId64 " bytes=%lu map=%zu\n",
			       (int64_t)src, (int64_t)dst, bytes, ctx->map_size);
			goto submit_done;
		}

		hot_dsa_prefault_range((char *)ctx->map + src, bytes, false);
		hot_dsa_prefault_range((char *)ctx->map + dst, bytes, true);

		descs[i].opcode = DSA_OPCODE_MEMMOVE;
		descs[i].flags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR | IDXD_OP_FLAG_BOF;
		descs[i].src_addr = (uint64_t)(unsigned long)((char *)ctx->map + src);
		descs[i].dst_addr = (uint64_t)(unsigned long)((char *)ctx->map + dst);
		descs[i].xfer_size = (uint32_t)bytes;
		descs[i].completion_addr = (uint64_t)(unsigned long)&comps[i];
	}

	start_us = hot_now_us();
	for (i = 0; i < batch_count; i++) {
		struct hot_move_range *r = &ranges[batch[i]];
		uint32_t retry_count;
		unsigned int wq_idx;
		unsigned long portal_mask;

		if (r->src_page == r->dst_page)
			continue;

		wq_idx = ctx->dsa_next_wq++ % (unsigned int)ctx->dsa_wq_count;
		portal_mask = ((unsigned long)ctx->dsa_portals[wq_idx]) & ~0xfffUL;

		for (retry_count = 0; retry_count < HOT_DSA_MAX_ENQ_RETRY; retry_count++) {
			unsigned long off = ((ctx->dsa_portal_offset[wq_idx]++ << 6) & 0xfffUL);
			void *slot = (void *)(portal_mask | off);

			if (hot_dsa_enqcmd(slot, &descs[i]) == 0) {
				ctx->dsa_enqcmd++;
				submitted[submitted_count++] = i;
				break;
			}
			hot_dsa_cpu_relax();
		}

		if (retry_count == HOT_DSA_MAX_ENQ_RETRY) {
			pr_err("DSA hot apply batch enqcmd timed out idx=%zu\n", i);
			goto submit_done;
		}
	}
	ret = 0;

submit_done:
	end_us = hot_now_us();
	if (end_us > start_us)
		ctx->dsa_submit_us += end_us - start_us;

	start_us = hot_now_us();
	for (i = 0; i < submitted_count; i++) {
		size_t desc_idx = submitted[i];
		uint32_t poll_count;
		int done = 0;

		for (poll_count = 0; poll_count < HOT_DSA_MAX_POLL_RETRY; poll_count++) {
			uint8_t status = comps[desc_idx].status;
			uint8_t code = (uint8_t)DSA_COMP_STATUS(status);

			if (status != 0 && code != DSA_COMP_NONE) {
				if (code == DSA_COMP_SUCCESS || code == DSA_COMP_SUCCESS_PRED) {
					done = 1;
					break;
				}
				pr_err("DSA hot apply batch completion failed idx=%zu status=%u code=%u\n",
				       desc_idx, status, code);
				ret = -1;
				done = 1;
				break;
			}
			hot_dsa_cpu_relax();
		}

		if (!done) {
			pr_err("DSA hot apply batch completion timed out idx=%zu\n",
			       desc_idx);
			ret = -1;
		}
	}
	end_us = hot_now_us();
	if (end_us > start_us)
		ctx->dsa_poll_us += end_us - start_us;

	if (ret)
		goto out;

	ctx->dsa_submit_batches++;
	if (batch_count > ctx->dsa_max_batch_ranges)
		ctx->dsa_max_batch_ranges = batch_count;

out:
	xfree(submitted);
	free((void *)comps);
	free(descs);
	return ret;
}
#endif

static int write_full_fd(int fd, const void *buf, size_t len)
{
	const char *p = buf;

	while (len) {
		ssize_t ret = write(fd, p, len);

		if (ret < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (ret == 0) {
			errno = EIO;
			return -1;
		}
		p += ret;
		len -= ret;
	}

	return 0;
}

static int read_full_fd(int fd, void *buf, size_t len)
{
	char *p = buf;

	while (len) {
		ssize_t ret = read(fd, p, len);

		if (ret < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (ret == 0) {
			errno = EIO;
			return -1;
		}
		p += ret;
		len -= ret;
	}

	return 0;
}

struct hot_memstore_seg {
	unsigned long img_id;
	unsigned long vaddr;
	unsigned long len;
	off_t off;
	int fd;
	void *map;
	size_t map_size;
	bool map_writable;
	char file[PATH_MAX];
};

#define DSA_FG_PATCH_SIZE	128U
#define DSA_FG_MAX_PATCHES	8U
#define DSA_FG_MAX_BYTES	1024U
#define HOT_FG_WRITEV_MAX	1024U

static bool hot_mode_is_memstore(void)
{
	const char *mode = getenv("CRIU_DSA_HOT_MODE");

	return mode && strcmp(mode, "memstore") == 0;
}

static bool dsa_fine_grained_enabled(void)
{
	const char *enabled = getenv("CRIU_DSA_FINE_GRAINED");

	if (!enabled || !enabled[0])
		enabled = getenv("CRIU_DSA_WRITE_SIDE_FINE_GRAINED");

	return enabled && (!strcmp(enabled, "1") || !strcasecmp(enabled, "true") ||
			   !strcasecmp(enabled, "yes") || !strcasecmp(enabled, "on"));
}

static const char *hot_fg_compare_backend_name(enum hot_fg_compare_backend backend)
{
	switch (backend) {
	case HOT_FG_COMPARE_DSA:
		return "dsa";
	case HOT_FG_COMPARE_MEMCMP:
		return "memcmp";
	case HOT_FG_COMPARE_SCALAR64:
		return "scalar64";
	case HOT_FG_COMPARE_SIMD_AVX2:
		return "simd-avx2";
	case HOT_FG_COMPARE_SIMD_AVX512:
		return "simd-avx512";
	case HOT_FG_COMPARE_HYBRID_DEMAND:
		return "hybrid-demand";
	case HOT_FG_COMPARE_VALIDATE:
		return "validate";
	default:
		return "invalid";
	}
}

static bool hot_fg_cpu_supports_avx2(void)
{
#ifdef HOT_FG_HAVE_X86_SIMD
	__builtin_cpu_init();
	return __builtin_cpu_supports("avx2");
#else
	return false;
#endif
}

static bool hot_fg_cpu_supports_avx512(void)
{
#ifdef HOT_FG_HAVE_X86_SIMD
	__builtin_cpu_init();
	return __builtin_cpu_supports("avx512f") &&
		__builtin_cpu_supports("avx512bw") &&
		__builtin_cpu_supports("avx512vl");
#else
	return false;
#endif
}

static int hot_fg_select_compare_backend(struct hot_apply_ctx *ctx)
{
	const char *value = getenv("CRIU_DSA_FG_COMPARE_BACKEND");
	enum hot_fg_compare_backend backend = HOT_FG_COMPARE_DSA;

	if (value && value[0]) {
		if (!strcasecmp(value, "dsa"))
			backend = HOT_FG_COMPARE_DSA;
		else if (!strcasecmp(value, "memcmp"))
			backend = HOT_FG_COMPARE_MEMCMP;
		else if (!strcasecmp(value, "scalar64"))
			backend = HOT_FG_COMPARE_SCALAR64;
		else if (!strcasecmp(value, "simd-avx2"))
			backend = HOT_FG_COMPARE_SIMD_AVX2;
		else if (!strcasecmp(value, "simd-avx512"))
			backend = HOT_FG_COMPARE_SIMD_AVX512;
		else if (!strcasecmp(value, "hybrid-demand"))
			backend = HOT_FG_COMPARE_HYBRID_DEMAND;
		else if (!strcasecmp(value, "validate"))
			backend = HOT_FG_COMPARE_VALIDATE;
		else {
			pr_err("DSA fine-grained compare backend is invalid: %s\n", value);
			return -1;
		}
	}

	if (backend == HOT_FG_COMPARE_SIMD_AVX2 && !hot_fg_cpu_supports_avx2()) {
		pr_err("DSA fine-grained simd-avx2 backend requires AVX2\n");
		return -1;
	}
	if ((backend == HOT_FG_COMPARE_SIMD_AVX512 ||
	     backend == HOT_FG_COMPARE_HYBRID_DEMAND ||
	     backend == HOT_FG_COMPARE_VALIDATE) && !hot_fg_cpu_supports_avx512()) {
		pr_err("DSA fine-grained %s backend requires AVX-512F/BW/VL\n",
		       hot_fg_compare_backend_name(backend));
		return -1;
	}

	ctx->fg_compare_backend = backend;
	return 0;
}

static int hot_fg_open_sidecar(struct hot_apply_ctx *ctx)
{
	char path[64];
	int dfd = get_service_fd(IMG_FD_OFF);

	snprintf(path, sizeof(path), "pages-fg-%u.idx", ctx->pages_id);
	ctx->fg_idx_fd = openat(dfd, path, O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC,
				CR_FD_PERM);
	if (ctx->fg_idx_fd < 0) {
		pr_perror("DSA fine-grained can't open %s", path);
		return -1;
	}

	snprintf(path, sizeof(path), "pages-fg-%u.dat", ctx->pages_id);
	ctx->fg_dat_fd = openat(dfd, path, O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC,
				CR_FD_PERM);
	if (ctx->fg_dat_fd < 0) {
		pr_perror("DSA fine-grained can't open %s", path);
		close(ctx->fg_idx_fd);
		ctx->fg_idx_fd = -1;
		return -1;
	}
	ctx->fg_dat_off = 0;

	return 0;
}

static int hot_memstore_seg_cmp(const void *a, const void *b)
{
	const struct hot_memstore_seg *left = a;
	const struct hot_memstore_seg *right = b;

	if (left->img_id != right->img_id)
		return left->img_id < right->img_id ? -1 : 1;
	if (left->vaddr != right->vaddr)
		return left->vaddr < right->vaddr ? -1 : 1;
	return 0;
}

static size_t hot_memstore_lower_bound(struct hot_memstore_seg *segs, size_t nr,
				       unsigned long img_id, unsigned long vaddr)
{
	size_t lo = 0;
	size_t hi = nr;

	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2;
		struct hot_memstore_seg *seg = &segs[mid];

		if (seg->img_id < img_id ||
		    (seg->img_id == img_id && seg->vaddr <= vaddr))
			lo = mid + 1;
		else
			hi = mid;
	}

	return lo;
}

static int hot_memstore_load(const char *path, struct hot_memstore_seg **segs_out,
			     size_t *nr_out)
{
	FILE *fp;
	struct hot_memstore_seg *segs = NULL;
	size_t nr = 0, cap = 0;
	char line[PATH_MAX + 128];

	*segs_out = NULL;
	*nr_out = 0;
	if (!path || !path[0])
		return 0;

	fp = fopen(path, "r");
	if (!fp) {
		if (errno == ENOENT)
			return 0;
		pr_perror("DSA hot memstore can't open old manifest %s", path);
		return -1;
	}

	while (fgets(line, sizeof(line), fp)) {
		struct hot_memstore_seg seg;
		unsigned long long off;
		int n;

		memset(&seg, 0, sizeof(seg));
		seg.fd = -1;
		seg.map = MAP_FAILED;
		n = sscanf(line, "seg %lu %lx %lu %4095s %llu",
			   &seg.img_id, &seg.vaddr, &seg.len, seg.file, &off);
		if (n != 5)
			continue;
		seg.off = (off_t)off;

		if (nr == cap) {
			size_t new_cap = cap ? cap * 2 : 256;
			void *new_segs = xrealloc(segs, new_cap * sizeof(segs[0]));

			if (!new_segs) {
				fclose(fp);
				xfree(segs);
				return -1;
			}
			segs = new_segs;
			cap = new_cap;
		}
		segs[nr++] = seg;
	}

	fclose(fp);
	if (nr)
		qsort(segs, nr, sizeof(segs[0]), hot_memstore_seg_cmp);
	*segs_out = segs;
	*nr_out = nr;
	return 0;
}

static int hot_memstore_emit_line_fd(int fd, unsigned long img_id,
				     unsigned long vaddr, unsigned long len,
				     const char *file, off_t off)
{
	char line[PATH_MAX + 128];
	int n;

	n = snprintf(line, sizeof(line), "seg %lu %lx %lu %s %llu\n",
		     img_id, vaddr, len, file, (unsigned long long)off);
	if (n < 0 || n >= (int)sizeof(line)) {
		pr_err("DSA hot memstore manifest line overflow\n");
		return -1;
	}
	if (write_full_fd(fd, line, n)) {
		pr_perror("DSA hot memstore manifest append failed");
		return -1;
	}
	return 0;
}

static int hot_apply_mkdir_root(const char *root)
{
	if (mkdir(root, 0755) && errno != EEXIST) {
		pr_perror("DSA hot apply can't create %s", root);
		return -1;
	}

	return 0;
}

static int hot_memstore_mkdir_image(struct hot_apply_ctx *ctx, char *dir,
				    size_t dir_len)
{
	char memstore[PATH_MAX];

	if (snprintf(memstore, sizeof(memstore), "%s/memstore", ctx->hot_root) >=
	    (int)sizeof(memstore)) {
		pr_err("DSA hot memstore path too long\n");
		return -1;
	}
	if (hot_apply_mkdir_root(memstore))
		return -1;
	if (snprintf(dir, dir_len, "%s/image-%lu", memstore, ctx->img_id) >=
	    (int)dir_len) {
		pr_err("DSA hot memstore image path too long\n");
		return -1;
	}
	return hot_apply_mkdir_root(dir);
}

static int hot_memstore_open_vma_segment(struct hot_apply_ctx *ctx,
					 unsigned long start,
					 unsigned long end,
					 const char *reuse_file,
					 off_t reuse_off,
					 struct hot_vma_segment *seg)
{
	char dir[PATH_MAX];
	char path[PATH_MAX];
	unsigned long len = end - start;
	int fd;

	memset(seg, 0, sizeof(*seg));
	seg->fd = -1;
	seg->map = MAP_FAILED;
	seg->start = start;
	seg->end = end;
	seg->off = reuse_off;
	seg->reuses_parent = reuse_file && reuse_file[0];

	if (reuse_file && reuse_file[0]) {
		fd = open(reuse_file, O_RDWR | O_CLOEXEC);
		if (fd < 0) {
			pr_perror("DSA hot memstore can't reopen VMA segment %s", reuse_file);
			return -1;
		}
		if (snprintf(seg->file, sizeof(seg->file), "%s", reuse_file) >=
		    (int)sizeof(seg->file)) {
			pr_err("DSA hot memstore reused VMA path too long\n");
			close(fd);
			return -1;
		}
		seg->fd = fd;
		return 0;
	}

	if (hot_memstore_mkdir_image(ctx, dir, sizeof(dir)))
		return -1;
	if (snprintf(path, sizeof(path), "%s/vma-%lx-%lx.mem", dir, start, end) >=
	    (int)sizeof(path)) {
		pr_err("DSA hot memstore VMA segment path too long\n");
		return -1;
	}

	fd = open(path, O_CREAT | O_RDWR | O_CLOEXEC, 0644);
	if (fd < 0) {
		pr_perror("DSA hot memstore can't open VMA segment %s", path);
		return -1;
	}
	if (ftruncate(fd, len)) {
		pr_perror("DSA hot memstore can't size VMA segment %s", path);
		close(fd);
		return -1;
	}

	if (snprintf(seg->file, sizeof(seg->file), "%s", path) >=
	    (int)sizeof(seg->file)) {
		pr_err("DSA hot memstore VMA path too long\n");
		close(fd);
		return -1;
	}
	seg->fd = fd;
	seg->off = 0;
	return 0;
}

static int hot_memstore_prefill_vma_from_old(struct hot_apply_ctx *ctx,
					     struct hot_vma_segment *seg);

static int hot_memstore_register_segment(struct hot_apply_ctx *ctx,
					 unsigned long start,
					 unsigned long end,
					 const char *reuse_file,
					 off_t reuse_off,
					 bool prefill_old)
{
	struct hot_vma_segment seg;
	void *new_segments;

	if (hot_memstore_open_vma_segment(ctx, start, end, reuse_file,
					  reuse_off, &seg))
		return -1;
	if (prefill_old && hot_memstore_prefill_vma_from_old(ctx, &seg)) {
		close(seg.fd);
		return -1;
	}

	if (ctx->nr_vma_segments == ctx->vma_segments_cap) {
		size_t new_cap = ctx->vma_segments_cap ? ctx->vma_segments_cap * 2 : 128;

		new_segments = xrealloc(ctx->vma_segments,
					new_cap * sizeof(ctx->vma_segments[0]));
		if (!new_segments) {
			close(seg.fd);
			return -1;
		}
		ctx->vma_segments = new_segments;
		ctx->vma_segments_cap = new_cap;
	}
	ctx->vma_segments[ctx->nr_vma_segments++] = seg;
	return 0;
}

static int hot_memstore_plan_segment(struct hot_apply_ctx *ctx,
				    unsigned long start, unsigned long end)
{
	struct hot_vma_plan *plans;
	size_t cap;

	if (start >= end || start & (PAGE_SIZE - 1) || end & (PAGE_SIZE - 1)) {
		pr_err("DSA hot memstore has invalid VMA plan %lx-%lx\n", start, end);
		return -1;
	}
	if (ctx->nr_vma_plans == ctx->vma_plans_cap) {
		cap = ctx->vma_plans_cap ? ctx->vma_plans_cap * 2 : 128;
		plans = xrealloc(ctx->vma_plans, cap * sizeof(*plans));
		if (!plans)
			return -1;
		ctx->vma_plans = plans;
		ctx->vma_plans_cap = cap;
	}
	ctx->vma_plans[ctx->nr_vma_plans++] = (struct hot_vma_plan) {
		.start = start,
		.end = end,
	};
	return 0;
}

static struct hot_memstore_seg *hot_memstore_find_old_cover(struct hot_apply_ctx *ctx,
						    unsigned long start,
						    unsigned long end)
{
	size_t i = ctx->old_memstore_cursor;

	if (i >= ctx->nr_old_memstore ||
	    (i < ctx->nr_old_memstore &&
	     (ctx->old_memstore[i].img_id != ctx->img_id ||
	      start < ctx->old_memstore[i].vaddr))) {
		i = hot_memstore_lower_bound(ctx->old_memstore,
					    ctx->nr_old_memstore, ctx->img_id, start);
		if (i)
			i--;
	}

	for (; i < ctx->nr_old_memstore; i++) {
		struct hot_memstore_seg *old = &ctx->old_memstore[i];
		unsigned long old_end;

		if (old->img_id < ctx->img_id)
			continue;
		if (old->img_id > ctx->img_id)
			break;
		old_end = old->vaddr + old->len;
		if (old_end <= start)
			continue;
		if (old->vaddr <= start && old_end >= end) {
			ctx->old_memstore_cursor = i;
			return old;
		}
		if (old->vaddr > start)
			break;
	}
	ctx->old_memstore_cursor = i;
	return NULL;
}

static int hot_memstore_materialize_vmas(struct hot_apply_ctx *ctx)
{
	size_t i;

	if (ctx->vmas_materialized)
		return 0;
	if (!ctx->nr_vma_plans) {
		pr_err("DSA hot memstore has no VMA plan for img_id=%lu\n", ctx->img_id);
		return -1;
	}
	if (!ctx->parent_view_loaded) {
		if (hot_memstore_load(ctx->memory_manifest_path, &ctx->old_memstore,
				       &ctx->nr_old_memstore))
			return -1;
		ctx->parent_view_loaded = true;
	}

	for (i = 0; i < ctx->nr_vma_plans; i++) {
		struct hot_vma_plan *plan = &ctx->vma_plans[i];
		struct hot_memstore_seg *old;
		const char *reuse_file = NULL;
		off_t reuse_off = 0;

		old = hot_memstore_find_old_cover(ctx, plan->start, plan->end);
		if (old) {
			reuse_file = old->file;
			reuse_off = old->off + (plan->start - old->vaddr);
		}
		if (hot_memstore_register_segment(ctx, plan->start, plan->end,
					  reuse_file, reuse_off, !old))
			return -1;
	}
	ctx->vmas_materialized = true;
	pr_info("DSA hot memstore VMA index materialized img_id=%lu segments=%zu old_segments=%zu\n",
		ctx->img_id, ctx->nr_vma_segments, ctx->nr_old_memstore);
	return 0;
}

static int hot_memstore_old_fd(struct hot_memstore_seg *old)
{
	if (old->fd >= 0)
		return old->fd;

	old->fd = open(old->file, O_RDWR | O_CLOEXEC);
	if (old->fd < 0)
		pr_perror("DSA hot memstore can't open old segment %s", old->file);
	return old->fd;
}

static void *hot_memstore_old_map(struct hot_memstore_seg *old)
{
	if (old->map && old->map != MAP_FAILED)
		return old->map;

	if (hot_memstore_old_fd(old) < 0)
		return MAP_FAILED;

	old->map = mmap(NULL, old->len, PROT_READ, MAP_SHARED, old->fd, old->off);
	if (old->map == MAP_FAILED)
		pr_perror("DSA hot memstore can't mmap old segment %s", old->file);
	else
		old->map_size = old->len;
	return old->map;
}

static struct hot_apply_ctx *hot_apply_alloc_ctx(int fd_type,
						  unsigned long img_id, u32 pages_id)
{
	const char *root = getenv("CRIU_DSA_HOT_CURRENT_DIR");
	const char *hot_root = getenv("CRIU_DSA_HOT_ROOT");
	const char *manifest = getenv("CRIU_DSA_HOT_MANIFEST");
	const char *memory_manifest = getenv("CRIU_DSA_HOT_MEMORY_MANIFEST");
	const char *memory_next = getenv("CRIU_DSA_HOT_MEMORY_NEXT");
	struct hot_apply_ctx *ctx;
	int compare_breakdown = dsa_compare_breakdown_mode();

	if (compare_breakdown < 0) {
		pr_err("Invalid CRIU_DSA_COMPARE_BREAKDOWN (use unset/0/off or 1/true)\n");
		return NULL;
	}

	ctx = xzalloc(sizeof(*ctx));
	if (!ctx)
		return NULL;

	hot_prq_profile_init(ctx);
	ctx->enabled = true;
	ctx->pipefd[0] = -1;
	ctx->pipefd[1] = -1;
	ctx->append_fd = -1;
	ctx->extent_fd = -1;
	ctx->manifest_fd = -1;
	ctx->fg_idx_fd = -1;
	ctx->fg_dat_fd = -1;
	ctx->fd_type = fd_type;
	ctx->img_id = img_id;
	ctx->pages_id = pages_id;
	ctx->current_dir = root;
	ctx->hot_root = hot_root && hot_root[0] ? hot_root : root;
	ctx->manifest_path = manifest;
	ctx->memory_manifest_path = memory_manifest;
	ctx->memory_next_path = memory_next;
	ctx->memstore = hot_mode_is_memstore();
	ctx->fine_grained = ctx->memstore && dsa_fine_grained_enabled();
	ctx->profile = dsa_profile_enabled();
	ctx->compare_breakdown = compare_breakdown == 1;
	if (ctx->compare_breakdown && (!ctx->fine_grained || !ctx->profile)) {
		pr_err("DSA compare breakdown requires fine-grained mode and CRIU_DSA_PROFILE=1\n");
		xfree(ctx);
		return NULL;
	}
	if (ctx->fine_grained && hot_fg_select_compare_backend(ctx)) {
		xfree(ctx);
		return NULL;
	}
	if (ctx->compare_breakdown &&
	    ctx->fg_compare_backend == HOT_FG_COMPARE_HYBRID_DEMAND) {
		pr_err("DSA hybrid-demand backend cannot use the global-prefault compare breakdown mode\n");
		xfree(ctx);
		return NULL;
	}
	ctx->pending_index = (size_t)-1;
	return ctx;
}

void page_xfer_hot_cleanup_before_freeze(void)
{
	struct page_xfer xfer = {};

	if (!hot_apply_prepared)
		return;
	xfer.hot_apply = hot_apply_prepared;
	hot_apply_prepared = NULL;
	hot_apply_abort(&xfer);
}

int page_xfer_hot_prepare_before_freeze(unsigned long img_id)
{
	struct hot_apply_ctx *ctx;
	size_t i;
	u64 total_start_us = 0;
	u64 manifest_us = 0;
	u64 map_us = 0;
	u64 wq_us = 0;
	u64 parent_bytes = 0;
	u64 phase_start_us = 0;

	if (!dsa_hot_apply_enabled() || !hot_mode_is_memstore() ||
	    !dsa_fine_grained_enabled())
		return 0;
	if (hot_apply_prepared) {
		pr_err("DSA fine-grained pre-freeze context already exists\n");
		return -1;
	}

	ctx = hot_apply_alloc_ctx(CR_FD_PAGEMAP, img_id, 0);
	if (!ctx)
		return -1;
	if (ctx->profile)
		total_start_us = dsa_profile_wall_now_us();
	if (ctx->fd_type != CR_FD_PAGEMAP || !ctx->hot_root || !ctx->hot_root[0]) {
		pr_err("DSA fine-grained pre-freeze context has no hot root\n");
		goto err;
	}

	/* The manifest describes the stable parent, not the target VMA.  Open and
	 * map it now, but deliberately do not touch all mapped parent pages. */
	if (ctx->profile)
		phase_start_us = dsa_profile_wall_now_us();
	if (hot_memstore_load(ctx->memory_manifest_path, &ctx->old_memstore,
			       &ctx->nr_old_memstore))
		goto err;
	if (ctx->profile)
		manifest_us = dsa_profile_delta_us(phase_start_us, dsa_profile_wall_now_us());
	ctx->parent_view_loaded = true;
	if (ctx->profile)
		phase_start_us = dsa_profile_wall_now_us();
	for (i = 0; i < ctx->nr_old_memstore; i++) {
		if (hot_memstore_old_map(&ctx->old_memstore[i]) == MAP_FAILED)
			goto err;
		parent_bytes += ctx->old_memstore[i].len;
	}
	if (ctx->profile)
		map_us = dsa_profile_delta_us(phase_start_us, dsa_profile_wall_now_us());

	/* WQ FDs/portals are immutable per round and must not be opened while the
	 * target is stopped.  The raw capture path has already validated MEMMOVE;
	 * this context owns the COMPARE portals used after thaw. */
	if (ctx->profile)
		phase_start_us = dsa_profile_wall_now_us();
	if (hot_dsa_open(ctx))
		goto err;
	if (ctx->profile)
		wq_us = dsa_profile_delta_us(phase_start_us, dsa_profile_wall_now_us());

	ctx->pre_freeze_ready = true;
	hot_apply_prepared = ctx;
	pr_info("DSA fine-grained pre-freeze parent view ready img_id=%lu segments=%zu wqs=%d backend=%s\n",
		img_id, ctx->nr_old_memstore, ctx->dsa_wq_count,
		hot_fg_compare_backend_name(ctx->fg_compare_backend));
	if (ctx->profile)
		pr_info("DSA_PRE_FREEZE_PROFILE: version=2 img_id=%lu backend=%s ret=0 total_us=%" PRIu64 " manifest_us=%" PRIu64 " parent_map_us=%" PRIu64 " wq_open_us=%" PRIu64 " parent_segments=%zu parent_bytes=%" PRIu64 " wqs=%d\n",
			img_id, hot_fg_compare_backend_name(ctx->fg_compare_backend),
			dsa_profile_delta_us(total_start_us, dsa_profile_wall_now_us()),
			manifest_us, map_us, wq_us, ctx->nr_old_memstore, parent_bytes,
			ctx->dsa_wq_count);
	return 0;

	err:
	if (ctx->profile)
		pr_info("DSA_PRE_FREEZE_PROFILE: version=2 img_id=%lu backend=%s ret=-1 total_us=%" PRIu64 " manifest_us=%" PRIu64 " parent_map_us=%" PRIu64 " wq_open_us=%" PRIu64 " parent_segments=%zu parent_bytes=%" PRIu64 " wqs=%d\n",
			img_id, hot_fg_compare_backend_name(ctx->fg_compare_backend),
			dsa_profile_delta_us(total_start_us, dsa_profile_wall_now_us()),
			manifest_us, map_us, wq_us, ctx->nr_old_memstore, parent_bytes,
			ctx->dsa_wq_count);
	{
		struct page_xfer xfer = {};

		xfer.hot_apply = ctx;
		hot_apply_abort(&xfer);
	}
	return -1;
}

static int copy_fd_range_loop(int src_fd, off_t src_off, int dst_fd,
			      off_t dst_off, unsigned long len)
{
	char buf[PAGE_SIZE * 16];
	unsigned long done = 0;

	while (done < len) {
		size_t chunk = len - done;
		size_t curr = 0;

		if (chunk > sizeof(buf))
			chunk = sizeof(buf);
		while (curr < chunk) {
			size_t want = chunk - curr;
			ssize_t ret;

			if (want > sizeof(buf) - curr)
				want = sizeof(buf) - curr;
			ret = pread(src_fd, buf + curr, want,
					    src_off + done + curr);

			if (ret < 1) {
				pr_perror("DSA hot memstore old segment read failed");
				return -1;
			}
			curr += ret;
		}

		curr = 0;
		while (curr < chunk) {
			size_t want = chunk - curr;
			ssize_t ret;

			if (want > sizeof(buf) - curr)
				want = sizeof(buf) - curr;
			ret = pwrite(dst_fd, buf + curr, want,
					     dst_off + done + curr);

			if (ret < 1) {
				pr_perror("DSA hot memstore VMA prefill write failed");
				return -1;
			}
			curr += ret;
		}
		done += chunk;
	}

	return 0;
}

static int hot_memstore_prefill_vma_from_old(struct hot_apply_ctx *ctx,
					     struct hot_vma_segment *seg)
{
	size_t i;

	for (i = 0; i < ctx->nr_old_memstore; i++) {
		struct hot_memstore_seg *old = &ctx->old_memstore[i];
		unsigned long old_end;
		unsigned long begin, end, len;
		int old_fd;
		int ret;

		if (old->img_id != ctx->img_id)
			continue;
		old_end = old->vaddr + old->len;
		if (old_end <= seg->start || old->vaddr >= seg->end)
			continue;

		begin = old->vaddr > seg->start ? old->vaddr : seg->start;
		end = old_end < seg->end ? old_end : seg->end;
		len = end - begin;
		if (!len)
			continue;

		old_fd = open(old->file, O_RDONLY | O_CLOEXEC);
		if (old_fd < 0) {
			pr_perror("DSA hot memstore can't open old segment %s", old->file);
			return -1;
		}
		ret = copy_fd_range_loop(old_fd, old->off + (begin - old->vaddr),
					 seg->fd, seg->off + (begin - seg->start),
					 len);
		close(old_fd);
		if (ret)
			return -1;
	}

	return 0;
}

static struct hot_vma_segment *hot_memstore_find_vma_segment(struct hot_apply_ctx *ctx,
							     unsigned long vaddr,
							     unsigned long len)
{
	size_t i = ctx->vma_segment_cursor;
	unsigned long end = vaddr + len;

	if (i >= ctx->nr_vma_segments ||
	    (i < ctx->nr_vma_segments && vaddr < ctx->vma_segments[i].start)) {
		size_t lo = 0;
		size_t hi = ctx->nr_vma_segments;

		while (lo < hi) {
			size_t mid = lo + (hi - lo) / 2;

			if (ctx->vma_segments[mid].start <= vaddr)
				lo = mid + 1;
			else
				hi = mid;
		}
		i = lo ? lo - 1 : 0;
	}

	for (; i < ctx->nr_vma_segments; i++) {
		struct hot_vma_segment *seg = &ctx->vma_segments[i];

		if (vaddr >= seg->start && end <= seg->end) {
			ctx->vma_segment_cursor = i;
			return seg;
		}
		if (seg->start > vaddr)
			break;
	}
	ctx->vma_segment_cursor = i;
	return NULL;
}

static int hot_memstore_old_make_writable(struct hot_apply_ctx *ctx,
					  struct hot_memstore_seg *old)
{
	if (!old->map || old->map == MAP_FAILED || !old->map_size)
		return -1;
	if (old->map_writable)
		return 0;
	if (mprotect(old->map, old->map_size, PROT_READ | PROT_WRITE)) {
		pr_perror("DSA hot memstore can't make parent segment writable %s", old->file);
		return -1;
	}
	old->map_writable = true;
	if (ctx->profile)
		ctx->profile_hot_mprotect_ops++;
	return 0;
}

static int hot_memstore_map_segment_writable(struct hot_apply_ctx *ctx,
					     struct hot_vma_segment *seg)
{
	if (!seg->map || seg->map == MAP_FAILED) {
		seg->map_size = seg->end - seg->start;
		seg->map = mmap(NULL, seg->map_size, PROT_READ, MAP_SHARED, seg->fd,
				seg->off);
		if (seg->map == MAP_FAILED) {
			pr_perror("DSA hot memstore can't mmap current segment %s", seg->file);
			return -1;
		}
	}
	if (seg->map_writable)
		return 0;
	if (mprotect(seg->map, seg->map_size, PROT_READ | PROT_WRITE)) {
		pr_perror("DSA hot memstore can't make current segment writable %s", seg->file);
		return -1;
	}
	seg->map_writable = true;
	if (ctx->profile)
		ctx->profile_hot_mprotect_ops++;
	return 0;
}

static int hot_memstore_write_to_old(struct hot_apply_ctx *ctx,
				     struct hot_memstore_seg *old, const void *buf,
				     unsigned long vaddr, unsigned long len)
{
	if (vaddr < old->vaddr || len > old->len ||
	    vaddr - old->vaddr > old->len - len)
		return -1;
	if (hot_memstore_old_make_writable(ctx, old))
		return -1;
	memcpy((char *)old->map + vaddr - old->vaddr, buf, len);
	if (ctx->profile)
		ctx->profile_hot_memcpy_bytes += len;
	return 0;
}

static bool hot_memstore_segment_reuses_old(const struct hot_vma_segment *seg,
					      const struct hot_memstore_seg *old,
					      unsigned long vaddr)
{
	if (!seg || !old || !seg->reuses_parent || strcmp(seg->file, old->file))
		return false;
	return seg->off + (off_t)(vaddr - seg->start) ==
		old->off + (off_t)(vaddr - old->vaddr);
}

static int hot_memstore_write_to_segments(struct hot_apply_ctx *ctx,
					  const void *buf,
					  unsigned long vaddr,
					  unsigned long len)
{
	unsigned long done = 0;

	while (done < len) {
		unsigned long cur = vaddr + done;
		unsigned long chunk;
		struct hot_vma_segment *seg;

		seg = hot_memstore_find_vma_segment(ctx, cur, 1);
		if (!seg) {
			pr_err("DSA hot memstore can't find VMA segment for write img_id=%lu vaddr=%lx len=%lu\n",
			       ctx->img_id, cur, len - done);
			return -1;
		}

		chunk = seg->end - cur;
		if (chunk > len - done)
			chunk = len - done;
		if (hot_memstore_map_segment_writable(ctx, seg))
			return -1;
		memcpy((char *)seg->map + cur - seg->start,
		       (const char *)buf + done, chunk);
		if (ctx->profile) {
			ctx->profile_hot_memcpy_bytes += chunk;
		}
		done += chunk;
	}

	return 0;
}

static int page_xfer_dsa_fg_write_sidecar(struct page_xfer *xfer,
					  const void *shared_ptr,
					  u32 desc_area_off, u32 desc_head)
{
	char idx_path[64];
	char dat_path[64];
	const unsigned char *shared = shared_ptr;
	u32 off;
	int idx_fd = -1;
	int dat_fd = -1;
	int dfd = get_service_fd(IMG_FD_OFF);
	int ret = -1;

	if (!xfer || !xfer->dsa_fine_grained)
		return 0;
	if (!shared) {
		pr_err("DSA fine-grained sidecar has no shared result arena\n");
		return -1;
	}

	snprintf(idx_path, sizeof(idx_path), "pages-fg-%u.idx", xfer->pages_id);
	idx_fd = openat(dfd, idx_path, O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC,
			0600);
	if (idx_fd < 0) {
		pr_perror("DSA fine-grained can't open %s", idx_path);
		return -1;
	}

	snprintf(dat_path, sizeof(dat_path), "pages-fg-%u.dat", xfer->pages_id);
	dat_fd = openat(dfd, dat_path, O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC,
			0600);
	if (dat_fd < 0) {
		pr_perror("DSA fine-grained can't open %s", dat_path);
		goto out;
	}

	for (off = desc_area_off; off < desc_head;
	     off += sizeof(struct dsa_fg_descriptor)) {
		const struct dsa_fg_descriptor *desc =
			(const struct dsa_fg_descriptor *)(shared + off);
		u32 i;

		if (!desc->record_stride ||
		    desc->record_stride < sizeof(struct parasite_dsa_fg_result)) {
			pr_err("DSA fine-grained sidecar descriptor invalid stride=%u\n",
			       desc->record_stride);
			goto out;
		}

		for (i = 0; i < desc->page_count; i++) {
			const struct parasite_dsa_fg_result *res;
			struct dsa_fg_page_meta meta = {};
			off_t data_off;

			res = (const struct parasite_dsa_fg_result *)(shared +
				desc->record_off + (uint64_t)i * desc->record_stride);
			data_off = lseek(dat_fd, 0, SEEK_CUR);
			if (data_off == (off_t)-1) {
				pr_perror("DSA fine-grained data seek failed");
				goto out;
			}

			meta.vaddr = res->vaddr;
			meta.data_off = data_off;
			meta.patch_count = res->patch_count;
			meta.flags = res->flags;

			if (res->flags == DSA_FG_PAGE_FULL) {
				if (res->data_len != PAGE_SIZE || res->patch_count) {
					pr_err("DSA fine-grained invalid full record len=%u patches=%u vaddr=%" PRIx64 "\n",
					       res->data_len, res->patch_count,
					       res->vaddr);
					goto out;
				}
				meta.data_len = PAGE_SIZE;
				if (write_full_fd(dat_fd, shared + res->data_off,
						  PAGE_SIZE)) {
					pr_perror("DSA fine-grained full data write failed");
					goto out;
				}
			} else if (res->flags == DSA_FG_PAGE_PATCH) {
				struct dsa_fg_patch_entry entries[DSA_FG_MAX_PATCHES];
				u16 j;
				u32 sum = 0;

				if (res->patch_count > DSA_FG_MAX_PATCHES ||
				    res->data_len > DSA_FG_MAX_BYTES) {
					pr_err("DSA fine-grained invalid patch record len=%u patches=%u vaddr=%" PRIx64 "\n",
					       res->data_len, res->patch_count,
					       res->vaddr);
					goto out;
				}
				for (j = 0; j < res->patch_count; j++) {
					const struct parasite_dsa_fg_result_entry *in =
						&res->entries[j];

					if (!in->len ||
					    (unsigned int)in->off + in->len > PAGE_SIZE) {
						pr_err("DSA fine-grained invalid patch entry vaddr=%" PRIx64 " off=%u len=%u\n",
						       res->vaddr, in->off, in->len);
						goto out;
					}
					entries[j].off = in->off;
					entries[j].len = in->len;
					sum += in->len;
				}
				if (sum != res->data_len) {
					pr_err("DSA fine-grained patch data length mismatch vaddr=%" PRIx64 " sum=%u len=%u\n",
					       res->vaddr, sum, res->data_len);
					goto out;
				}
				meta.data_len = res->patch_count * sizeof(entries[0]) +
					res->data_len;
				if (res->patch_count &&
				    write_full_fd(dat_fd, entries,
						  res->patch_count * sizeof(entries[0]))) {
					pr_perror("DSA fine-grained patch entry write failed");
					goto out;
				}
				for (j = 0; j < res->patch_count; j++) {
					const struct parasite_dsa_fg_result_entry *in =
						&res->entries[j];

					if (write_full_fd(dat_fd, shared + in->data_off,
							  in->len)) {
						pr_perror("DSA fine-grained patch data write failed");
						goto out;
					}
				}
			} else if (res->flags == DSA_FG_PAGE_PARENT) {
				if (res->data_len || res->patch_count) {
					pr_err("DSA fine-grained invalid parent record len=%u patches=%u vaddr=%" PRIx64 "\n",
					       res->data_len, res->patch_count, res->vaddr);
					goto out;
				}
				meta.data_len = 0;
			} else {
				pr_err("DSA fine-grained invalid record flags=%u vaddr=%" PRIx64 "\n",
				       res->flags, res->vaddr);
				goto out;
			}

			if (write_full_fd(idx_fd, &meta, sizeof(meta))) {
				pr_perror("DSA fine-grained index write failed");
				goto out;
			}
		}
	}

	ret = 0;
out:
	if (dat_fd >= 0 && close(dat_fd))
		ret = -1;
	if (idx_fd >= 0 && close(idx_fd))
		ret = -1;
	return ret;
}

int page_xfer_dsa_fg_apply_records(struct page_xfer *xfer,
				   const void *shared_ptr,
				   u32 desc_area_off, u32 desc_head)
{
	struct hot_apply_ctx *ctx;
	const unsigned char *shared = shared_ptr;
	u32 off;
	uint64_t start_us;
	uint64_t delta_us;

	if (!xfer || !xfer->hot_apply)
		return 0;
	ctx = xfer->hot_apply;
	if (!ctx->memstore)
		return 0;
	if (!shared) {
		pr_err("DSA fine-grained hot apply has no shared buffer\n");
		return -1;
	}

	start_us = hot_now_us();
	for (off = desc_area_off; off < desc_head;
	     off += sizeof(struct dsa_fg_descriptor)) {
		const struct dsa_fg_descriptor *desc =
			(const struct dsa_fg_descriptor *)(shared + off);
		u32 i;

		if (!desc->record_stride ||
		    desc->record_stride < sizeof(struct parasite_dsa_fg_result)) {
			pr_err("DSA fine-grained hot descriptor invalid stride=%u\n",
			       desc->record_stride);
			return -1;
		}

		for (i = 0; i < desc->page_count; i++) {
			const struct parasite_dsa_fg_result *res;
			u16 j;

			res = (const struct parasite_dsa_fg_result *)(shared +
				desc->record_off + (uint64_t)i * desc->record_stride);

			if (res->flags == DSA_FG_PAGE_FULL) {
				if (res->data_len != PAGE_SIZE || res->patch_count) {
					pr_err("DSA fine-grained hot full record invalid vaddr=%" PRIx64 " len=%u patches=%u\n",
					       res->vaddr, res->data_len,
					       res->patch_count);
					return -1;
				}
				if (hot_memstore_write_to_segments(ctx,
						shared + res->data_off,
						res->vaddr, PAGE_SIZE))
					return -1;
				if (ctx->profile) {
					ctx->fg_full_pages++;
					ctx->fg_patch_bytes += PAGE_SIZE;
					ctx->memstore_bytes += PAGE_SIZE;
				}
			} else if (res->flags == DSA_FG_PAGE_PATCH) {
				u32 sum = 0;

				if (res->patch_count > DSA_FG_MAX_PATCHES ||
				    res->data_len > DSA_FG_MAX_BYTES) {
					pr_err("DSA fine-grained hot patch record invalid vaddr=%" PRIx64 " len=%u patches=%u\n",
					       res->vaddr, res->data_len,
					       res->patch_count);
					return -1;
				}
				for (j = 0; j < res->patch_count; j++) {
					const struct parasite_dsa_fg_result_entry *ent =
						&res->entries[j];

					if (!ent->len ||
					    (unsigned int)ent->off + ent->len > PAGE_SIZE) {
						pr_err("DSA fine-grained hot patch entry invalid vaddr=%" PRIx64 " off=%u len=%u\n",
						       res->vaddr, ent->off, ent->len);
						return -1;
					}
					if (hot_memstore_write_to_segments(ctx,
							shared + ent->data_off,
							res->vaddr + ent->off,
							ent->len))
						return -1;
					sum += ent->len;
				}
				if (sum != res->data_len) {
					pr_err("DSA fine-grained hot patch length mismatch vaddr=%" PRIx64 " sum=%u len=%u\n",
					       res->vaddr, sum, res->data_len);
					return -1;
				}
				if (ctx->profile) {
					ctx->fg_patch_pages++;
					ctx->fg_patch_bytes += res->data_len;
					ctx->memstore_bytes += res->data_len;
				}
			} else if (res->flags == DSA_FG_PAGE_PARENT) {
				if (res->data_len || res->patch_count) {
					pr_err("DSA fine-grained hot parent record invalid vaddr=%" PRIx64 " len=%u patches=%u\n",
					       res->vaddr, res->data_len, res->patch_count);
					return -1;
				}
			} else {
				pr_err("DSA fine-grained hot record has unknown flags=%u vaddr=%" PRIx64 "\n",
				       res->flags, res->vaddr);
				return -1;
			}
			if (ctx->profile)
				ctx->fg_pages++;
		}
	}
	delta_us = hot_now_us() - start_us;
	ctx->append_splice_us += delta_us;
	ctx->append_time_us += delta_us;
	return 0;
}

static int splice_exact_at(int in, int out, off_t off, unsigned long len);

static bool hot_memstore_should_track_vma(struct vma_area *vma)
{
	VmaEntry *e = vma->e;

	if (vma_area_is(vma, VMA_AREA_GUARD))
		return false;
	if (vma_entry_is(e, VMA_AREA_VSYSCALL))
		return false;
	if (e->flags & MAP_HUGETLB)
		return false;
	if (e->start >= kdat.task_size || e->end > kdat.task_size)
		return false;
	return true;
}

static int hot_memstore_splice_to_segments(struct hot_apply_ctx *ctx, int pipefd,
					   unsigned long vaddr,
					   unsigned long len)
{
	unsigned long done = 0;

	while (done < len) {
		unsigned long cur = vaddr + done;
		unsigned long chunk;
		struct hot_vma_segment *seg;

		seg = hot_memstore_find_vma_segment(ctx, cur, 1);
		if (!seg) {
			pr_err("DSA hot memstore can't find VMA segment img_id=%lu vaddr=%lx len=%lu range=%lx-%lx\n",
			       ctx->img_id, cur, len - done, vaddr, vaddr + len);
			return -1;
		}

		chunk = seg->end - cur;
		if (chunk > len - done)
			chunk = len - done;
		if (splice_exact_at(pipefd, seg->fd,
				    seg->off + (cur - seg->start), chunk))
			return -1;
		done += chunk;
	}

	return 0;
}

static int splice_exact_at(int in, int out, off_t off, unsigned long len)
{
	unsigned long curr = 0;

	while (curr < len) {
		loff_t pos = off + curr;
		ssize_t ret = splice(in, NULL, out, &pos, len - curr, SPLICE_F_MOVE);

		if (ret == -1) {
			pr_perror("Unable to splice pages data at offset");
			return -1;
		}
		if (ret == 0) {
			pr_err("A pipe was closed unexpectedly\n");
			return -1;
		}
		curr += ret;
	}

	return 0;
}

/*
 * The original hot-checkpoint backend maintained a CRIU-style full pages.img
 * and reordered it after every incremental dump.  The active backend is now
 * VMA-segment memstore, so keep the old implementation out of the build.
 */
#if 0
static int hot_apply_open_file(const char *root, char *path, size_t path_len,
			       const char *name, int flags, mode_t mode)
{
	int fd;

	if (snprintf(path, path_len, "%s/%s", root, name) >= (int)path_len) {
		pr_err("DSA hot apply path is too long: %s/%s\n", root, name);
		return -1;
	}

	fd = open(path, flags | O_CLOEXEC, mode);
	if (fd < 0)
		pr_perror("DSA hot apply can't open %s", path);

	return fd;
}

static int hot_apply_read_current_pages_id(struct hot_apply_ctx *ctx, const char *root)
{
	struct cr_img *pmi = NULL;
	struct cr_img *pi = NULL;
	int dfd;
	u32 pages_id = 0;

	dfd = open(root, O_DIRECTORY | O_RDONLY | O_CLOEXEC);
	if (dfd < 0) {
		pr_perror("DSA hot apply can't open current dir %s", root);
		return -1;
	}

	pmi = open_image_at(dfd, ctx->fd_type, O_RSTR, ctx->img_id);
	if (!pmi || empty_image(pmi)) {
		pr_err("DSA hot apply can't open current pagemap fd_type=%d img_id=%lu\n",
		       ctx->fd_type, ctx->img_id);
		goto err;
	}

	pi = open_pages_image_at(dfd, O_RDWR, pmi, &pages_id);
	if (!pi) {
		pr_err("DSA hot apply can't open current pages for fd_type=%d img_id=%lu\n",
		       ctx->fd_type, ctx->img_id);
		goto err;
	}

	ctx->current_pages_id = pages_id;
	close_image(pi);
	close_image(pmi);
	close(dfd);
	return 0;

err:
	if (pi)
		close_image(pi);
	if (pmi)
		close_image(pmi);
	close(dfd);
	return -1;
}
#endif

static int hot_apply_add_entry(struct hot_apply_ctx *ctx, struct iovec *iov, u32 flags,
			       size_t *idx)
{
	struct hot_apply_extent *e;

	if (ctx->nr_entries == ctx->entries_cap) {
		size_t new_cap = ctx->entries_cap ? ctx->entries_cap * 2 : 128;
		void *new_entries = xrealloc(ctx->entries, new_cap * sizeof(ctx->entries[0]));

		if (!new_entries)
			return -1;
		ctx->entries = new_entries;
		ctx->entries_cap = new_cap;
	}

	e = &ctx->entries[ctx->nr_entries];
	memset(e, 0, sizeof(*e));
	e->valid = true;
	e->flags = flags;
	e->fd_type = ctx->fd_type;
	e->img_id = ctx->img_id;
	e->pages_id = ctx->memstore ? ctx->pages_id : ctx->current_pages_id;
	e->vaddr = (unsigned long)iov->iov_base;
	e->len = iov->iov_len;
	if (idx)
		*idx = ctx->nr_entries;
	ctx->nr_entries++;
	return 0;
}

static int hot_apply_write_manifest(const char *path, const char *state)
{
	char tmp[PATH_MAX];
	char body[256];
	int fd;
	int n;

	if (!path || !path[0])
		return 0;
	if (snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int)sizeof(tmp)) {
		pr_err("DSA hot apply manifest path is too long: %s\n", path);
		return -1;
	}

	fd = open(tmp, O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC, 0644);
	if (fd < 0) {
		pr_perror("DSA hot apply can't open manifest %s", tmp);
		return -1;
	}

	n = snprintf(body, sizeof(body), "{\n  \"state\": \"%s\"\n}\n", state);
	if (n < 0 || n >= (int)sizeof(body)) {
		close(fd);
		unlink(tmp);
		pr_err("DSA hot apply manifest body overflow\n");
		return -1;
	}
	if (write_full_fd(fd, body, n)) {
		pr_perror("DSA hot apply manifest write failed");
		close(fd);
		unlink(tmp);
		return -1;
	}
	if (close(fd)) {
		pr_perror("DSA hot apply manifest close failed");
		unlink(tmp);
		return -1;
	}
	if (rename(tmp, path)) {
		pr_perror("DSA hot apply manifest rename failed");
		unlink(tmp);
		return -1;
	}

	return 0;
}

#if 0
static void hot_apply_free_old_ranges(struct hot_old_range *ranges)
{
	xfree(ranges);
}

static int hot_apply_load_old_ranges(struct hot_apply_ctx *ctx, struct hot_old_range **ranges_out,
				     size_t *nr_out, off_t *old_size_out)
{
	struct page_read pr;
	struct hot_old_range *ranges = NULL;
	size_t nr = 0, cap = 0;
	off_t off = 0;
	int pr_flags = (ctx->fd_type == CR_FD_PAGEMAP) ? PR_TASK : PR_SHMEM;
	int dfd, ret, i;

	*ranges_out = NULL;
	*nr_out = 0;
	*old_size_out = 0;

	dfd = open(ctx->current_dir, O_DIRECTORY | O_RDONLY | O_CLOEXEC);
	if (dfd < 0) {
		pr_perror("DSA hot apply can't open current dir %s", ctx->current_dir);
		return -1;
	}

	ret = open_page_read_at(dfd, ctx->img_id, &pr, pr_flags);
	close(dfd);
	if (ret <= 0) {
		pr_err("DSA hot apply can't read old current pagemap img_id=%lu ret=%d\n",
		       ctx->img_id, ret);
		return -1;
	}

	for (i = 0; i < pr.nr_pmes; i++) {
		PagemapEntry *pe = pr.pmes[i];
		unsigned long len = pagemap_len(pe);

		if (!pagemap_present(pe)) {
			pr_err("DSA hot apply old current is not a full image: vaddr=%" PRIx64 " flags=%" PRIx32 "\n",
			       pe->vaddr, pe->flags);
			pr.close(&pr);
			hot_apply_free_old_ranges(ranges);
			return -1;
		}

		if (nr == cap) {
			size_t new_cap = cap ? cap * 2 : 128;
			void *new_ranges = xrealloc(ranges, new_cap * sizeof(ranges[0]));

			if (!new_ranges) {
				pr.close(&pr);
				hot_apply_free_old_ranges(ranges);
				return -1;
			}
			ranges = new_ranges;
			cap = new_cap;
		}
		ranges[nr].vaddr = pe->vaddr;
		ranges[nr].len = len;
		ranges[nr].off = off;
		nr++;
		off += len;
	}

	pr.close(&pr);
	*ranges_out = ranges;
	*nr_out = nr;
	*old_size_out = off;
	return 0;
}

static int hot_apply_find_old_range(struct hot_old_range *ranges, size_t nr,
				    unsigned long vaddr, size_t *idx)
{
	size_t i = *idx;

	if (i >= nr)
		i = 0;

	while (i < nr) {
		unsigned long start = ranges[i].vaddr;
		unsigned long end = start + ranges[i].len;

		if (vaddr >= start && vaddr < end) {
			*idx = i;
			return 0;
		}
		if (end <= vaddr) {
			i++;
			continue;
		}
		break;
	}

	pr_err("DSA hot apply can't find old page for vaddr=%lx\n", vaddr);
	return -1;
}

static int hot_apply_fill_sources(struct hot_apply_ctx *ctx,
				  struct hot_old_range *old_ranges, size_t nr_old,
				  off_t old_size, struct hot_page_source **sources_out,
				  size_t *final_pages_out, off_t *final_size_out)
{
	struct hot_page_source *sources = NULL;
	size_t final_pages = 0;
	size_t old_idx = 0;
	size_t i;

	*sources_out = NULL;
	*final_pages_out = 0;
	*final_size_out = 0;

	for (i = 0; i < ctx->nr_entries; i++) {
		if (ctx->entries[i].len % PAGE_SIZE) {
			pr_err("DSA hot apply entry is not page aligned len=%lu\n",
			       ctx->entries[i].len);
			return -1;
		}
		final_pages += ctx->entries[i].len / PAGE_SIZE;
	}

	if (!final_pages)
		return 0;

	sources = xmalloc(final_pages * sizeof(sources[0]));
	if (!sources)
		return -1;

	final_pages = 0;
	for (i = 0; i < ctx->nr_entries; i++) {
		struct hot_apply_extent *e = &ctx->entries[i];
		unsigned long pos = e->vaddr;
		unsigned long left = e->len;

		if (e->flags & PE_PRESENT) {
			unsigned long pages = e->len / PAGE_SIZE;
			unsigned long p;

			if (!e->has_append || e->append_offset % PAGE_SIZE) {
				pr_err("DSA hot apply present entry lacks aligned append offset\n");
				goto err;
			}
			for (p = 0; p < pages; p++) {
				sources[final_pages].src_page = e->append_offset / PAGE_SIZE + p;
				sources[final_pages].patch = true;
				final_pages++;
			}
			continue;
		}

		if (!(e->flags & PE_PARENT)) {
			pr_err("DSA hot apply unsupported pagemap flags=%" PRIx32 "\n", e->flags);
			goto err;
		}

		while (left) {
			struct hot_old_range *r;
			unsigned long in_range;
			unsigned long pages, p;
			off_t src_off;

			if (hot_apply_find_old_range(old_ranges, nr_old, pos, &old_idx))
				goto err;
			r = &old_ranges[old_idx];
			in_range = r->vaddr + r->len - pos;
			if (in_range > left)
				in_range = left;
			if (in_range % PAGE_SIZE) {
				pr_err("DSA hot apply old split is not page aligned\n");
				goto err;
			}

			src_off = r->off + (pos - r->vaddr);
			if (src_off >= old_size || src_off % PAGE_SIZE) {
				pr_err("DSA hot apply invalid old source offset=%" PRId64 "\n",
				       (int64_t)src_off);
				goto err;
			}
			pages = in_range / PAGE_SIZE;
			for (p = 0; p < pages; p++) {
				sources[final_pages].src_page = src_off / PAGE_SIZE + p;
				sources[final_pages].patch = false;
				final_pages++;
			}

			pos += in_range;
			left -= in_range;
		}
	}

	*sources_out = sources;
	*final_pages_out = final_pages;
	*final_size_out = (off_t)final_pages * PAGE_SIZE;
	return 0;

err:
	xfree(sources);
	return -1;
}

static int hot_apply_reserve_ranges(struct hot_move_range **ranges,
				    size_t *cap, size_t need)
{
	struct hot_move_range *new_ranges;
	size_t new_cap = *cap ? *cap : 128;

	if (need <= *cap)
		return 0;
	while (new_cap < need)
		new_cap *= 2;

	new_ranges = xrealloc(*ranges, new_cap * sizeof((*ranges)[0]));
	if (!new_ranges)
		return -1;
	*ranges = new_ranges;
	*cap = new_cap;
	return 0;
}

static int hot_apply_add_move_range(struct hot_move_range **ranges,
				    size_t *nr, size_t *cap,
				    off_t src_page, off_t dst_page,
				    size_t nr_pages, bool scratch, bool patch)
{
	struct hot_move_range *r;

	if (!nr_pages || src_page == dst_page)
		return 0;
	if (hot_apply_reserve_ranges(ranges, cap, *nr + 1))
		return -1;

	r = &(*ranges)[(*nr)++];
	r->src_page = src_page;
	r->dst_page = dst_page;
	r->nr_pages = nr_pages;
	r->pending = true;
	r->scratch = scratch;
	r->patch = patch;
	return 0;
}

static int hot_apply_add_or_extend_move_range(struct hot_move_range **ranges,
					      size_t *nr, size_t *cap,
					      off_t src_page, off_t dst_page,
					      size_t nr_pages, bool scratch,
					      bool patch)
{
	struct hot_move_range *last;

	if (!*nr)
		return hot_apply_add_move_range(ranges, nr, cap, src_page,
						dst_page, nr_pages, scratch, patch);

	last = &(*ranges)[*nr - 1];
	if (last->pending && last->scratch == scratch && last->patch == patch &&
	    last->src_page + (off_t)last->nr_pages == src_page &&
	    last->dst_page + (off_t)last->nr_pages == dst_page) {
		last->nr_pages += nr_pages;
		return 0;
	}

	return hot_apply_add_move_range(ranges, nr, cap, src_page,
					dst_page, nr_pages, scratch, patch);
}

static int hot_apply_build_move_ranges(struct hot_apply_ctx *ctx,
				       struct hot_page_source *sources,
				       size_t final_pages,
				       struct hot_move_range **ranges_out,
				       size_t *nr_ranges_out)
{
	struct hot_move_range *ranges = NULL;
	size_t nr = 0, cap = 0;
	size_t i = 0;
	bool pass_patch;

	*ranges_out = NULL;
	*nr_ranges_out = 0;

	for (pass_patch = false; ; pass_patch = true) {
		i = 0;
		while (i < final_pages) {
			off_t src = sources[i].src_page;
			size_t pages = 1;

			if (sources[i].patch != pass_patch || src == (off_t)i) {
				i++;
				continue;
			}

			while (i + pages < final_pages &&
			       sources[i + pages].patch == pass_patch &&
			       sources[i + pages].src_page != (off_t)(i + pages) &&
			       sources[i + pages].src_page == src + (off_t)pages)
				pages++;

			if (hot_apply_add_or_extend_move_range(&ranges, &nr, &cap, src,
							       (off_t)i, pages, false,
							       pass_patch))
				goto err;
			if (pages > ctx->max_range_pages)
				ctx->max_range_pages = pages;
			i += pages;
		}

		if (pass_patch)
			break;
	}

	ctx->range_count = nr;
	*ranges_out = ranges;
	*nr_ranges_out = nr;
	return 0;

err:
	xfree(ranges);
	return -1;
}

static void hot_apply_live_counts_add(unsigned int *live_counts, size_t final_pages,
				      off_t start, size_t nr_pages, int delta)
{
	size_t i, begin, end;

	if (start < 0 || (size_t)start >= final_pages)
		return;

	begin = (size_t)start;
	end = begin + nr_pages;
	if (end > final_pages)
		end = final_pages;

	for (i = begin; i < end; i++) {
		if (delta > 0) {
			live_counts[i] += (unsigned int)delta;
			continue;
		}
		if (live_counts[i] < (unsigned int)(-delta))
			live_counts[i] = 0;
		else
			live_counts[i] -= (unsigned int)(-delta);
	}
}

static void hot_apply_live_counts_build(unsigned int *live_counts,
					size_t final_pages,
					struct hot_move_range *ranges,
					size_t nr_ranges)
{
	size_t i;

	memset(live_counts, 0, final_pages * sizeof(live_counts[0]));
	for (i = 0; i < nr_ranges; i++) {
		if (!ranges[i].pending || ranges[i].scratch)
			continue;
		hot_apply_live_counts_add(live_counts, final_pages,
					  ranges[i].src_page, ranges[i].nr_pages, 1);
	}
}

static bool hot_apply_range_contains_page(struct hot_move_range *r, size_t page)
{
	if (r->scratch || r->src_page < 0)
		return false;
	if (page < (size_t)r->src_page)
		return false;
	return page < (size_t)r->src_page + r->nr_pages;
}

static bool hot_apply_range_is_safe(struct hot_move_range *r,
				    unsigned int *live_counts,
				    size_t final_pages)
{
	size_t i, begin, end;

	if (r->dst_page < 0 || (size_t)r->dst_page >= final_pages)
		return true;

	begin = (size_t)r->dst_page;
	end = begin + r->nr_pages;
	if (end > final_pages)
		end = final_pages;

	for (i = begin; i < end; i++) {
		unsigned int self_live = hot_apply_range_contains_page(r, i) ? 1 : 0;

		if (live_counts[i] > self_live)
			return false;
	}

	return true;
}

static bool hot_apply_dst_conflicts(uint32_t *dst_epoch, uint32_t epoch,
				    struct hot_move_range *r,
				    size_t final_pages)
{
	size_t i, begin, end;

	if (r->dst_page < 0 || (size_t)r->dst_page >= final_pages)
		return false;

	begin = (size_t)r->dst_page;
	end = begin + r->nr_pages;
	if (end > final_pages)
		end = final_pages;

	for (i = begin; i < end; i++) {
		if (dst_epoch[i] == epoch)
			return true;
	}

	return false;
}

static void hot_apply_mark_dst(uint32_t *dst_epoch, uint32_t epoch,
			       struct hot_move_range *r, size_t final_pages)
{
	size_t i, begin, end;

	if (r->dst_page < 0 || (size_t)r->dst_page >= final_pages)
		return;

	begin = (size_t)r->dst_page;
	end = begin + r->nr_pages;
	if (end > final_pages)
		end = final_pages;

	for (i = begin; i < end; i++)
		dst_epoch[i] = epoch;
}

static int hot_apply_stage_scratch_range(struct hot_apply_ctx *ctx,
					 struct hot_move_range **ranges,
					 size_t *nr_ranges, size_t *cap,
					 size_t idx, size_t *added_pending,
					 unsigned int *live_counts,
					 size_t final_pages)
{
	struct hot_move_range *r = &(*ranges)[idx];
	struct hot_move_range scratch;
	size_t chunk_pages = r->nr_pages;
	off_t old_src_page = r->src_page;
	off_t scratch_off, scratch_page;
	unsigned long bytes;

	if (chunk_pages > HOT_APPLY_SCRATCH_PAGES)
		chunk_pages = HOT_APPLY_SCRATCH_PAGES;
	if (!chunk_pages)
		return -1;
	if (chunk_pages > ULONG_MAX / PAGE_SIZE) {
		pr_err("DSA hot apply scratch range is too large: pages=%zu\n",
		       chunk_pages);
		return -1;
	}

	scratch_off = ctx->file_size;
	if (scratch_off % PAGE_SIZE) {
		pr_err("DSA hot apply scratch tail is not page aligned: %" PRId64 "\n",
		       (int64_t)scratch_off);
		return -1;
	}
	scratch_page = scratch_off / PAGE_SIZE;
	bytes = (unsigned long)chunk_pages * PAGE_SIZE;

	if (hot_apply_remap_current(ctx, scratch_off + bytes))
		return -1;
	if (hot_dsa_copy_bytes(ctx, r->src_page * PAGE_SIZE, scratch_off, bytes))
		return -1;
	ctx->file_size = scratch_off + bytes;
	ctx->dsa_copy_pages += chunk_pages;
	ctx->dsa_copy_ranges++;
	ctx->dsa_copy_bytes += bytes;

	hot_apply_live_counts_add(live_counts, final_pages, old_src_page,
				  chunk_pages, -1);

	scratch.src_page = scratch_page;
	scratch.dst_page = r->dst_page;
	scratch.nr_pages = chunk_pages;
	scratch.pending = true;
	scratch.scratch = true;
	scratch.patch = r->patch;

	if (chunk_pages == r->nr_pages) {
		*r = scratch;
		*added_pending = 0;
	} else {
		r->src_page += chunk_pages;
		r->dst_page += chunk_pages;
		r->nr_pages -= chunk_pages;
		if (hot_apply_reserve_ranges(ranges, cap, *nr_ranges + 1))
			return -1;
		(*ranges)[(*nr_ranges)++] = scratch;
		*added_pending = 1;
	}

	ctx->scratch_uses++;
	ctx->scratch_bytes += bytes;
	return 0;
}

static int hot_apply_break_range_cycle(struct hot_apply_ctx *ctx,
				       struct hot_move_range **ranges,
				       size_t *nr_ranges, size_t *cap,
				       size_t *added_pending,
				       unsigned int *live_counts,
				       size_t final_pages)
{
	size_t i;

	for (i = 0; i < *nr_ranges; i++) {
		if ((*ranges)[i].pending && !(*ranges)[i].scratch)
			return hot_apply_stage_scratch_range(ctx, ranges,
							     nr_ranges, cap,
							     i, added_pending,
							     live_counts,
							     final_pages);
	}

	pr_err("DSA hot apply couldn't find a non-scratch range to break cycle\n");
	return -1;
}

static int hot_apply_stage_blocking_patch_source(struct hot_apply_ctx *ctx,
						 struct hot_move_range **ranges,
						 size_t *nr_ranges, size_t *cap,
						 size_t *added_pending,
						 unsigned int *live_counts,
						 size_t final_pages,
						 bool *staged)
{
	size_t i;

	*staged = false;
	for (i = 0; i < *nr_ranges; i++) {
		struct hot_move_range *r = &(*ranges)[i];

		if (!r->pending || r->scratch || !r->patch)
			continue;
		if (r->src_page < 0 || (size_t)r->src_page >= final_pages)
			continue;
		*staged = true;
		return hot_apply_stage_scratch_range(ctx, ranges, nr_ranges,
						     cap, i,
						     added_pending, live_counts,
						     final_pages);
	}

	return 0;
}

static int hot_apply_move_pages(struct hot_apply_ctx *ctx,
				struct hot_page_source *sources, size_t final_pages)
{
	struct hot_move_range *ranges = NULL;
	size_t nr_ranges = 0, cap_ranges = 0;
	size_t pending_count = 0;
	unsigned int *live_counts = NULL;
	uint32_t *dst_epoch = NULL;
	uint32_t epoch = 0;
	size_t *batch = NULL;
	size_t i;
	int ret = -1;
	uint64_t phase_start;
	uint64_t schedule_start;

	if (!final_pages)
		return 0;

	phase_start = hot_now_us();
	live_counts = xmalloc(final_pages * sizeof(live_counts[0]));
	dst_epoch = xzalloc(final_pages * sizeof(dst_epoch[0]));
	if (!live_counts || !dst_epoch)
		goto out;
	ctx->move_alloc_us += hot_now_us() - phase_start;

	phase_start = hot_now_us();
	if (hot_apply_build_move_ranges(ctx, sources, final_pages,
					&ranges, &nr_ranges))
		goto out;
	ctx->move_build_ranges_us += hot_now_us() - phase_start;
	cap_ranges = nr_ranges;
	pending_count = nr_ranges;
	phase_start = hot_now_us();
	batch = xmalloc(nr_ranges * sizeof(batch[0]));
	if (!batch)
		goto out;
	ctx->move_alloc_us += hot_now_us() - phase_start;
	phase_start = hot_now_us();
	hot_apply_live_counts_build(live_counts, final_pages, ranges, nr_ranges);
	ctx->move_live_counts_us += hot_now_us() - phase_start;

	schedule_start = hot_now_us();
	while (pending_count) {
		size_t batch_count = 0;
		uint64_t scan_start;
		uint64_t scan_end;
		bool progress = false;

		epoch++;
		if (!epoch) {
			memset(dst_epoch, 0, final_pages * sizeof(dst_epoch[0]));
			epoch++;
		}

		scan_start = hot_now_us();
		for (i = 0; i < nr_ranges; i++) {
			if (!ranges[i].pending)
				continue;
			if (!hot_apply_range_is_safe(&ranges[i], live_counts, final_pages))
				continue;
			if (hot_apply_dst_conflicts(dst_epoch, epoch, &ranges[i],
						    final_pages))
				continue;
			batch[batch_count++] = i;
			hot_apply_mark_dst(dst_epoch, epoch, &ranges[i], final_pages);
		}
		scan_end = hot_now_us();
		if (scan_end > scan_start)
			ctx->ready_scan_us += scan_end - scan_start;
		ctx->ready_rounds++;

		if (batch_count) {
			if (hot_dsa_submit_range_batch(ctx, ranges, batch, batch_count))
				goto out;

			for (i = 0; i < batch_count; i++) {
				struct hot_move_range *r = &ranges[batch[i]];
				unsigned long bytes = (unsigned long)r->nr_pages * PAGE_SIZE;

				ctx->moved_pages += r->nr_pages;
				ctx->moved_ranges++;
				ctx->dsa_copy_pages += r->nr_pages;
				ctx->dsa_copy_ranges++;
				ctx->dsa_copy_bytes += bytes;
				if (r->patch) {
					ctx->patch_pages += r->nr_pages;
					ctx->patch_ranges++;
				}
				if (!r->scratch)
					hot_apply_live_counts_add(live_counts, final_pages,
								  r->src_page,
								  r->nr_pages, -1);
				r->pending = false;
				pending_count--;
			}
			continue;
		}

		ctx->ready_empty_rounds++;

		i = 0;
		if (hot_apply_stage_blocking_patch_source(ctx, &ranges,
							  &nr_ranges,
							  &cap_ranges,
							  &i, live_counts,
							  final_pages,
							  &progress))
			goto out;
		if (progress) {
			pending_count += i;
			continue;
		}

		i = 0;
		if (hot_apply_break_range_cycle(ctx, &ranges, &nr_ranges,
						&cap_ranges,
						&i, live_counts, final_pages))
			goto out;
		pending_count += i;
	}
	ctx->move_schedule_us += hot_now_us() - schedule_start;

	ret = 0;

out:
	xfree(batch);
	xfree(dst_epoch);
	xfree(live_counts);
	xfree(ranges);
	return ret;
}

static int hot_apply_rewrite_pagemap(struct hot_apply_ctx *ctx)
{
	struct cr_img *pmi = NULL;
	PagemapHead head = PAGEMAP_HEAD__INIT;
	int dfd;
	size_t i;
	int ret = -1;

	dfd = open(ctx->current_dir, O_DIRECTORY | O_RDONLY | O_CLOEXEC);
	if (dfd < 0) {
		pr_perror("DSA hot apply can't open current dir for pagemap rewrite");
		return -1;
	}

	pmi = open_image_at(dfd, ctx->fd_type, O_DUMP, ctx->img_id);
	if (!pmi)
		goto out;

	head.pages_id = ctx->current_pages_id;
	if (pb_write_one(pmi, &head, PB_PAGEMAP_HEAD) < 0)
		goto out;

	for (i = 0; i < ctx->nr_entries; i++) {
		struct hot_apply_extent *e = &ctx->entries[i];
		PagemapEntry pe = PAGEMAP_ENTRY__INIT;

		pe.vaddr = e->vaddr;
		pe.nr_pages = e->len / PAGE_SIZE;
		pe.has_flags = true;
		pe.flags = PE_PRESENT;
		pe.has_nr_pages = true;

		if (pb_write_one(pmi, &pe, PB_PAGEMAP) < 0)
			goto out;
	}

	ret = 0;

out:
	if (pmi)
		close_image(pmi);
	close(dfd);
	return ret;
}

static int hot_apply_reorder_current(struct hot_apply_ctx *ctx)
{
	struct hot_old_range *old_ranges = NULL;
	struct hot_page_source *sources = NULL;
	size_t nr_old = 0;
	size_t final_pages = 0;
	off_t old_size = 0;
	off_t final_size = 0;
	uint64_t start_us = hot_now_us();
	uint64_t phase_start;
	off_t append_size;
	int ret = -1;

	phase_start = hot_now_us();
	if (hot_apply_load_old_ranges(ctx, &old_ranges, &nr_old, &old_size))
		goto out;
	ctx->reorder_load_old_us += hot_now_us() - phase_start;

	phase_start = hot_now_us();
	if (hot_apply_fill_sources(ctx, old_ranges, nr_old, old_size,
				   &sources, &final_pages, &final_size))
		goto out;
	ctx->reorder_fill_sources_us += hot_now_us() - phase_start;

	phase_start = hot_now_us();
	append_size = lseek(ctx->append_fd, 0, SEEK_END);
	if (append_size == (off_t)-1) {
		pr_perror("DSA hot apply can't seek current pages image");
		goto out;
	}
	if (append_size % PAGE_SIZE) {
		pr_err("DSA hot apply current pages size is not page aligned: %" PRId64 "\n",
		       (int64_t)append_size);
		goto out;
	}
	ctx->reorder_seek_us += hot_now_us() - phase_start;

	phase_start = hot_now_us();
	if (hot_dsa_open(ctx))
		goto out;
	ctx->reorder_dsa_open_us += hot_now_us() - phase_start;
	phase_start = hot_now_us();
	if (hot_apply_remap_current(ctx, append_size))
		goto out;
	ctx->reorder_mmap_us += hot_now_us() - phase_start;

	phase_start = hot_now_us();
	if (hot_apply_move_pages(ctx, sources, final_pages))
		goto out;
	ctx->reorder_move_us += hot_now_us() - phase_start;

	phase_start = hot_now_us();
	hot_apply_unmap_current(ctx);
	ctx->reorder_unmap_us += hot_now_us() - phase_start;
	phase_start = hot_now_us();
	if (ftruncate(ctx->append_fd, final_size)) {
		pr_perror("DSA hot apply can't truncate current pages image");
		goto out;
	}
	ctx->reorder_truncate_us += hot_now_us() - phase_start;

	phase_start = hot_now_us();
	if (hot_apply_rewrite_pagemap(ctx))
		goto out;
	ctx->reorder_rewrite_pagemap_us += hot_now_us() - phase_start;

	ctx->reorder_time_us = hot_now_us() - start_us;
	pr_info("DSA hot apply reordered current img_id=%lu pages_id=%u old_size=%" PRId64 " final_size=%" PRId64 " entries=%zu append_bytes=%" PRIu64 " append_time_us=%" PRIu64 " append_prepare_us=%" PRIu64 " append_tee_us=%" PRIu64 " append_splice_us=%" PRIu64 " reorder_time_us=%" PRIu64 " reorder_load_old_us=%" PRIu64 " reorder_fill_sources_us=%" PRIu64 " reorder_seek_us=%" PRIu64 " reorder_dsa_open_us=%" PRIu64 " reorder_mmap_us=%" PRIu64 " reorder_move_us=%" PRIu64 " reorder_unmap_us=%" PRIu64 " reorder_truncate_us=%" PRIu64 " reorder_rewrite_pagemap_us=%" PRIu64 " move_alloc_us=%" PRIu64 " move_build_ranges_us=%" PRIu64 " move_live_counts_us=%" PRIu64 " move_schedule_us=%" PRIu64 " moved_pages=%" PRIu64 " moved_ranges=%" PRIu64 " range_count=%" PRIu64 " max_range_pages=%" PRIu64 " patch_pages=%" PRIu64 " patch_ranges=%" PRIu64 " scratch_uses=%" PRIu64 " scratch_bytes=%" PRIu64 " dsa_copy_pages=%" PRIu64 " dsa_copy_ranges=%" PRIu64 " dsa_copy_bytes=%" PRIu64 " dsa_submit_us=%" PRIu64 " dsa_poll_us=%" PRIu64 " dsa_enqcmd=%" PRIu64 " dsa_submit_batches=%" PRIu64 " dsa_max_batch_ranges=%" PRIu64 " ready_scan_us=%" PRIu64 " ready_rounds=%" PRIu64 " ready_empty_rounds=%" PRIu64 "\n",
		ctx->img_id, ctx->current_pages_id, (int64_t)old_size,
		(int64_t)final_size, ctx->nr_entries, ctx->append_bytes,
		ctx->append_time_us, ctx->append_prepare_us, ctx->append_tee_us,
		ctx->append_splice_us, ctx->reorder_time_us,
		ctx->reorder_load_old_us, ctx->reorder_fill_sources_us,
		ctx->reorder_seek_us, ctx->reorder_dsa_open_us,
		ctx->reorder_mmap_us, ctx->reorder_move_us,
		ctx->reorder_unmap_us, ctx->reorder_truncate_us,
		ctx->reorder_rewrite_pagemap_us, ctx->move_alloc_us,
		ctx->move_build_ranges_us, ctx->move_live_counts_us,
		ctx->move_schedule_us, ctx->moved_pages, ctx->moved_ranges,
		ctx->range_count, ctx->max_range_pages, ctx->patch_pages,
		ctx->patch_ranges, ctx->scratch_uses, ctx->scratch_bytes,
		ctx->dsa_copy_pages, ctx->dsa_copy_ranges,
		ctx->dsa_copy_bytes, ctx->dsa_submit_us, ctx->dsa_poll_us,
		ctx->dsa_enqcmd, ctx->dsa_submit_batches,
		ctx->dsa_max_batch_ranges, ctx->ready_scan_us,
		ctx->ready_rounds, ctx->ready_empty_rounds);
	ret = 0;

out:
	hot_apply_unmap_current(ctx);
	hot_dsa_close(ctx);
	xfree(sources);
	hot_apply_free_old_ranges(old_ranges);
	return ret;
}
#endif

static void hot_apply_abort(struct page_xfer *xfer)
{
	struct hot_apply_ctx *ctx = xfer->hot_apply;
	size_t i;

	if (!ctx)
		return;

	if (ctx->pipefd[1] >= 0) {
		close(ctx->pipefd[1]);
		ctx->pipefd[1] = -1;
	}
	if (!ctx->finished)
		(void)hot_apply_write_manifest(ctx->manifest_path, "failed");
	hot_apply_unmap_current(ctx);
	hot_dsa_close(ctx);
	if (ctx->pipefd[0] >= 0)
		close(ctx->pipefd[0]);
	if (ctx->append_fd >= 0)
		close(ctx->append_fd);
	if (ctx->extent_fd >= 0)
		close(ctx->extent_fd);
	if (ctx->manifest_fd >= 0)
		close(ctx->manifest_fd);
	if (ctx->fg_idx_fd >= 0)
		close(ctx->fg_idx_fd);
	if (ctx->fg_dat_fd >= 0)
		close(ctx->fg_dat_fd);
	for (i = 0; i < ctx->nr_old_memstore; i++) {
		if (ctx->old_memstore[i].map && ctx->old_memstore[i].map != MAP_FAILED)
			munmap(ctx->old_memstore[i].map, ctx->old_memstore[i].map_size);
		if (ctx->old_memstore[i].fd >= 0)
			close(ctx->old_memstore[i].fd);
	}
	for (i = 0; i < ctx->nr_vma_segments; i++) {
		if (ctx->vma_segments[i].map &&
		    ctx->vma_segments[i].map != MAP_FAILED)
			munmap(ctx->vma_segments[i].map, ctx->vma_segments[i].map_size);
		if (ctx->vma_segments[i].fd >= 0)
			close(ctx->vma_segments[i].fd);
	}

	xfree(ctx->old_memstore);
	xfree(ctx->vma_segments);
	xfree(ctx->vma_plans);
	xfree(ctx->pagemap_plan);
	xfree(ctx->entries);
	xfree(ctx);
	xfer->hot_apply = NULL;
}

static int hot_memstore_finish(struct hot_apply_ctx *ctx)
{
	size_t i;
	int ret = -1;
	uint64_t producer_time_us;
	uint64_t total_hot_work_us;

	if (ctx->manifest_fd < 0) {
		pr_err("DSA hot memstore manifest fd is not open\n");
		goto out;
	}
	if (!ctx->nr_vma_segments) {
		pr_err("DSA hot memstore has no VMA segments for img_id=%lu\n",
		       ctx->img_id);
		goto out;
	}

	for (i = 0; i < ctx->nr_vma_segments; i++) {
		struct hot_vma_segment *seg = &ctx->vma_segments[i];

		if (hot_memstore_emit_line_fd(ctx->manifest_fd, ctx->img_id,
					      seg->start, seg->end - seg->start,
					      seg->file, seg->off))
			goto out;
	}

	ctx->memstore_segments = ctx->nr_vma_segments;
	producer_time_us = ctx->append_time_us;
	total_hot_work_us = ctx->append_time_us;
	if (dsa_debug_enabled())
		pr_info("DSA hot memstore updated img_id=%lu entries=%zu bytes=%" PRIu64 " vma_segments=%" PRIu64 " append_time_us=%" PRIu64 " producer_time_us=%" PRIu64 " tee_us=%" PRIu64 " write_us=%" PRIu64 " fg_pages=%" PRIu64 " fg_patch_pages=%" PRIu64 " fg_full_pages=%" PRIu64 " fg_patch_bytes=%" PRIu64 " fg_compare_ops=%" PRIu64 " fg_copy_ops=%" PRIu64 " enqueue_wait_us=%" PRIu64 " worker_wait_us=%" PRIu64 " worker_join_us=%" PRIu64 " queue_max=%" PRIu64 " pipe_size=%" PRIu64 "\n",
		ctx->img_id, ctx->nr_entries, ctx->memstore_bytes,
		ctx->memstore_segments, total_hot_work_us, producer_time_us,
		ctx->append_tee_us, ctx->append_splice_us,
		ctx->fg_pages, ctx->fg_patch_pages, ctx->fg_full_pages,
		ctx->fg_patch_bytes, ctx->fg_compare_ops, ctx->fg_copy_ops,
		ctx->append_enqueue_wait_us,
		ctx->worker_wait_us, ctx->worker_join_us,
		ctx->worker_queue_max, ctx->worker_pipe_size);
	ret = 0;

out:
	return ret;
}

static int hot_apply_prepare_post_thaw(struct hot_apply_ctx *ctx)
{
	int dfd;
	u64 materialize_start_us = 0;

	if (ctx->post_thaw_ready)
		return 0;
	if (hot_apply_mkdir_root(ctx->hot_root))
		return -1;
	if (ctx->pipefd[0] < 0 && pipe2(ctx->pipefd, O_CLOEXEC)) {
		pr_perror("DSA hot apply can't create pipe");
		return -1;
	}
	if (ctx->profile)
		materialize_start_us = dsa_profile_wall_now_us();
	if (hot_memstore_materialize_vmas(ctx))
		return -1;
	if (ctx->profile)
		ctx->profile_materialize_us += dsa_profile_delta_us(materialize_start_us,
							      dsa_profile_wall_now_us());
	if (ctx->fine_grained) {
		if (hot_fg_open_sidecar(ctx))
			return -1;
		if (!ctx->pre_freeze_ready && hot_dsa_open(ctx))
			return -1;
	}
	if (!ctx->memory_next_path || !ctx->memory_next_path[0]) {
		pr_err("DSA hot memstore requires CRIU_DSA_HOT_MEMORY_NEXT\n");
		return -1;
	}
	dfd = get_service_fd(IMG_FD_OFF);
	ctx->manifest_fd = openat(dfd, ctx->memory_next_path,
				  O_CREAT | O_APPEND | O_WRONLY | O_CLOEXEC, CR_FD_PERM);
	if (ctx->manifest_fd < 0) {
		pr_perror("DSA hot memstore can't open next manifest %s",
			  ctx->memory_next_path);
		return -1;
	}
	ctx->post_thaw_ready = true;
	return 0;
}

static int hot_fg_validate_sidecar(struct hot_apply_ctx *ctx)
{
	struct stat idx_st;
	struct stat dat_st;
	u64 idx_expected;

	if (!ctx->fine_grained)
		return 0;
	if (ctx->fg_idx_fd < 0 || ctx->fg_dat_fd < 0 || ctx->fg_dat_off < 0)
		return -1;
	if (fstat(ctx->fg_idx_fd, &idx_st) || fstat(ctx->fg_dat_fd, &dat_st)) {
		pr_perror("DSA fine-grained sidecar fstat failed");
		return -1;
	}
	idx_expected = ctx->fg_pages * sizeof(struct dsa_fg_page_meta);
	if ((u64)idx_st.st_size != idx_expected ||
	    (u64)dat_st.st_size != (u64)ctx->fg_dat_off) {
		pr_err("DSA fine-grained sidecar size mismatch idx=%" PRIu64 "/%" PRIu64
		       " dat=%" PRIu64 "/%" PRIu64 "\n",
		       (u64)idx_st.st_size, idx_expected, (u64)dat_st.st_size,
		       (u64)ctx->fg_dat_off);
		return -1;
	}
	return 0;
}

static int hot_apply_finish(struct page_xfer *xfer)
{
	struct hot_apply_ctx *ctx = xfer->hot_apply;
	int ret = 0;

	if (!ctx || ctx->finished)
		return 0;

	ctx->finished = true;

	if (ctx->pipefd[1] >= 0) {
		close(ctx->pipefd[1]);
		ctx->pipefd[1] = -1;
	}
	if (ctx->pipefd[0] >= 0) {
		close(ctx->pipefd[0]);
		ctx->pipefd[0] = -1;
	}
	if (ret == 0 && hot_fg_validate_sidecar(ctx))
		ret = -1;
	if (ret == 0 && hot_memstore_finish(ctx))
		ret = -1;
	if (ctx->append_fd >= 0) {
		if (close(ctx->append_fd)) {
			pr_perror("DSA hot apply append close failed");
			ret = -1;
		}
		ctx->append_fd = -1;
	}
	if (ctx->extent_fd >= 0) {
		if (close(ctx->extent_fd)) {
			pr_perror("DSA hot apply extent close failed");
			ret = -1;
		}
		ctx->extent_fd = -1;
	}
	if (ctx->manifest_fd >= 0) {
		if (close(ctx->manifest_fd)) {
			pr_perror("DSA hot memstore manifest close failed");
			ret = -1;
		}
		ctx->manifest_fd = -1;
	}
	if (ctx->fg_idx_fd >= 0) {
		if (close(ctx->fg_idx_fd)) {
			pr_perror("DSA fine-grained index close failed");
			ret = -1;
		}
		ctx->fg_idx_fd = -1;
	}
	if (ctx->fg_dat_fd >= 0) {
		if (close(ctx->fg_dat_fd)) {
			pr_perror("DSA fine-grained data close failed");
			ret = -1;
		}
		ctx->fg_dat_fd = -1;
	}
	xfree(ctx->entries);
	ctx->entries = NULL;
	return ret;
}

static void hot_profile_begin(struct hot_apply_ctx *ctx)
{
	if (!ctx || !ctx->profile || ctx->profile_started)
		return;
	ctx->profile_started = true;
	ctx->profile_total_start_us = dsa_profile_wall_now_us();
}

static void hot_profile_emit(struct hot_apply_ctx *ctx, int ret)
{
	const char *backend;
	u64 total_us;
	u64 accounted_us;
	u64 unaccounted_us;
	u64 idx_bytes;
	u64 dat_bytes;

	if (!ctx || !ctx->profile || !ctx->profile_started || ctx->profile_emitted)
		return;
	backend = hot_fg_compare_backend_name(ctx->fg_compare_backend);

	total_us = dsa_profile_delta_us(ctx->profile_total_start_us,
					 dsa_profile_wall_now_us());
	accounted_us = ctx->profile_post_prepare_us + ctx->profile_raw_index_us +
		ctx->profile_span_build_us + ctx->profile_compare_wall_us +
		ctx->profile_hot_apply_us + ctx->profile_pagemap_us +
		ctx->profile_finish_us;
	unaccounted_us = total_us >= accounted_us ? total_us - accounted_us : 0;
	idx_bytes = ctx->fg_pages * sizeof(struct dsa_fg_page_meta);
	dat_bytes = ctx->fg_dat_off >= 0 ? (u64)ctx->fg_dat_off : 0;

	ctx->profile_emitted = true;
	pr_info("DSA_POST_THAW_PROFILE_TIME: version=5 pages_id=%u backend=%s ret=%d total_us=%" PRIu64 " post_prepare_us=%" PRIu64 " materialize_us=%" PRIu64 " raw_index_us=%" PRIu64 " span_build_us=%" PRIu64 " compare_output_pipeline_wall_us=%" PRIu64 " compare_engine_wall_us=%" PRIu64 " compare_engine_cpu_us=%" PRIu64 " compare_breakdown=%u parent_prefault_wall_us=%" PRIu64 " parent_prefault_cpu_us=%" PRIu64 " compare_core_wall_us=%" PRIu64 " compare_core_cpu_us=%" PRIu64 " control_thread_cpu_us=%" PRIu64 " output_wall_us=%" PRIu64 " hot_apply_us=%" PRIu64 " pagemap_us=%" PRIu64 " pagemap_plan_us=%" PRIu64 " parent_validate_us=%" PRIu64 " pagemap_pack_us=%" PRIu64 " finish_us=%" PRIu64 " accounted_us=%" PRIu64 " unaccounted_us=%" PRIu64 " ledger_overrun=%u\n",
		ctx->pages_id, backend, ret, total_us, ctx->profile_post_prepare_us,
		ctx->profile_materialize_us, ctx->profile_raw_index_us,
		ctx->profile_span_build_us, ctx->profile_compare_wall_us,
		ctx->profile_compare_engine_wall_us,
		ctx->profile_compare_engine_cpu_us,
		ctx->compare_breakdown ? 1 : 0,
		ctx->profile_parent_prefault_wall_us,
		ctx->profile_parent_prefault_cpu_us,
		ctx->profile_compare_core_wall_us,
		ctx->profile_compare_core_cpu_us, ctx->profile_compare_cpu_us,
		ctx->profile_output_wall_us, ctx->profile_hot_apply_us,
		ctx->profile_pagemap_us, ctx->profile_pagemap_plan_us,
		ctx->profile_parent_validate_us, ctx->profile_pagemap_pack_us,
		ctx->profile_finish_us, accounted_us,
		unaccounted_us, accounted_us > total_us ? 1 : 0);
	pr_info("DSA_POST_THAW_PROFILE_COUNT: version=5 pages_id=%u backend=%s ret=%d raw_pages=%" PRIu64 " raw_bytes=%" PRIu64 " capture_runs=%" PRIu64 " spans=%" PRIu64 " span_pages=%" PRIu64 " max_span_pages=%" PRIu64 " compare_ops=%" PRIu64 " memcmp_calls=%" PRIu64 " memcmp_requested_bytes=%" PRIu64 " memcmp_scalar_bytes=%" PRIu64 " scalar64_calls=%" PRIu64 " scalar64_word_ops=%" PRIu64 " scalar64_refine_bytes=%" PRIu64 " scalar64_tail_bytes=%" PRIu64 " scalar64_bytes_examined=%" PRIu64 " simd_vector_ops=%" PRIu64 " simd_bytes_examined=%" PRIu64 " hybrid_dsa_claim_spans=%" PRIu64 " hybrid_dsa_claim_pages=%" PRIu64 " hybrid_cpu_claim_spans=%" PRIu64 " hybrid_cpu_claim_pages=%" PRIu64 " hybrid_cpu_waves=%" PRIu64 " hybrid_dsa_to_cpu_handoff_spans=%" PRIu64 " hybrid_dsa_to_cpu_handoff_pages=%" PRIu64 " hybrid_dsa_to_cpu_handoff_remaining_bytes=%" PRIu64 " hybrid_unclaimed_empty_count=%" PRIu64 " prq_profile_available=%u prq_profile_sources=%u prq_pg_requests=%" PRIu64 " prq_thread_cpu_us=%" PRIu64 " prq_setup_errno=%d enq_retries=%" PRIu64 " poll_sweeps=%" PRIu64 " not_ready=%" PRIu64 " max_active=%" PRIu64 " completions_harvested=%" PRIu64 " completion_timeout_count=%" PRIu64 " max_completion_age_us=%" PRIu64 " write_units=%" PRIu64 " write_unit_max_us=%" PRIu64 " prefault_spans=%" PRIu64 " prefault_pages=%" PRIu64 " parent_pages=%" PRIu64 " patch_pages=%" PRIu64 " full_pages=%" PRIu64 " patch_ranges=%" PRIu64 " patch_bytes=%" PRIu64 " idx_write_calls=%" PRIu64 " idx_bytes=%" PRIu64 " dat_write_calls=%" PRIu64 " dat_writev_calls=%" PRIu64 " dat_bytes=%" PRIu64 " hot_pwrite_ops=%" PRIu64 " hot_pwrite_bytes=%" PRIu64 " hot_mprotect_ops=%" PRIu64 " hot_memcpy_bytes=%" PRIu64 " pagemap_iovs=%" PRIu64 " pagemap_input_records=%" PRIu64 " pagemap_records=%zu pagemap_merged_records=%" PRIu64 " pagemap_present_pages=%" PRIu64 " pagemap_fg_pages=%" PRIu64 " pagemap_bytes=%" PRIu64 " pagemap_flushes=%" PRIu64 "\n",
		ctx->pages_id, backend, ret, ctx->profile_raw_pages, ctx->profile_raw_bytes,
		ctx->profile_capture_runs, ctx->profile_spans,
		ctx->profile_span_pages, ctx->profile_max_span_pages,
		ctx->fg_compare_ops, ctx->profile_memcmp_calls,
		ctx->profile_memcmp_requested_bytes,
		ctx->profile_memcmp_scalar_bytes, ctx->profile_scalar64_calls,
		ctx->profile_scalar64_word_ops, ctx->profile_scalar64_refine_bytes,
		ctx->profile_scalar64_tail_bytes, ctx->profile_scalar64_bytes_examined,
		ctx->profile_simd_vector_ops,
		ctx->profile_simd_bytes_examined,
		ctx->profile_hybrid_dsa_claim_spans,
		ctx->profile_hybrid_dsa_claim_pages,
		ctx->profile_hybrid_cpu_claim_spans,
		ctx->profile_hybrid_cpu_claim_pages,
		ctx->profile_hybrid_cpu_waves,
		ctx->profile_hybrid_dsa_to_cpu_handoff_spans,
		ctx->profile_hybrid_dsa_to_cpu_handoff_pages,
		ctx->profile_hybrid_dsa_to_cpu_handoff_remaining_bytes,
		ctx->profile_hybrid_unclaimed_empty_count,
		ctx->profile_prq_available ? 1 : 0,
		ctx->profile_nr_prq_sources,
		ctx->profile_prq_pg_requests,
		ctx->profile_prq_thread_cpu_us,
		ctx->profile_prq_setup_errno,
		ctx->profile_compare_enq_retries,
		ctx->profile_compare_poll_sweeps, ctx->profile_compare_not_ready,
		ctx->profile_compare_max_active, ctx->profile_completions_harvested,
		ctx->profile_completion_timeout_count,
		ctx->profile_max_completion_age_us,
		ctx->profile_write_units, ctx->profile_write_unit_max_us,
		ctx->profile_prefault_spans,
		ctx->profile_prefault_pages, ctx->profile_parent_pages,
		ctx->fg_patch_pages, ctx->fg_full_pages, ctx->profile_patch_ranges,
		ctx->fg_patch_bytes, ctx->profile_idx_writes, idx_bytes,
		ctx->profile_dat_writes, ctx->profile_dat_writevs, dat_bytes,
		ctx->profile_hot_pwrite_ops, ctx->profile_hot_pwrite_bytes,
		ctx->profile_hot_mprotect_ops, ctx->profile_hot_memcpy_bytes,
		ctx->profile_pagemap_iovs, ctx->pagemap_plan_input_records,
		ctx->nr_pagemap_plan,
		ctx->pagemap_plan_input_records >= ctx->nr_pagemap_plan ?
			ctx->pagemap_plan_input_records - ctx->nr_pagemap_plan : 0,
		ctx->pagemap_plan_present_pages, ctx->pagemap_plan_fg_pages,
		ctx->profile_pagemap_bytes, ctx->profile_pagemap_flushes);
}

static int hot_apply_init_xfer(struct page_xfer *xfer, int fd_type,
			       unsigned long img_id, u32 pages_id)
{
	struct hot_apply_ctx *ctx;

	if (!dsa_hot_apply_enabled())
		return 0;

	if (hot_apply_prepared) {
		ctx = hot_apply_prepared;
		if (ctx->pre_freeze_ready && ctx->fd_type == fd_type &&
		    ctx->img_id == img_id && ctx->fine_grained) {
			hot_apply_prepared = NULL;
			ctx->pages_id = pages_id;
			xfer->hot_apply = ctx;
			pr_info("DSA fine-grained attached pre-freeze parent view img_id=%lu pages_id=%u\n",
				img_id, pages_id);
			return 0;
		}
		/* A process-tree dump can open another task's pagemap first.  It must
		 * not consume the root task's immutable context; that task follows the
		 * ordinary post-thaw setup and the prepared context remains available
		 * for its matching img_id. */
	}

	ctx = hot_apply_alloc_ctx(fd_type, img_id, pages_id);
	if (!ctx)
		return -1;

	if (!ctx->memstore) {
		pr_err("DSA hot apply full-pages image/reorder mode has been removed; use CRIU_DSA_HOT_MODE=memstore\n");
		goto err;
	}

	if (fd_type != CR_FD_PAGEMAP) {
		pr_info("DSA hot memstore skips non-task pagemap fd_type=%d img_id=%lu\n",
			fd_type, img_id);
		xfree(ctx);
		return 0;
	}

	if (!ctx->hot_root || !ctx->hot_root[0]) {
		pr_err("DSA hot apply has no hot root/current dir\n");
		goto err;
	}

	xfer->hot_apply = ctx;
	pr_info("DSA hot memstore plan ready fd_type=%d img_id=%lu pages_id=%u root=%s next=%s old=%s fine_grained=%u\n",
		fd_type, img_id, pages_id, ctx->hot_root,
		ctx->memory_next_path,
		ctx->memory_manifest_path ? ctx->memory_manifest_path : "",
		ctx->fine_grained ? 1 : 0);
	return 0;

err:
	if (xfer->hot_apply) {
		hot_apply_abort(xfer);
	} else {
		xfer->hot_apply = ctx;
		hot_apply_abort(xfer);
	}
	return -1;
}

int page_xfer_hot_set_vmas(struct page_xfer *xfer, struct vm_area_list *vmas)
{
	struct hot_apply_ctx *ctx = xfer->hot_apply;
	struct vma_area *vma;

	if (!ctx || !ctx->memstore)
		return 0;
	if (ctx->fd_type != CR_FD_PAGEMAP)
		return 0;

	list_for_each_entry(vma, &vmas->h, list) {
		unsigned long start, end;

		if (!hot_memstore_should_track_vma(vma))
			continue;

		start = vma->e->start;
		end = vma->e->end;
		if (hot_memstore_plan_segment(ctx, start, end))
			return -1;
	}

	pr_info("DSA hot memstore VMA plan ready img_id=%lu segments=%zu\n",
		ctx->img_id, ctx->nr_vma_plans);
	return 0;
}

static int hot_apply_set_pending(struct page_xfer *xfer, struct iovec *iov, u32 flags)
{
	struct hot_apply_ctx *ctx = xfer->hot_apply;
	size_t idx = (size_t)-1;

	if (!ctx)
		return 0;

	if (!(flags & (PE_PRESENT | PE_PARENT))) {
		pr_err("DSA hot apply unsupported pagemap flags=%" PRIx32 "\n", flags);
		ctx->pending.valid = false;
		return -1;
	}

	if (hot_apply_add_entry(ctx, iov, flags, &idx)) {
		ctx->pending.valid = false;
		return -1;
	}

	if (!(flags & PE_PRESENT)) {
		ctx->pending.valid = false;
		ctx->pending_index = (size_t)-1;
		return 0;
	}

	ctx->pending.valid = true;
	ctx->pending.flags = flags;
	ctx->pending.fd_type = ctx->fd_type;
	ctx->pending.img_id = ctx->img_id;
	ctx->pending.pages_id = ctx->memstore ? ctx->pages_id : ctx->current_pages_id;
	ctx->pending.vaddr = (unsigned long)iov->iov_base;
	ctx->pending.len = iov->iov_len;
	ctx->pending_index = idx;
	return 0;
}

static int hot_apply_log_pending(struct hot_apply_ctx *ctx, unsigned long len,
				 off_t append_offset)
{
	struct hot_apply_extent *e = &ctx->pending;
	char line[256];
	int n;

	if (!e->valid || e->len != len) {
		pr_err("DSA hot apply pending extent mismatch valid=%d pending=%lu write=%lu\n",
		       e->valid, e->len, len);
		return -1;
	}

	e->seq = ctx->next_seq++;
	e->append_offset = append_offset;
	e->has_append = true;
	if (ctx->pending_index >= ctx->nr_entries) {
		pr_err("DSA hot apply pending index is invalid\n");
		return -1;
	}
	ctx->entries[ctx->pending_index].seq = e->seq;
	ctx->entries[ctx->pending_index].append_offset = append_offset;
	ctx->entries[ctx->pending_index].has_append = true;

	n = snprintf(line, sizeof(line),
		     "seq=%lu fd_type=%d img_id=%lu pages_id=%u vaddr=%" PRIx64 " len=%lu flags=%" PRIx32 " append_offset=%" PRIu64 "\n",
		     e->seq, e->fd_type, e->img_id, e->pages_id,
		     (uint64_t)e->vaddr, e->len, e->flags,
		     (uint64_t)append_offset);
	if (n < 0 || n >= (int)sizeof(line)) {
		pr_err("DSA hot apply extent line overflow\n");
		return -1;
	}
	if (write_full_fd(ctx->extent_fd, line, n)) {
		pr_perror("DSA hot apply extent write failed");
		return -1;
	}

	return 0;
}

static int hot_memstore_log_pending(struct hot_apply_ctx *ctx, unsigned long len,
				    struct hot_apply_extent **entry_out)
{
	struct hot_apply_extent *e = &ctx->pending;
	char line[PATH_MAX + 256];
	int n;

	*entry_out = NULL;
	if (!e->valid || e->len != len) {
		pr_err("DSA hot memstore pending extent mismatch valid=%d pending=%lu write=%lu\n",
		       e->valid, e->len, len);
		return -1;
	}

	e->seq = ctx->next_seq++;
	if (ctx->pending_index >= ctx->nr_entries) {
		pr_err("DSA hot memstore pending index is invalid\n");
		return -1;
	}
	ctx->entries[ctx->pending_index].seq = e->seq;
	*entry_out = &ctx->entries[ctx->pending_index];

	n = snprintf(line, sizeof(line),
		     "seq=%lu fd_type=%d img_id=%lu pages_id=%u vaddr=%" PRIx64 " len=%lu flags=%" PRIx32 " backend=memstore\n",
		     e->seq, e->fd_type, e->img_id, e->pages_id,
		     (uint64_t)e->vaddr, e->len, e->flags);
	if (n < 0 || n >= (int)sizeof(line)) {
		pr_err("DSA hot memstore extent line overflow\n");
		return -1;
	}
	if (ctx->extent_fd >= 0 && write_full_fd(ctx->extent_fd, line, n)) {
		pr_perror("DSA hot memstore extent write failed");
		return -1;
	}

	return 0;
}

static int splice_exact(int in, int out, unsigned long len)
{
	unsigned long curr = 0;

	while (curr < len) {
		ssize_t ret = splice(in, NULL, out, NULL, len - curr, SPLICE_F_MOVE);

		if (ret == -1) {
			pr_perror("Unable to splice pages data");
			return -1;
		}
		if (ret == 0) {
			pr_err("A pipe was closed unexpectedly\n");
			return -1;
		}
		curr += ret;
	}

	return 0;
}

struct page_server_iov {
	u32 cmd;
	u64 nr_pages;
	u64 vaddr;
	u64 dst_id;
};

static void psi2iovec(struct page_server_iov *ps, struct iovec *iov)
{
	iov->iov_base = decode_pointer(ps->vaddr);
	iov->iov_len = ps->nr_pages * PAGE_SIZE;
}

#define PS_IOV_ADD    1
#define PS_IOV_HOLE   2
#define PS_IOV_OPEN   3
#define PS_IOV_OPEN2  4
#define PS_IOV_PARENT 5
#define PS_IOV_ADD_F  6
#define PS_IOV_GET    7

#define PS_IOV_CLOSE	   0x1023
#define PS_IOV_FORCE_CLOSE 0x1024

#define PS_CMD_BITS 16
#define PS_CMD_MASK ((1 << PS_CMD_BITS) - 1)

#define PS_TYPE_BITS 8
#define PS_TYPE_MASK ((1 << PS_TYPE_BITS) - 1)

#define PS_TYPE_PID   (1)
#define PS_TYPE_SHMEM (2)
/*
 * XXX: When adding new types here check decode_pm for legacy
 * numbers that can be met from older CRIUs
 */

static inline u64 encode_pm(int type, unsigned long id)
{
	if (type == CR_FD_PAGEMAP)
		type = PS_TYPE_PID;
	else if (type == CR_FD_SHMEM_PAGEMAP)
		type = PS_TYPE_SHMEM;
	else {
		BUG();
		return 0;
	}

	return ((u64)id) << PS_TYPE_BITS | type;
}

static int decode_pm(u64 dst_id, unsigned long *id)
{
	int type;

	/*
	 * Magic numbers below came from the older CRIU versions that
	 * erroneously used the changing CR_FD_* constants. The
	 * changes were made when we merged images together and moved
	 * the CR_FD_-s at the tail of the enum
	 */
	type = dst_id & PS_TYPE_MASK;
	switch (type) {
	case 10: /* 3.1 3.2 */
	case 11: /* 1.3 1.4 1.5 1.6 1.7 1.8 2.* 3.0 */
	case 16: /* 1.2 */
	case 17: /* 1.0 1.1 */
	case PS_TYPE_PID:
		*id = dst_id >> PS_TYPE_BITS;
		type = CR_FD_PAGEMAP;
		break;
	case 27: /* 1.3 */
	case 28: /* 1.4 1.5 */
	case 29: /* 1.6 1.7 */
	case 32: /* 1.2 1.8 */
	case 33: /* 1.0 1.1 3.1 3.2 */
	case 34: /* 2.* 3.0 */
	case PS_TYPE_SHMEM:
		*id = dst_id >> PS_TYPE_BITS;
		type = CR_FD_SHMEM_PAGEMAP;
		break;
	default:
		type = -1;
		break;
	}

	return type;
}

static inline u32 encode_ps_cmd(u32 cmd, u32 flags)
{
	return flags << PS_CMD_BITS | cmd;
}

static inline u32 decode_ps_cmd(u32 cmd)
{
	return cmd & PS_CMD_MASK;
}

static inline u32 decode_ps_flags(u32 cmd)
{
	return cmd >> PS_CMD_BITS;
}

static inline int __send(int sk, const void *buf, size_t sz, int fl)
{
	return opts.tls ? tls_send(buf, sz, fl) : send(sk, buf, sz, fl);
}

static inline int __recv(int sk, void *buf, size_t sz, int fl)
{
	return opts.tls ? tls_recv(buf, sz, fl) : recv(sk, buf, sz, fl);
}

static inline int send_psi_flags(int sk, struct page_server_iov *pi, int flags)
{
	if (__send(sk, pi, sizeof(*pi), flags) != sizeof(*pi)) {
		pr_perror("Can't send PSI %d to server", pi->cmd);
		return -1;
	}
	return 0;
}

static inline int send_psi(int sk, struct page_server_iov *pi)
{
	return send_psi_flags(sk, pi, 0);
}

static void tcp_cork(int sk, bool on)
{
	int val = on ? 1 : 0;
	if (setsockopt(sk, SOL_TCP, TCP_CORK, &val, sizeof(val)))
		pr_pwarn("Unable to set TCP_CORK=%d", val);
}

static void tcp_nodelay(int sk, bool on)
{
	int val = on ? 1 : 0;
	if (setsockopt(sk, SOL_TCP, TCP_NODELAY, &val, sizeof(val)))
		pr_pwarn("Unable to set TCP_NODELAY=%d", val);
}

/* page-server xfer */
static int write_pages_to_server(struct page_xfer *xfer, int p, unsigned long len)
{
	ssize_t ret, left = len;

	if (opts.tls) {
		pr_debug("Sending %lx bytes\n", len);

		if (tls_send_data_from_fd(p, len))
			return -1;
	} else {
		pr_debug("Splicing %lx bytes into socket\n", len);

		while (left > 0) {
			ret = splice(p, NULL, xfer->sk, NULL, left, SPLICE_F_MOVE);
			if (ret < 0) {
				pr_perror("Can't write pages to socket");
				return -1;
			}

			pr_debug("\tSpliced: %lx bytes sent\n", (unsigned long)ret);
			left -= ret;
		}
	}

	return 0;
}

static int write_pagemap_to_server(struct page_xfer *xfer, struct iovec *iov, u32 flags)
{
	struct page_server_iov pi = {
		.cmd = encode_ps_cmd(PS_IOV_ADD_F, flags),
		.nr_pages = iov->iov_len / PAGE_SIZE,
		.vaddr = encode_pointer(iov->iov_base),
		.dst_id = xfer->dst_id,
	};

	return send_psi(xfer->sk, &pi);
}

static void close_server_xfer(struct page_xfer *xfer)
{
	xfer->sk = -1;
}

static int open_page_server_xfer(struct page_xfer *xfer, int fd_type, unsigned long img_id)
{
	char has_parent;
	struct page_server_iov pi = {
		.cmd = PS_IOV_OPEN2,
	};

	xfer->sk = page_server_sk;
	xfer->write_pagemap = write_pagemap_to_server;
	xfer->write_pages = write_pages_to_server;
	xfer->close = close_server_xfer;
	xfer->dst_id = encode_pm(fd_type, img_id);
	xfer->parent = NULL;

	pi.dst_id = xfer->dst_id;
	if (send_psi(xfer->sk, &pi)) {
		pr_perror("Can't write to page server");
		return -1;
	}

	/* Push the command NOW */
	tcp_nodelay(xfer->sk, true);

	if (__recv(xfer->sk, &has_parent, 1, 0) != 1) {
		pr_perror("The page server doesn't answer");
		return -1;
	}

	if (has_parent)
		xfer->parent = (void *)1; /* This is required for generate_iovs() */

	return 0;
}

/* local xfer */
static int hot_fg_write_pages_loc(struct page_xfer *xfer, int p,
				  unsigned long len,
				  struct hot_apply_extent *pending_entry);

static int write_pages_loc(struct page_xfer *xfer, int p, unsigned long len)
{
	struct hot_apply_ctx *ctx = xfer->hot_apply;
	unsigned long curr = 0;
	off_t append_offset;
	uint64_t append_prepare_start_us;
	struct hot_apply_extent *pending_entry = NULL;

	if (!ctx)
		return splice_exact(p, img_raw_fd(xfer->pi), len);

	append_prepare_start_us = hot_now_us();
	if (ctx->memstore) {
		if (hot_memstore_log_pending(ctx, len, &pending_entry))
			return -1;
	} else {
		append_offset = lseek(ctx->append_fd, 0, SEEK_END);
		if (append_offset == (off_t)-1) {
			pr_perror("DSA hot apply can't seek append file");
			return -1;
		}

		if (hot_apply_log_pending(ctx, len, append_offset))
			return -1;
	}
	ctx->append_prepare_us += hot_now_us() - append_prepare_start_us;

	if (ctx->fine_grained) {
		uint64_t append_start_us = hot_now_us();

		if (!ctx->memstore || !pending_entry) {
			pr_err("DSA fine-grained write requires hot memstore pending entry\n");
			return -1;
		}
		if (hot_fg_write_pages_loc(xfer, p, len, pending_entry))
			return -1;
		ctx->append_time_us += hot_now_us() - append_start_us;
		ctx->pending.valid = false;
		return 0;
	}

	while (curr < len) {
		uint64_t append_start_us;
		uint64_t append_delta_us;
		ssize_t ret;

		append_start_us = hot_now_us();
		ret = tee(p, ctx->pipefd[1], len - curr, 0);
		append_delta_us = hot_now_us() - append_start_us;
		ctx->append_tee_us += append_delta_us;
		ctx->append_time_us += append_delta_us;
		if (ret < 0) {
			pr_perror("DSA hot apply tee failed");
			return -1;
		}
		if (ret == 0) {
			pr_err("DSA hot apply tee returned 0\n");
			return -1;
		}

		if (splice_exact(p, img_raw_fd(xfer->pi), ret))
			return -1;

		append_start_us = hot_now_us();
		if (ctx->memstore) {
			if (hot_memstore_splice_to_segments(ctx, ctx->pipefd[0],
							    pending_entry->vaddr + curr,
							    ret))
				return -1;
		} else if (splice_exact(ctx->pipefd[0], ctx->append_fd, ret))
			return -1;
		append_delta_us = hot_now_us() - append_start_us;
		ctx->append_splice_us += append_delta_us;
		ctx->append_time_us += append_delta_us;
		ctx->append_bytes += ret;
		if (ctx->memstore)
			ctx->memstore_bytes += ret;

		curr += ret;
	}

	ctx->pending.valid = false;
	return 0;
}

static int check_pagehole_in_parent(struct page_read *p, struct iovec *iov)
{
	int ret;
	unsigned long off, end;

	/*
	 * Try to find pagemap entry in parent, from which
	 * the data will be read on restore.
	 *
	 * This is the optimized version of the page-by-page
	 * read_pagemap_page routine.
	 */

	pr_debug("Checking %p - %p hole\n", iov->iov_base, iov->iov_base + iov->iov_len);
	off = (unsigned long)iov->iov_base;
	end = off + iov->iov_len;
	while (1) {
		unsigned long pend;

		ret = p->seek_pagemap(p, off);
		if (ret <= 0 || !p->pe) {
			pr_err("Missing %lx in parent pagemap\n", off);
			return -1;
		}

		pr_debug("\tFound %" PRIx64 " - %" PRIx64 "\n",
			 p->pe->vaddr, p->pe->vaddr + pagemap_len(p->pe));

		/*
		 * The pagemap entry in parent may happen to be
		 * shorter, than the hole we write. In this case
		 * we should go ahead and check the remainder.
		 */

		pend = p->pe->vaddr + pagemap_len(p->pe);
		if (end <= pend)
			return 0;

		pr_debug("\t\tcontinue on %lx\n", pend);
		off = pend;
	}
}

static u32 page_xfer_effective_flags(struct page_xfer *xfer, u32 flags)
{
	struct hot_apply_ctx *ctx = xfer->hot_apply;

	if (((ctx && ctx->fine_grained) || xfer->dsa_fine_grained) &&
	    (flags & PE_PRESENT))
		flags |= PE_DSA_FG;

	return flags;
}

static bool hot_fg_defer_pagemap(const struct page_xfer *xfer)
{
	const struct hot_apply_ctx *ctx = xfer->hot_apply;

	return ctx && ctx->memstore && ctx->fine_grained &&
		xfer->dsa_fg_raw_capture && xfer->dsa_fg_materialized;
}

static int hot_fg_pagemap_plan_append(struct hot_apply_ctx *ctx,
				      const struct iovec *iov, u32 flags)
{
	struct hot_pagemap_plan_entry *entries;
	struct hot_pagemap_plan_entry *last;
	unsigned long vaddr = (unsigned long)iov->iov_base;
	unsigned long len = iov->iov_len;
	u64 nr_pages;
	size_t cap;

	if (!len || len % PAGE_SIZE || vaddr % PAGE_SIZE) {
		pr_err("DSA fine-grained pagemap record is not page aligned: %p/%zu\n",
		       iov->iov_base, iov->iov_len);
		return -1;
	}
	if (vaddr > ULONG_MAX - len) {
		pr_err("DSA fine-grained pagemap record overflows address space: %p/%zu\n",
		       iov->iov_base, iov->iov_len);
		return -1;
	}
	nr_pages = len / PAGE_SIZE;
	if (ctx->pagemap_plan_input_records == UINT64_MAX ||
	    ((flags & PE_PRESENT) &&
	     ctx->pagemap_plan_present_pages > UINT64_MAX - nr_pages) ||
	    ((flags & PE_DSA_FG) &&
	     ctx->pagemap_plan_fg_pages > UINT64_MAX - nr_pages)) {
		pr_err("DSA fine-grained pagemap accounting overflow\n");
		return -1;
	}
	if ((flags & PE_DSA_FG) && !(flags & PE_PRESENT)) {
		pr_err("DSA fine-grained pagemap record lacks PE_PRESENT: %p/%zu flags=%#x\n",
		       iov->iov_base, iov->iov_len, flags);
		return -1;
	}

	ctx->pagemap_plan_input_records++;
	if (flags & PE_PRESENT)
		ctx->pagemap_plan_present_pages += nr_pages;
	if (flags & PE_DSA_FG)
		ctx->pagemap_plan_fg_pages += nr_pages;

	if (ctx->nr_pagemap_plan) {
		last = &ctx->pagemap_plan[ctx->nr_pagemap_plan - 1];
		if (last->vaddr > ULONG_MAX - last->len) {
			pr_err("DSA fine-grained pagemap plan has overflowing tail\n");
			return -1;
		}
		if (vaddr < last->vaddr + last->len) {
			pr_err("DSA fine-grained pagemap input is not ordered: %p/%zu after %p/%lu\n",
			       iov->iov_base, iov->iov_len, (void *)last->vaddr,
			       last->len);
			return -1;
		}
		if (vaddr == last->vaddr + last->len && last->flags == flags) {
			if (last->len > ULONG_MAX - len) {
				pr_err("DSA fine-grained pagemap coalesce length overflow\n");
				return -1;
			}
			last->len += len;
			return 0;
		}
	}
	if (ctx->nr_pagemap_plan == ctx->pagemap_plan_cap) {
		cap = ctx->pagemap_plan_cap ? ctx->pagemap_plan_cap * 2 : 1024;
		if (cap < ctx->pagemap_plan_cap ||
		    cap > SIZE_MAX / sizeof(*entries)) {
			pr_err("DSA fine-grained pagemap plan capacity overflow\n");
			return -1;
		}
		entries = xrealloc(ctx->pagemap_plan, cap * sizeof(*entries));
		if (!entries)
			return -1;
		ctx->pagemap_plan = entries;
		ctx->pagemap_plan_cap = cap;
	}
	ctx->pagemap_plan[ctx->nr_pagemap_plan++] =
		(struct hot_pagemap_plan_entry) {
			.vaddr = vaddr,
			.len = len,
			.flags = flags,
		};
	return 0;
}

static int hot_fg_pagemap_validate(struct page_xfer *xfer)
{
	struct hot_apply_ctx *ctx = xfer->hot_apply;
	size_t i;

	if (ctx->pagemap_plan_input_records < ctx->nr_pagemap_plan ||
	    ctx->pagemap_plan_present_pages != ctx->pagemap_plan_fg_pages ||
	    ctx->pagemap_plan_fg_pages != ctx->fg_pages) {
		pr_err("DSA fine-grained pagemap/sidecar mismatch: input_records=%" PRIu64
		       " output_records=%zu present_pages=%" PRIu64
		       " fg_pages=%" PRIu64 " sidecar_pages=%" PRIu64 "\n",
		       ctx->pagemap_plan_input_records, ctx->nr_pagemap_plan,
		       ctx->pagemap_plan_present_pages, ctx->pagemap_plan_fg_pages,
		       ctx->fg_pages);
		return -1;
	}

	for (i = 0; i < ctx->nr_pagemap_plan; i++) {
		const struct hot_pagemap_plan_entry *entry = &ctx->pagemap_plan[i];
		struct iovec iov = {
			.iov_base = (void *)entry->vaddr,
			.iov_len = entry->len,
		};

		if (!(entry->flags & PE_PARENT) || !xfer->parent)
			continue;
		if (check_pagehole_in_parent(xfer->parent, &iov)) {
			pr_err("DSA fine-grained pagemap parent hole %p - %p not found\n",
			       iov.iov_base, iov.iov_base + iov.iov_len);
			return -1;
		}
	}
	return 0;
}

#define HOT_FG_PAGEMAP_PACK_BYTES (64U * 1024U)

static int hot_fg_pagemap_emit(struct page_xfer *xfer)
{
	struct hot_apply_ctx *ctx = xfer->hot_apply;
	unsigned char *buf;
	size_t used = 0;
	size_t i;
	int ret = -1;

	if (!ctx->nr_pagemap_plan)
		return 0;
	if (lazy_image(xfer->pmi) && open_image_lazy(xfer->pmi))
		return -1;
	buf = xmalloc(HOT_FG_PAGEMAP_PACK_BYTES);
	if (!buf)
		return -1;

	for (i = 0; i < ctx->nr_pagemap_plan; i++) {
		const struct hot_pagemap_plan_entry *entry = &ctx->pagemap_plan[i];
		PagemapEntry pe = PAGEMAP_ENTRY__INIT;
		size_t packed;
		u32 size;

		pe.vaddr = encode_pointer((void *)entry->vaddr);
		pe.nr_pages = entry->len / PAGE_SIZE;
		pe.has_flags = true;
		pe.flags = entry->flags;
		pe.has_nr_pages = true;
		size = pagemap_entry__get_packed_size(&pe);
		if (size > HOT_FG_PAGEMAP_PACK_BYTES - sizeof(size)) {
			pr_err("DSA fine-grained pagemap record too large size=%u\n", size);
			goto out;
		}
		if (used && used + sizeof(size) + size > HOT_FG_PAGEMAP_PACK_BYTES) {
			if (bwrite(&xfer->pmi->_x, buf, used) != (int)used) {
				pr_perror("DSA fine-grained pagemap batch write failed");
				goto out;
			}
			if (ctx->profile)
				ctx->profile_pagemap_flushes++;
			used = 0;
		}
		memcpy(buf + used, &size, sizeof(size));
		packed = pagemap_entry__pack(&pe, buf + used + sizeof(size));
		if (packed != size) {
			pr_err("DSA fine-grained pagemap pack mismatch packed=%zu size=%u\n",
			       packed, size);
			goto out;
		}
		used += sizeof(size) + size;
		if (ctx->profile) {
			ctx->profile_pagemap_bytes += sizeof(size) + size;
		}
	}
	if (used) {
		if (bwrite(&xfer->pmi->_x, buf, used) != (int)used) {
			pr_perror("DSA fine-grained pagemap final batch write failed");
			goto out;
		}
		if (ctx->profile)
			ctx->profile_pagemap_flushes++;
	}
	ret = 0;
out:
	xfree(buf);
	return ret;
}

static int write_pagemap_loc(struct page_xfer *xfer, struct iovec *iov, u32 flags)
{
	int ret;
	PagemapEntry pe = PAGEMAP_ENTRY__INIT;

	flags = page_xfer_effective_flags(xfer, flags);

	pe.vaddr = encode_pointer(iov->iov_base);
	pe.nr_pages = iov->iov_len / PAGE_SIZE;
	pe.has_flags = true;
	pe.flags = flags;
	pe.has_nr_pages = true;

	if (flags & PE_PRESENT) {
		if (opts.auto_dedup && xfer->parent != NULL) {
			ret = dedup_one_iovec(xfer->parent, pe.vaddr, pagemap_len(&pe));
			if (ret == -1) {
				pr_perror("Auto-deduplication failed");
				return ret;
			}
		}
	} else if ((flags & PE_PARENT) && !hot_fg_defer_pagemap(xfer)) {
		if (xfer->parent != NULL) {
			ret = check_pagehole_in_parent(xfer->parent, iov);
			if (ret) {
				pr_err("Hole %p - %p not found in parent\n",
				       iov->iov_base, iov->iov_base + iov->iov_len);
				return -1;
			}
		}
	}
	if (hot_fg_defer_pagemap(xfer))
		return hot_fg_pagemap_plan_append(xfer->hot_apply, iov, flags);

	if (pb_write_one(xfer->pmi, &pe, PB_PAGEMAP) < 0)
		return -1;

	if (hot_apply_set_pending(xfer, iov, flags))
		return -1;
	return 0;
}

static int hot_fg_write_meta(struct hot_apply_ctx *ctx,
			     struct dsa_fg_page_meta *meta)
{
	if (write_full_fd(ctx->fg_idx_fd, meta, sizeof(*meta))) {
		pr_perror("DSA fine-grained index write failed");
		return -1;
	}
	return 0;
}

static int hot_fg_writev_full_fd(int fd, struct iovec *iov, unsigned int nr)
{
	unsigned int head = 0;

	if (!nr || nr > HOT_FG_WRITEV_MAX)
		return nr ? -1 : 0;

	while (head < nr) {
		ssize_t ret = writev(fd, &iov[head], nr - head);

		if (ret < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (ret == 0) {
			errno = EIO;
			return -1;
		}

		while (head < nr && ret >= (ssize_t)iov[head].iov_len) {
			ret -= iov[head].iov_len;
			head++;
		}
		if (head < nr && ret) {
			iov[head].iov_base = (char *)iov[head].iov_base + ret;
			iov[head].iov_len -= ret;
		}
	}

	return 0;
}

static int hot_fg_write_full(struct hot_apply_ctx *ctx, unsigned long vaddr,
			     const void *cur)
{
	struct dsa_fg_page_meta meta = {};
	off_t data_off;

	data_off = ctx->fg_dat_off;
	if (write_full_fd(ctx->fg_dat_fd, cur, PAGE_SIZE)) {
		pr_perror("DSA fine-grained full page write failed");
		return -1;
	}
	ctx->fg_dat_off += PAGE_SIZE;

	meta.vaddr = vaddr;
	meta.data_off = data_off;
	meta.data_len = PAGE_SIZE;
	meta.patch_count = 0;
	meta.flags = DSA_FG_PAGE_FULL;
	if (hot_fg_write_meta(ctx, &meta))
		return -1;

	if (ctx->profile) {
		ctx->fg_pages++;
		ctx->fg_full_pages++;
		ctx->fg_patch_bytes += PAGE_SIZE;
	}
	return 0;
}

static int hot_fg_write_patch(struct hot_apply_ctx *ctx, unsigned long vaddr,
			      const void *cur, const void *old)
{
	struct dsa_fg_patch_entry patches[PAGE_SIZE / DSA_FG_PATCH_SIZE];
	struct iovec data_iov[DSA_FG_MAX_PATCHES];
	unsigned int patch_count = 0;
	unsigned int bytes = 0;
	unsigned int cursor = 0;
	struct dsa_fg_page_meta meta = {};
	off_t data_off;

	while (cursor < PAGE_SIZE) {
		unsigned int diff;
		unsigned int len;
		bool equal;

		if (hot_dsa_compare_first_diff(ctx,
					       (const char *)cur + cursor,
					       (const char *)old + cursor,
					       PAGE_SIZE - cursor,
					       &equal, &diff))
			return -1;
		if (equal)
			break;
		diff += cursor;

		len = PAGE_SIZE - diff;
		if (len > DSA_FG_PATCH_SIZE)
			len = DSA_FG_PATCH_SIZE;
		if (patch_count == sizeof(patches) / sizeof(patches[0]) ||
		    patch_count + 1 > DSA_FG_MAX_PATCHES ||
		    bytes + len > DSA_FG_MAX_BYTES)
			return hot_fg_write_full(ctx, vaddr, cur);

		patches[patch_count].off = diff;
		patches[patch_count].len = len;
		data_iov[patch_count].iov_base = (void *)((const char *)cur + diff);
		data_iov[patch_count].iov_len = len;
		patch_count++;
		bytes += len;
		cursor = diff + len;
	}

	data_off = ctx->fg_dat_off;
	if (patch_count) {
		if (write_full_fd(ctx->fg_dat_fd, patches,
				  patch_count * sizeof(patches[0])) ||
		    hot_fg_writev_full_fd(ctx->fg_dat_fd, data_iov, patch_count)) {
			pr_perror("DSA fine-grained patch write failed");
			return -1;
		}
		ctx->fg_dat_off += patch_count * sizeof(patches[0]) + bytes;
	}

	meta.vaddr = vaddr;
	meta.data_off = data_off;
	meta.data_len = patch_count * sizeof(patches[0]) + bytes;
	meta.patch_count = patch_count;
	meta.flags = patch_count ? DSA_FG_PAGE_PATCH : DSA_FG_PAGE_PARENT;
	if (hot_fg_write_meta(ctx, &meta))
		return -1;

	if (ctx->profile) {
		ctx->fg_pages++;
		if (patch_count) {
			ctx->fg_patch_pages++;
			ctx->fg_patch_bytes += bytes;
		}
	}
	return 0;
}

static int hot_fg_write_page(struct hot_apply_ctx *ctx, unsigned long vaddr,
			     const void *cur)
{
	struct hot_memstore_seg *old;
	void *old_map;

	old = hot_memstore_find_old_cover(ctx, vaddr, vaddr + PAGE_SIZE);
	if (!old)
		return hot_fg_write_full(ctx, vaddr, cur);

	old_map = hot_memstore_old_map(old);
	if (old_map == MAP_FAILED)
		return -1;

	return hot_fg_write_patch(ctx, vaddr, cur,
			  (const char *)old_map + (vaddr - old->vaddr));
}

enum hot_fg_raw_page_state {
	HOT_FG_RAW_PENDING = 0,
	HOT_FG_RAW_PARENT,
	HOT_FG_RAW_PATCH,
	HOT_FG_RAW_FULL,
};

struct hot_fg_raw_page {
	unsigned long vaddr;
	const unsigned char *raw;
	const unsigned char *parent;
	u32 capture_run;
	u32 cursor;
	u32 patch_bytes;
	u16 patch_count;
	u16 state;
	struct dsa_fg_patch_entry patches[DSA_FG_MAX_PATCHES];
};

struct hot_fg_compare_slot {
	struct dsa_hw_desc desc __attribute__((aligned(64)));
	volatile struct dsa_completion_record comp __attribute__((aligned(32)));
	struct hot_fg_compare_span *span;
	u32 submitted_cursor;
	u32 submitted_len;
	u32 wq_idx;
	u64 submit_sequence;
	u64 submit_ns;
	u64 completion_deadline_ns;
	bool active;
};

enum hot_fg_compare_span_state {
	HOT_FG_SPAN_UNPREFAULTED = 0,
	HOT_FG_SPAN_READY,
	HOT_FG_SPAN_ACTIVE,
	HOT_FG_SPAN_DONE,
};

enum hot_fg_compare_owner {
	HOT_FG_OWNER_NONE = 0,
	HOT_FG_OWNER_DSA,
	HOT_FG_OWNER_CPU,
};

struct hot_fg_compare_span {
	const unsigned char *raw;
	const unsigned char *parent;
	size_t first_page;
	size_t page_count;
	u32 length;
	u32 cursor;
	size_t finalized_pages;
	u8 state;
	u8 owner;
};

struct hot_fg_ready_queue {
	size_t *indices;
	struct hot_fg_compare_span *spans;
	size_t capacity;
	size_t head;
	size_t tail;
	size_t nr;
};

struct hot_fg_output_state {
	struct hot_apply_ctx *ctx;
	struct hot_fg_raw_page *pages;
	size_t nr_pages;
	size_t next_page;
	struct dsa_fg_page_meta metas[HOT_FG_OUTPUT_META_MAX];
	struct iovec iov[HOT_FG_WRITEV_MAX];
	struct iovec write_iov[HOT_FG_WRITEV_MAX];
	unsigned int nr_metas;
	unsigned int nr_iov;
	unsigned int iov_head;
	u64 chunk_dat_bytes;
	bool flushing;
	bool idx_written;
};

static int hot_fg_raw_pages_append(struct hot_apply_ctx *ctx,
				   struct hot_fg_raw_page **pages, size_t *nr,
				   size_t *cap, unsigned long vaddr,
				   const unsigned char *raw, u32 capture_run)
{
	struct hot_fg_raw_page *page;
	struct hot_memstore_seg *old;
	void *old_map;

	if (*nr == *cap) {
		size_t new_cap = *cap ? *cap * 2 : 4096;
		void *new_pages = xrealloc(*pages, new_cap * sizeof(**pages));

		if (!new_pages)
			return -1;
		*pages = new_pages;
		*cap = new_cap;
	}
	page = &(*pages)[(*nr)++];
	memset(page, 0, sizeof(*page));
	page->vaddr = vaddr;
	page->raw = raw;
	page->capture_run = capture_run;
	page->state = HOT_FG_RAW_PENDING;

	old = hot_memstore_find_old_cover(ctx, vaddr, vaddr + PAGE_SIZE);
	if (!old) {
		page->state = HOT_FG_RAW_FULL;
		return 0;
	}
	old_map = hot_memstore_old_map(old);
	if (old_map == MAP_FAILED)
		return -1;
	page->parent = (const unsigned char *)old_map + (vaddr - old->vaddr);
	return 0;
}

static int hot_fg_ready_queue_init(struct hot_fg_ready_queue *queue,
				   struct hot_fg_compare_span *spans,
				   size_t nr_spans)
{
	memset(queue, 0, sizeof(*queue));
	queue->indices = xmalloc(nr_spans * sizeof(*queue->indices));
	if (!queue->indices)
		return -1;
	queue->spans = spans;
	queue->capacity = nr_spans;
	return 0;
}

static void hot_fg_ready_queue_fini(struct hot_fg_ready_queue *queue)
{
	xfree(queue->indices);
	queue->indices = NULL;
}

static int hot_fg_ready_queue_push(struct hot_fg_ready_queue *queue,
				   size_t span_idx)
{
	struct hot_fg_compare_span *span;

	if (span_idx >= queue->capacity || queue->nr >= queue->capacity)
		return -1;
	span = &queue->spans[span_idx];
	if (span->state != HOT_FG_SPAN_READY)
		return -1;
	queue->indices[queue->tail] = span_idx;
	queue->tail = (queue->tail + 1) % queue->capacity;
	queue->nr++;
	return 0;
}

static int hot_fg_ready_queue_pop(struct hot_fg_ready_queue *queue,
				  size_t *span_idx)
{
	if (!queue->nr)
		return 1;
	*span_idx = queue->indices[queue->head];
	queue->head = (queue->head + 1) % queue->capacity;
	queue->nr--;
	return 0;
}

static bool hot_fg_output_done(const struct hot_fg_output_state *out)
{
	return out->next_page == out->nr_pages && !out->nr_metas &&
	       !out->flushing;
}

static void hot_fg_output_reset_chunk(struct hot_fg_output_state *out)
{
	out->nr_metas = 0;
	out->nr_iov = 0;
	out->iov_head = 0;
	out->chunk_dat_bytes = 0;
	out->flushing = false;
	out->idx_written = false;
}

static int hot_fg_output_append_iov(struct hot_fg_output_state *out,
				    const void *base, size_t len)
{
	struct iovec *last;

	if (!len)
		return 0;
	if (out->nr_iov) {
		last = &out->iov[out->nr_iov - 1];
		if ((const char *)last->iov_base + last->iov_len == base) {
			last->iov_len += len;
			return 0;
		}
	}
	if (out->nr_iov >= HOT_FG_WRITEV_MAX)
		return -1;
	out->iov[out->nr_iov].iov_base = (void *)base;
	out->iov[out->nr_iov].iov_len = len;
	out->nr_iov++;
	return 0;
}

static int hot_fg_output_append_page(struct hot_fg_output_state *out,
				     bool *progress)
{
	struct hot_apply_ctx *ctx = out->ctx;
	struct hot_fg_raw_page *page;
	struct dsa_fg_page_meta *meta;
	u64 data_len = 0;
	unsigned int needed_iov = 0;
	u16 i;

	*progress = false;
	if (out->next_page == out->nr_pages) {
		if (out->nr_metas) {
			out->flushing = true;
			*progress = true;
		}
		return 0;
	}
	page = &out->pages[out->next_page];
	if (page->state == HOT_FG_RAW_PENDING)
		return 0;
	if (page->state == HOT_FG_RAW_FULL) {
		data_len = PAGE_SIZE;
		needed_iov = 1;
	} else if (page->state == HOT_FG_RAW_PATCH) {
		data_len = page->patch_count * sizeof(page->patches[0]) +
			page->patch_bytes;
		needed_iov = 1 + page->patch_count;
	} else if (page->state != HOT_FG_RAW_PARENT) {
		pr_err("DSA fine-grained sidecar has invalid final page state=%u\n",
		       page->state);
		return -1;
	}

	if (out->nr_metas &&
	    (out->nr_metas == HOT_FG_OUTPUT_META_MAX ||
	     needed_iov > HOT_FG_WRITEV_MAX - out->nr_iov ||
	     data_len > HOT_FG_OUTPUT_LOGICAL_BYTES - out->chunk_dat_bytes)) {
		out->flushing = true;
		*progress = true;
		return 0;
	}
	if (needed_iov > HOT_FG_WRITEV_MAX ||
	    data_len > HOT_FG_OUTPUT_LOGICAL_BYTES) {
		pr_err("DSA fine-grained sidecar page exceeds output bounds vaddr=%lx iov=%u bytes=%" PRIu64 "\n",
		       page->vaddr, needed_iov, data_len);
		return -1;
	}
	if (ctx->fg_dat_off < 0 || data_len > (u64)LLONG_MAX -
	    (u64)ctx->fg_dat_off) {
		pr_err("DSA fine-grained sidecar data offset overflow off=%lld bytes=%" PRIu64 "\n",
		       (long long)ctx->fg_dat_off, data_len);
		return -1;
	}
	if (!ctx->profile_output_start_us && ctx->profile)
		ctx->profile_output_start_us = dsa_profile_wall_now_us();
	meta = &out->metas[out->nr_metas++];
	memset(meta, 0, sizeof(*meta));
	meta->vaddr = page->vaddr;
	meta->data_off = ctx->fg_dat_off;
	meta->data_len = data_len;
	if (page->state == HOT_FG_RAW_FULL) {
		meta->flags = DSA_FG_PAGE_FULL;
		if (hot_fg_output_append_iov(out, page->raw, PAGE_SIZE))
			return -1;
	} else if (page->state == HOT_FG_RAW_PATCH) {
		meta->flags = DSA_FG_PAGE_PATCH;
		meta->patch_count = page->patch_count;
		if (hot_fg_output_append_iov(out, page->patches,
					     page->patch_count * sizeof(page->patches[0])))
			return -1;
		for (i = 0; i < page->patch_count; i++) {
			if (hot_fg_output_append_iov(out,
						     page->raw + page->patches[i].off,
						     page->patches[i].len))
				return -1;
		}
	} else {
		meta->flags = DSA_FG_PAGE_PARENT;
	}
	ctx->fg_dat_off += data_len;
	out->chunk_dat_bytes += data_len;
	ctx->fg_pages++;
	if (page->state == HOT_FG_RAW_FULL) {
		ctx->fg_full_pages++;
		ctx->fg_patch_bytes += PAGE_SIZE;
	} else if (page->state == HOT_FG_RAW_PATCH) {
		ctx->fg_patch_pages++;
		ctx->fg_patch_bytes += page->patch_bytes;
		if (ctx->profile)
			ctx->profile_patch_ranges += page->patch_count;
	} else if (ctx->profile) {
		ctx->profile_parent_pages++;
	}
	out->next_page++;
	if (out->nr_metas == HOT_FG_OUTPUT_META_MAX ||
	    out->nr_iov == HOT_FG_WRITEV_MAX ||
	    out->chunk_dat_bytes == HOT_FG_OUTPUT_LOGICAL_BYTES ||
	    out->next_page == out->nr_pages)
		out->flushing = true;
	*progress = true;
	return 0;
}

static void hot_fg_output_advance_iov(struct hot_fg_output_state *out,
				      u64 bytes)
{
	while (bytes && out->iov_head < out->nr_iov) {
		struct iovec *iov = &out->iov[out->iov_head];

		if (bytes >= iov->iov_len) {
			bytes -= iov->iov_len;
			out->iov_head++;
		} else {
			iov->iov_base = (char *)iov->iov_base + bytes;
			iov->iov_len -= bytes;
			bytes = 0;
		}
	}
}

static int hot_fg_output_write_dat_unit(struct hot_fg_output_state *out,
					bool *progress)
{
	struct hot_apply_ctx *ctx = out->ctx;
	u64 bytes = 0;
	u64 write_start_us = 0;
	unsigned int nr = 0;
	unsigned int i;

	*progress = false;
	for (i = out->iov_head; i < out->nr_iov &&
	     bytes < HOT_FG_OUTPUT_WRITE_BYTES; i++) {
		u64 len = out->iov[i].iov_len;

		if (len > HOT_FG_OUTPUT_WRITE_BYTES - bytes)
			len = HOT_FG_OUTPUT_WRITE_BYTES - bytes;
		out->write_iov[nr] = out->iov[i];
		out->write_iov[nr].iov_len = len;
		nr++;
		bytes += len;
	}
	if (!nr)
		return 0;
	if (ctx->profile)
		write_start_us = dsa_profile_wall_now_us();
	if (hot_fg_writev_full_fd(ctx->fg_dat_fd, out->write_iov, nr)) {
		pr_perror("DSA fine-grained bounded data write failed");
		return -1;
	}
	hot_fg_output_advance_iov(out, bytes);
	if (ctx->profile) {
		u64 elapsed = dsa_profile_delta_us(write_start_us,
						 dsa_profile_wall_now_us());

		ctx->profile_dat_writevs++;
		ctx->profile_write_units++;
		if (elapsed > ctx->profile_write_unit_max_us)
			ctx->profile_write_unit_max_us = elapsed;
	}
	*progress = true;
	return 0;
}

static int hot_fg_output_step(struct hot_fg_output_state *out,
			      bool allow_write, bool *progress,
			      bool *wrote)
{
	struct hot_apply_ctx *ctx = out->ctx;

	*progress = false;
	*wrote = false;
	if (!out->flushing)
		return hot_fg_output_append_page(out, progress);
	if (!allow_write)
		return 0;
	if (!out->idx_written) {
		size_t bytes = out->nr_metas * sizeof(out->metas[0]);
		u64 write_start_us = 0;

		if (ctx->profile)
			write_start_us = dsa_profile_wall_now_us();
		if (write_full_fd(ctx->fg_idx_fd, out->metas, bytes)) {
			pr_perror("DSA fine-grained bounded index write failed");
			return -1;
		}
		out->idx_written = true;
		if (ctx->profile) {
			u64 elapsed = dsa_profile_delta_us(write_start_us,
							 dsa_profile_wall_now_us());

			ctx->profile_idx_writes++;
			ctx->profile_write_units++;
			if (elapsed > ctx->profile_write_unit_max_us)
				ctx->profile_write_unit_max_us = elapsed;
		}
		*progress = true;
		*wrote = true;
		if (!out->nr_iov)
			hot_fg_output_reset_chunk(out);
		return 0;
	}
	if (hot_fg_output_write_dat_unit(out, progress))
		return -1;
	if (*progress) {
		*wrote = true;
		if (out->iov_head == out->nr_iov)
			hot_fg_output_reset_chunk(out);
	}
	return 0;
}

static int hot_fg_output_drain(struct hot_fg_output_state *out)
{
	while (!hot_fg_output_done(out)) {
		bool progress;
		bool wrote;

		if (hot_fg_output_step(out, true, &progress, &wrote))
			return -1;
		if (!progress) {
			pr_err("DSA fine-grained output drain blocked at page=%zu/%zu state=%u\n",
			       out->next_page, out->nr_pages,
			       out->next_page < out->nr_pages ?
			       out->pages[out->next_page].state : 0);
			return -1;
		}
	}
	return 0;
}

static int hot_fg_compare_submit(struct hot_apply_ctx *ctx,
				  struct hot_fg_compare_slot *slot,
				  struct hot_fg_compare_span *span,
				  u64 submit_sequence, u64 submit_ns)
{
	unsigned int wq_idx;
	unsigned long portal_mask;
	unsigned long off;
	uint32_t retry;

	if (!span->parent || span->state != HOT_FG_SPAN_READY ||
	    span->cursor >= span->length || !ctx->dsa_wq_count ||
	    !ctx->dsa_max_transfer_size)
		return -1;
	wq_idx = ctx->dsa_next_wq++ % (unsigned int)ctx->dsa_wq_count;
	portal_mask = ((unsigned long)ctx->dsa_portals[wq_idx]) & ~0xfffUL;
	memset(&slot->desc, 0, sizeof(slot->desc));
	memset((void *)&slot->comp, 0, sizeof(slot->comp));
	slot->submitted_cursor = span->cursor;
	slot->submitted_len = span->length - span->cursor;
	if (slot->submitted_len > ctx->dsa_max_transfer_size)
		slot->submitted_len = ctx->dsa_max_transfer_size;
	if (!slot->submitted_len)
		return -1;
	slot->wq_idx = wq_idx;
	slot->span = span;
	slot->submit_sequence = submit_sequence;
	slot->submit_ns = submit_ns;
	slot->completion_deadline_ns = submit_ns + HOT_DSA_COMPLETION_TIMEOUT_NS;
	slot->desc.opcode = DSA_OPCODE_COMPARE;
	slot->desc.flags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR | IDXD_OP_FLAG_BOF;
	slot->desc.src_addr = (uint64_t)(unsigned long)(span->raw + span->cursor);
	slot->desc.src2_addr = (uint64_t)(unsigned long)(span->parent + span->cursor);
	slot->desc.xfer_size = slot->submitted_len;
	slot->desc.completion_addr = (uint64_t)(unsigned long)&slot->comp;

	for (retry = 0; retry < HOT_DSA_MAX_ENQ_RETRY; retry++) {
		void *portal_slot;

		off = ((ctx->dsa_portal_offset[wq_idx]++ << 6) & 0xfffUL);
		portal_slot = (void *)(portal_mask | off);
		if (hot_dsa_enqcmd(portal_slot, &slot->desc) == 0)
			break;
		hot_dsa_cpu_relax();
	}
	if (retry == HOT_DSA_MAX_ENQ_RETRY) {
		pr_err("DSA fine-grained compare wavefront enqcmd timed out\n");
		return -1;
	}
	if (ctx->profile) {
		ctx->fg_compare_ops++;
		ctx->dsa_enqcmd++;
		ctx->profile_compare_enq_retries += retry;
	}
	slot->active = true;
	span->state = HOT_FG_SPAN_ACTIVE;
	return 0;
}

static __attribute__((noreturn)) void
hot_fg_completion_timeout_fatal(const struct hot_fg_compare_slot *slot,
				 size_t active, u64 now_ns, const char *stage)
{
	u64 age_us = now_ns >= slot->submit_ns ?
		(now_ns - slot->submit_ns) / 1000ULL : 0;

	pr_err("CDP_DSA_COMPLETION_TIMEOUT: stage=%s exit=%u wq=%u sequence=%" PRIu64
	       " age_us=%" PRIu64 " active=%zu opcode=%u length=%u src=%" PRIx64
	       " dst=%" PRIx64 " status=%u\n",
	       stage, CDP_DSA_COMPLETION_TIMEOUT_EXIT, slot->wq_idx,
	       slot->submit_sequence, age_us, active, slot->desc.opcode,
	       slot->submitted_len, slot->desc.src_addr, slot->desc.src2_addr,
	       (unsigned int)__atomic_load_n(&slot->comp.status, __ATOMIC_ACQUIRE));
	/* Do not return through page-xfer cleanup while the descriptor may still
	 * reference its completion record or the raw arena.  Process exit closes
	 * the idxd user-WQ fds; the driver drains this PASID before unbinding SVA.
	 */
	_exit(CDP_DSA_COMPLETION_TIMEOUT_EXIT);
}

static int hot_fg_compare_complete(struct hot_fg_compare_slot *slot,
				   bool *complete, bool *equal, u32 *first_diff)
{
	uint8_t status = __atomic_load_n(&slot->comp.status, __ATOMIC_ACQUIRE);
	uint8_t code = (uint8_t)DSA_COMP_STATUS(status);

	*complete = false;
	if (status == 0 || code == DSA_COMP_NONE)
		return 0;
	if (code != DSA_COMP_SUCCESS && code != DSA_COMP_SUCCESS_PRED) {
		pr_err("DSA fine-grained compare wavefront completion failed status=%u code=%u\n",
		       status, code);
		return -1;
	}
	*complete = true;
	*equal = slot->comp.result == 0;
	if (*equal) {
		*first_diff = slot->submitted_len;
		return 0;
	}
	if (slot->comp.bytes_completed >= slot->submitted_len) {
		pr_err("DSA fine-grained compare wavefront returned invalid first_diff=%u bytes=%u\n",
		       slot->comp.bytes_completed, slot->submitted_len);
		return -1;
	}
	*first_diff = slot->comp.bytes_completed;
	return 0;
}

static int hot_fg_span_finalize(struct hot_fg_compare_span *span,
				struct hot_fg_raw_page *pages, u32 cursor)
{
	while (span->finalized_pages < span->page_count) {
		size_t page_idx = span->finalized_pages;
		struct hot_fg_raw_page *page = &pages[span->first_page + page_idx];

		if ((page_idx + 1) * PAGE_SIZE > cursor)
			break;
		if (page->state == HOT_FG_RAW_PENDING)
			page->state = page->patch_count ? HOT_FG_RAW_PATCH :
				HOT_FG_RAW_PARENT;
		else if (page->state != HOT_FG_RAW_FULL &&
			 page->state != HOT_FG_RAW_PATCH &&
			 page->state != HOT_FG_RAW_PARENT)
			return -1;
		span->finalized_pages++;
	}
	return 0;
}

static int hot_fg_span_record_diff(struct hot_fg_compare_span *span,
				  struct hot_fg_raw_page *pages, u32 diff)
{
	size_t page_idx;
	struct hot_fg_raw_page *page;
	u32 page_off;
	u32 patch_len;

	if (diff >= span->length || diff < span->cursor)
		return -1;
	if (hot_fg_span_finalize(span, pages, diff))
		return -1;

	page_idx = diff / PAGE_SIZE;
	page = &pages[span->first_page + page_idx];
	page_off = diff % PAGE_SIZE;
	patch_len = PAGE_SIZE - page_off;
	if (patch_len > DSA_FG_PATCH_SIZE)
		patch_len = DSA_FG_PATCH_SIZE;

	if (page->patch_count >= DSA_FG_MAX_PATCHES ||
	    page->patch_bytes + patch_len > DSA_FG_MAX_BYTES) {
		page->state = HOT_FG_RAW_FULL;
		span->cursor = (page_idx + 1) * PAGE_SIZE;
		return hot_fg_span_finalize(span, pages, span->cursor);
	}
	page->patches[page->patch_count].off = page_off;
	page->patches[page->patch_count].len = patch_len;
	page->patch_bytes += patch_len;
	page->patch_count++;
	span->cursor = diff + patch_len;
	return hot_fg_span_finalize(span, pages, span->cursor);
}

struct hot_fg_cpu_scan_stats {
	u64 memcmp_calls;
	u64 memcmp_requested_bytes;
	u64 memcmp_scalar_bytes;
	u64 scalar64_calls;
	u64 scalar64_word_ops;
	u64 scalar64_refine_bytes;
	u64 scalar64_tail_bytes;
	u64 scalar64_bytes_examined;
	u64 vector_ops;
	u64 bytes_examined;
};

static int (*volatile hot_fg_libc_memcmp)(const void *, const void *, size_t) = memcmp;

static noinline u32 __attribute__((optimize("no-tree-vectorize")))
hot_fg_scalar_first_diff(const unsigned char *raw,
			 const unsigned char *parent, u32 length)
{
	u32 cursor;

	for (cursor = 0; cursor < length; cursor++) {
		if (raw[cursor] != parent[cursor])
			return cursor;
	}
	return length;
}

static int hot_fg_memcmp_first_diff(const unsigned char *raw,
				    const unsigned char *parent, u32 length,
				    bool *equal, u32 *first_diff,
				    struct hot_fg_cpu_scan_stats *stats)
{
	u32 diff;

	if (stats) {
		stats->memcmp_calls++;
		stats->memcmp_requested_bytes += length;
	}
	if (hot_fg_libc_memcmp(raw, parent, length) == 0) {
		*equal = true;
		*first_diff = length;
		return 0;
	}

	diff = hot_fg_scalar_first_diff(raw, parent, length);
	if (diff >= length) {
		pr_err("DSA fine-grained memcmp backend couldn't recover first difference\n");
		return -1;
	}
	if (stats)
		stats->memcmp_scalar_bytes += diff + 1;
	*equal = false;
	*first_diff = diff;
	return 0;
}

static noinline int __attribute__((optimize("no-tree-vectorize", "no-tree-slp-vectorize")))
hot_fg_scalar64_first_diff(const unsigned char *raw,
			   const unsigned char *parent, u32 length,
			   bool *equal, u32 *first_diff,
			   struct hot_fg_cpu_scan_stats *stats)
{
	u32 cursor = 0;
	u32 word_region = length & ~((u32)sizeof(u64) - 1);

	while (length - cursor >= sizeof(u64)) {
		u64 raw_word;
		u64 parent_word;
		u32 byte;

		/* memcpy keeps unaligned accesses and aliasing valid.  With the
		 * vectorizers disabled, x86-64 lowers these to ordinary GPR loads. */
		memcpy(&raw_word, raw + cursor, sizeof(raw_word));
		memcpy(&parent_word, parent + cursor, sizeof(parent_word));
		if ((raw_word ^ parent_word) == 0) {
			cursor += sizeof(u64);
			continue;
		}

		/* Refine by address order rather than ctz so this remains correct
		 * independently of host byte order. */
		for (byte = 0; byte < sizeof(u64); byte++) {
			if (raw[cursor + byte] != parent[cursor + byte]) {
				*equal = false;
				*first_diff = cursor + byte;
				goto account;
			}
		}
		pr_err("DSA fine-grained scalar64 backend couldn't refine unequal word\n");
		return -1;
	}

	while (cursor < length) {
		if (raw[cursor] != parent[cursor]) {
			*equal = false;
			*first_diff = cursor;
			goto account;
		}
		cursor++;
	}
	*equal = true;
	*first_diff = length;

account:
	/* Derive the profile geometry once per first-diff call.  Keeping all
	 * counters out of the 8-byte loop makes profile mode low disturbance. */
	if (stats) {
		u64 word_ops;
		u64 refine_bytes = 0;
		u64 tail_bytes = 0;

		if (*equal) {
			word_ops = length / sizeof(u64);
			tail_bytes = length - word_region;
		} else if (*first_diff < word_region) {
			word_ops = *first_diff / sizeof(u64) + 1;
			refine_bytes = *first_diff % sizeof(u64) + 1;
		} else {
			word_ops = length / sizeof(u64);
			tail_bytes = *first_diff - word_region + 1;
		}
		stats->scalar64_calls++;
		stats->scalar64_word_ops += word_ops;
		stats->scalar64_refine_bytes += refine_bytes;
		stats->scalar64_tail_bytes += tail_bytes;
		stats->scalar64_bytes_examined += word_ops * sizeof(u64) +
			refine_bytes + tail_bytes;
	}
	return 0;
}

#ifdef HOT_FG_HAVE_X86_SIMD
static void hot_fg_account_simd_scan(struct hot_fg_cpu_scan_stats *stats,
				     u32 length, bool equal, u32 first_diff,
				     u32 vector_bytes)
{
	u32 vector_region;
	u64 vector_ops;
	u64 tail_bytes = 0;

	if (!stats)
		return;
	vector_region = length - length % vector_bytes;
	if (equal) {
		vector_ops = length / vector_bytes;
		tail_bytes = length - vector_region;
	} else if (first_diff < vector_region) {
		vector_ops = first_diff / vector_bytes + 1;
	} else {
		vector_ops = length / vector_bytes;
		tail_bytes = first_diff - vector_region + 1;
	}
	stats->vector_ops += vector_ops;
	stats->bytes_examined += vector_ops * vector_bytes + tail_bytes;
}

static int __attribute__((target("avx2")))
hot_fg_simd_avx2_first_diff(const unsigned char *raw,
			    const unsigned char *parent, u32 length,
			    bool *equal, u32 *first_diff,
			    struct hot_fg_cpu_scan_stats *stats)
{
	u32 cursor = 0;

	while (cursor + 32 <= length) {
		__m256i raw_v = _mm256_loadu_si256((const __m256i *)(raw + cursor));
		__m256i parent_v = _mm256_loadu_si256((const __m256i *)(parent + cursor));
		u32 equal_mask = (u32)_mm256_movemask_epi8(_mm256_cmpeq_epi8(raw_v, parent_v));

		if (equal_mask != UINT32_MAX) {
			*equal = false;
			*first_diff = cursor + (u32)__builtin_ctz(~equal_mask);
			goto account;
		}
		cursor += 32;
	}
	while (cursor < length) {
		if (raw[cursor] != parent[cursor]) {
			*equal = false;
			*first_diff = cursor;
			goto account;
		}
		cursor++;
	}
	*equal = true;
	*first_diff = length;

account:
	hot_fg_account_simd_scan(stats, length, *equal, *first_diff, 32);
	return 0;
}

static int __attribute__((target("avx512f,avx512bw,avx512vl")))
hot_fg_simd_avx512_first_diff(const unsigned char *raw,
			      const unsigned char *parent, u32 length,
			      bool *equal, u32 *first_diff,
			      struct hot_fg_cpu_scan_stats *stats)
{
	u32 cursor = 0;

	while (cursor + 64 <= length) {
		__m512i raw_v = _mm512_loadu_si512((const void *)(raw + cursor));
		__m512i parent_v = _mm512_loadu_si512((const void *)(parent + cursor));
		__mmask64 equal_mask = _mm512_cmpeq_epi8_mask(raw_v, parent_v);

		if (equal_mask != ~(__mmask64)0) {
			*equal = false;
			*first_diff = cursor + (u32)__builtin_ctzll((u64)~equal_mask);
			goto account;
		}
		cursor += 64;
	}
	while (cursor < length) {
		if (raw[cursor] != parent[cursor]) {
			*equal = false;
			*first_diff = cursor;
			goto account;
		}
		cursor++;
	}
	*equal = true;
	*first_diff = length;

account:
	hot_fg_account_simd_scan(stats, length, *equal, *first_diff, 64);
	return 0;
}
#endif

static int hot_fg_cpu_first_diff(enum hot_fg_compare_backend backend,
				 const unsigned char *raw,
				 const unsigned char *parent, u32 length,
				 bool *equal, u32 *first_diff,
				 struct hot_fg_cpu_scan_stats *stats)
{
	if (!raw || !parent || !length || !equal || !first_diff)
		return -1;

	if (backend == HOT_FG_COMPARE_MEMCMP)
		return hot_fg_memcmp_first_diff(raw, parent, length, equal,
					       first_diff, stats);
	if (backend == HOT_FG_COMPARE_SCALAR64)
		return hot_fg_scalar64_first_diff(raw, parent, length, equal,
						 first_diff, stats);

#ifdef HOT_FG_HAVE_X86_SIMD
	if (backend == HOT_FG_COMPARE_SIMD_AVX2)
		return hot_fg_simd_avx2_first_diff(raw, parent, length, equal,
					  first_diff, stats);
	if (backend == HOT_FG_COMPARE_SIMD_AVX512 ||
	    backend == HOT_FG_COMPARE_VALIDATE)
		return hot_fg_simd_avx512_first_diff(raw, parent, length, equal,
					    first_diff, stats);
#else
	(void)backend;
	(void)stats;
#endif

	pr_err("DSA fine-grained CPU compare backend is unavailable\n");
	return -1;
}

static int hot_fg_prefault_all(struct hot_apply_ctx *ctx,
			       struct hot_fg_compare_span *spans, size_t nr_spans)
{
	size_t i;

	for (i = 0; i < nr_spans; i++) {
		struct hot_fg_compare_span *span = &spans[i];

		if (!span->parent || !span->length || span->length % PAGE_SIZE ||
		    span->state != HOT_FG_SPAN_UNPREFAULTED) {
			pr_err("DSA compare breakdown has invalid prefault span=%zu state=%u length=%u\n",
			       i, span->state, span->length);
			return -1;
		}
		hot_dsa_prefault_range((void *)span->parent, span->length, false);
		span->state = HOT_FG_SPAN_READY;
		if (ctx->profile) {
			ctx->profile_prefault_spans++;
			ctx->profile_prefault_pages += span->length / PAGE_SIZE;
		}
	}
	return 0;
}

static int hot_fg_compare_cpu(struct hot_apply_ctx *ctx,
			      struct hot_fg_raw_page *pages,
			      struct hot_fg_compare_span *spans, size_t nr_spans,
			      enum hot_fg_compare_backend backend,
			      bool record_profile)
{
	struct hot_fg_cpu_scan_stats stats = {};
	size_t i;

	for (i = 0; i < nr_spans; i++) {
		struct hot_fg_compare_span *span = &spans[i];

		if (!span->parent || !span->length || span->length % PAGE_SIZE ||
		    (span->state != HOT_FG_SPAN_UNPREFAULTED &&
		     !(ctx->compare_breakdown && span->state == HOT_FG_SPAN_READY))) {
			pr_err("DSA fine-grained CPU compare has invalid backend=%s span=%zu state=%u length=%u\n",
			       hot_fg_compare_backend_name(backend), i,
			       span->state, span->length);
			return -1;
		}
		if (span->state == HOT_FG_SPAN_UNPREFAULTED) {
			hot_dsa_prefault_range((void *)span->parent, span->length, false);
			if (record_profile && ctx->profile) {
				ctx->profile_prefault_spans++;
				ctx->profile_prefault_pages += span->length / PAGE_SIZE;
			}
		}
		span->state = HOT_FG_SPAN_ACTIVE;
		while (span->cursor < span->length) {
			bool equal;
			u32 diff;

			if (hot_fg_cpu_first_diff(backend, span->raw + span->cursor,
						  span->parent + span->cursor,
						  span->length - span->cursor, &equal, &diff,
						  record_profile && ctx->profile ? &stats : NULL))
				return -1;
			if (equal) {
				span->cursor = span->length;
				if (hot_fg_span_finalize(span, pages, span->cursor))
					return -1;
				break;
			}
			if (hot_fg_span_record_diff(span, pages, span->cursor + diff))
				return -1;
		}
		if (span->cursor != span->length ||
		    hot_fg_span_finalize(span, pages, span->length) ||
		    span->finalized_pages != span->page_count) {
			pr_err("DSA fine-grained CPU compare backend=%s span ended with unfinished pages\n",
			       hot_fg_compare_backend_name(backend));
			return -1;
		}
		span->state = HOT_FG_SPAN_DONE;
	}

	if (record_profile && ctx->profile) {
		ctx->profile_memcmp_calls += stats.memcmp_calls;
		ctx->profile_memcmp_requested_bytes += stats.memcmp_requested_bytes;
		ctx->profile_memcmp_scalar_bytes += stats.memcmp_scalar_bytes;
		ctx->profile_scalar64_calls += stats.scalar64_calls;
		ctx->profile_scalar64_word_ops += stats.scalar64_word_ops;
		ctx->profile_scalar64_refine_bytes += stats.scalar64_refine_bytes;
		ctx->profile_scalar64_tail_bytes += stats.scalar64_tail_bytes;
		ctx->profile_scalar64_bytes_examined += stats.scalar64_bytes_examined;
		ctx->profile_simd_vector_ops += stats.vector_ops;
		ctx->profile_simd_bytes_examined += stats.bytes_examined;
	}
	return 0;
}

static int hot_fg_validate_compare_metadata(const struct hot_fg_raw_page *dsa_pages,
					    const struct hot_fg_raw_page *simd_pages,
					    size_t nr_pages,
					    const struct hot_fg_compare_span *dsa_spans,
					    const struct hot_fg_compare_span *simd_spans,
					    size_t nr_spans)
{
	size_t i;

	for (i = 0; i < nr_pages; i++) {
		const struct hot_fg_raw_page *dsa = &dsa_pages[i];
		const struct hot_fg_raw_page *simd = &simd_pages[i];

		if (dsa->state != simd->state || dsa->cursor != simd->cursor ||
		    dsa->patch_bytes != simd->patch_bytes ||
		    dsa->patch_count != simd->patch_count ||
		    memcmp(dsa->patches, simd->patches,
			   dsa->patch_count * sizeof(dsa->patches[0]))) {
			pr_err("DSA fine-grained validate page metadata mismatch page=%zu vaddr=%lx dsa_state=%u simd_state=%u dsa_ranges=%u simd_ranges=%u\n",
			       i, dsa->vaddr, dsa->state, simd->state,
			       dsa->patch_count, simd->patch_count);
			return -1;
		}
	}
	for (i = 0; i < nr_spans; i++) {
		const struct hot_fg_compare_span *dsa = &dsa_spans[i];
		const struct hot_fg_compare_span *simd = &simd_spans[i];

		if (dsa->cursor != simd->cursor ||
		    dsa->finalized_pages != simd->finalized_pages ||
		    dsa->state != simd->state) {
			pr_err("DSA fine-grained validate span metadata mismatch span=%zu dsa_cursor=%u simd_cursor=%u dsa_state=%u simd_state=%u\n",
			       i, dsa->cursor, simd->cursor, dsa->state, simd->state);
			return -1;
		}
	}
	return 0;
}

static int hot_fg_wavefront_prefault(struct hot_apply_ctx *ctx,
				     struct hot_fg_ready_queue *ready,
				     size_t *next_unprefaulted,
				     size_t active)
{
	while (active + ready->nr < HOT_DSA_COMPARE_INFLIGHT &&
	       *next_unprefaulted < ready->capacity) {
		size_t span_idx = (*next_unprefaulted)++;
		struct hot_fg_compare_span *span = &ready->spans[span_idx];

		if (span->state != HOT_FG_SPAN_UNPREFAULTED) {
			pr_err("DSA fine-grained compare invalid prefault state=%u span=%zu\n",
			       span->state, span_idx);
			return -1;
		}
		hot_dsa_prefault_range((void *)span->parent, span->length, false);
		if (ctx->profile) {
			ctx->profile_prefault_spans++;
			ctx->profile_prefault_pages += span->length / PAGE_SIZE;
		}
		span->state = HOT_FG_SPAN_READY;
		if (hot_fg_ready_queue_push(ready, span_idx)) {
			pr_err("DSA fine-grained compare ready queue push failed span=%zu\n",
			       span_idx);
			return -1;
		}
	}
	return 0;
}

static int hot_fg_wavefront_fill(struct hot_apply_ctx *ctx,
				 struct hot_fg_compare_slot *slots,
				 struct hot_fg_ready_queue *ready,
				 size_t *active, u64 *submit_sequence,
				 u64 submit_ns)
{
	size_t i;

	for (i = 0; i < HOT_DSA_COMPARE_INFLIGHT &&
	     *active < HOT_DSA_COMPARE_INFLIGHT; i++) {
		struct hot_fg_compare_span *span;
		size_t span_idx;

		if (slots[i].active)
			continue;
		if (!ready->nr)
			break;
		if (hot_fg_ready_queue_pop(ready, &span_idx)) {
			return -1;
		}
		span = &ready->spans[span_idx];
		if (span->state != HOT_FG_SPAN_READY) {
			pr_err("DSA fine-grained compare ready queue state=%u span=%zu\n",
			       span->state, span_idx);
			return -1;
		}
		if (hot_fg_compare_submit(ctx, &slots[i], span,
					  ++*submit_sequence, submit_ns))
			return -1;
		(*active)++;
	}
	return 0;
}

static int hot_fg_wavefront_drain_slots(struct hot_fg_compare_slot *slots,
					 size_t *active)
{
	u64 sweeps = 0;

	while (*active) {
		size_t i;
		bool progress = false;

		for (i = 0; i < HOT_DSA_COMPARE_INFLIGHT; i++) {
			if (!slots[i].active ||
			    __atomic_load_n(&slots[i].comp.status, __ATOMIC_ACQUIRE) == 0)
				continue;
			slots[i].active = false;
			(*active)--;
			progress = true;
		}
		if (!*active)
			return 0;
		if (!progress && (++sweeps & 0xfffULL) == 0) {
			u64 now_ns = hot_dsa_watchdog_now_ns();

			for (i = 0; i < HOT_DSA_COMPARE_INFLIGHT; i++) {
				if (!slots[i].active)
					continue;
				if (!now_ns)
					hot_fg_completion_timeout_fatal(&slots[i], *active,
						slots[i].completion_deadline_ns,
						"error-drain-clock");
				if (now_ns >= slots[i].completion_deadline_ns)
					hot_fg_completion_timeout_fatal(&slots[i], *active,
						now_ns, "error-drain");
			}
		}
		hot_dsa_cpu_relax();
	}
	return 0;
}

static int hot_fg_compare_wavefront(struct hot_apply_ctx *ctx,
				    struct hot_fg_raw_page *pages,
				    struct hot_fg_compare_span *spans, size_t nr_spans)
{
	struct hot_fg_compare_slot slots[HOT_DSA_COMPARE_INFLIGHT] = {};
	struct hot_fg_ready_queue ready;
	size_t next_unprefaulted = 0;
	size_t done = 0;
	size_t active = 0;
	u64 submit_sequence = 0;
	size_t i;
	int ret = -1;

	if (!nr_spans)
		return 0;
	if (hot_fg_ready_queue_init(&ready, spans, nr_spans))
		return -1;
	if (ctx->compare_breakdown) {
		for (i = 0; i < nr_spans; i++) {
			if (spans[i].state != HOT_FG_SPAN_READY ||
			    hot_fg_ready_queue_push(&ready, i)) {
				pr_err("DSA compare breakdown has non-ready span=%zu state=%u\n",
				       i, spans[i].state);
				goto out;
			}
		}
		next_unprefaulted = nr_spans;
	}

	while (done < nr_spans) {
		u64 now_ns = hot_dsa_watchdog_now_ns();
		struct hot_fg_compare_slot *expired_slot = NULL;
		size_t harvested = 0;
		bool had_active = active != 0;

		if (!now_ns) {
			if (active) {
				for (i = 0; i < HOT_DSA_COMPARE_INFLIGHT; i++) {
					if (slots[i].active)
						hot_fg_completion_timeout_fatal(&slots[i], active,
							slots[i].completion_deadline_ns,
							"scheduler-clock");
				}
			}
			pr_perror("DSA fine-grained completion watchdog clock failed");
			goto out;
		}
		if (had_active && ctx->profile) {
			ctx->profile_compare_poll_sweeps++;
			if (active > ctx->profile_compare_max_active)
				ctx->profile_compare_max_active = active;
		}

		for (i = 0; i < HOT_DSA_COMPARE_INFLIGHT; i++) {
			struct hot_fg_compare_slot *slot = &slots[i];
			struct hot_fg_compare_span *span;
			bool complete, equal;
			u32 diff;

			if (!slot->active)
				continue;
			if (hot_fg_compare_complete(slot, &complete, &equal, &diff)) {
				/* A non-zero status means DMA to this completion record is over,
				 * even when the operation itself failed. */
				if (__atomic_load_n(&slot->comp.status, __ATOMIC_ACQUIRE)) {
					slot->active = false;
					active--;
				}
				goto out;
			}
			if (!complete) {
				if (ctx->profile)
					ctx->profile_compare_not_ready++;
				if (!expired_slot && now_ns >= slot->completion_deadline_ns)
					expired_slot = slot;
				continue;
			}
			span = slot->span;
			if (!span || span->state != HOT_FG_SPAN_ACTIVE ||
			    slot->submitted_cursor != span->cursor) {
				pr_err("DSA fine-grained compare span completion has stale cursor\n");
				slot->active = false;
				active--;
				goto out;
			}
			slot->active = false;
			active--;
			harvested++;
			if (ctx->profile && now_ns >= slot->submit_ns) {
				u64 age_us = (now_ns - slot->submit_ns) / 1000ULL;

				if (age_us > ctx->profile_max_completion_age_us)
					ctx->profile_max_completion_age_us = age_us;
			}
			if (equal) {
				span->cursor += slot->submitted_len;
				if (hot_fg_span_finalize(span, pages, span->cursor))
					goto out;
			} else {
				diff += slot->submitted_cursor;
				if (hot_fg_span_record_diff(span, pages, diff))
					goto out;
			}
			if (span->cursor == span->length) {
				if (hot_fg_span_finalize(span, pages, span->length))
					goto out;
				if (span->finalized_pages != span->page_count) {
					pr_err("DSA fine-grained compare span ended with unfinished pages\n");
					goto out;
				}
				span->state = HOT_FG_SPAN_DONE;
				done++;
			} else {
				span->state = HOT_FG_SPAN_READY;
				if (hot_fg_ready_queue_push(&ready,
							(size_t)(span - spans))) {
					pr_err("DSA fine-grained compare ready queue overflow\n");
					goto out;
				}
			}
		}

		/* All visible completions are harvested before an expired ACTIVE slot
		 * is declared stuck.  This prevents a delayed scheduler return
		 * from turning an already completed descriptor into a false timeout. */
		if (expired_slot &&
		    __atomic_load_n(&expired_slot->comp.status, __ATOMIC_ACQUIRE) == 0) {
			if (ctx->profile)
				ctx->profile_completion_timeout_count++;
			hot_fg_completion_timeout_fatal(expired_slot, active, now_ns,
						"compare");
		}

		if (had_active && ctx->profile)
			ctx->profile_completions_harvested += harvested;

		if (hot_fg_wavefront_fill(ctx, slots, &ready, &active,
					  &submit_sequence, now_ns) ||
		    hot_fg_wavefront_prefault(ctx, &ready, &next_unprefaulted,
					      active))
			goto out;
		/* Prefault may block on residency work.  Timestamp the descriptors
		 * created from that new READY batch after prefault, not before it. */
		if (ready.nr && active < HOT_DSA_COMPARE_INFLIGHT) {
			u64 refill_ns = hot_dsa_watchdog_now_ns();

			if (!refill_ns) {
				if (active) {
					for (i = 0; i < HOT_DSA_COMPARE_INFLIGHT; i++) {
						if (slots[i].active)
							hot_fg_completion_timeout_fatal(&slots[i], active,
								slots[i].completion_deadline_ns,
								"refill-clock");
					}
				}
				pr_perror("DSA fine-grained refill watchdog clock failed");
				goto out;
			}
			if (hot_fg_wavefront_fill(ctx, slots, &ready, &active,
						  &submit_sequence, refill_ns))
				goto out;
		}
		if (!active && done < nr_spans) {
			pr_err("DSA fine-grained compare lost pending descriptors done=%zu ready=%zu next=%zu total=%zu\n",
			       done, ready.nr, next_unprefaulted, nr_spans);
			goto out;
		}
		if (active)
			hot_dsa_cpu_relax();
	}
	ret = 0;
out:
	if (active && hot_fg_wavefront_drain_slots(slots, &active))
		ret = -1;
	hot_fg_ready_queue_fini(&ready);
	return ret;
}

static int hot_fg_hybrid_validate_spans(struct hot_fg_raw_page *pages,
					struct hot_fg_compare_span *spans,
					size_t nr_spans)
{
	unsigned long previous_vaddr = 0;
	bool have_previous = false;
	size_t i;

	for (i = 0; i < nr_spans; i++) {
		struct hot_fg_compare_span *span = &spans[i];
		unsigned long vaddr = pages[span->first_page].vaddr;

		if (!span->parent || !span->length || !span->page_count ||
		    span->length % PAGE_SIZE ||
		    span->length / PAGE_SIZE != span->page_count ||
		    span->state != HOT_FG_SPAN_UNPREFAULTED ||
		    span->owner != HOT_FG_OWNER_NONE) {
			pr_err("DSA hybrid-demand has invalid initial span=%zu owner=%u state=%u length=%u\n",
			       i, span->owner, span->state, span->length);
			return -1;
		}
		if (have_previous && vaddr <= previous_vaddr) {
			pr_err("DSA hybrid-demand spans are not strictly ordered: previous=%lx current=%lx\n",
			       previous_vaddr, vaddr);
			return -1;
		}
		previous_vaddr = vaddr;
		have_previous = true;
	}
	return 0;
}

static int hot_fg_hybrid_claim_cpu(struct hot_apply_ctx *ctx,
				   struct hot_fg_compare_span *spans,
				   size_t *unclaimed_head,
				   size_t unclaimed_tail,
				   size_t *cpu_current)
{
	struct hot_fg_compare_span *span;
	size_t span_idx;

	if (*cpu_current != SIZE_MAX)
		return 0;
	if (*unclaimed_head >= unclaimed_tail)
		return 1;

	span_idx = (*unclaimed_head)++;
	span = &spans[span_idx];
	if (span->owner != HOT_FG_OWNER_NONE ||
	    span->state != HOT_FG_SPAN_UNPREFAULTED) {
		pr_err("DSA hybrid-demand CPU claim has invalid span=%zu owner=%u state=%u\n",
		       span_idx, span->owner, span->state);
		return -1;
	}
	span->owner = HOT_FG_OWNER_CPU;
	span->state = HOT_FG_SPAN_READY;
	*cpu_current = span_idx;
	if (ctx->profile) {
		ctx->profile_hybrid_cpu_claim_spans++;
		ctx->profile_hybrid_cpu_claim_pages += span->page_count;
	}
	return 0;
}

static int hot_fg_hybrid_fill_dsa(struct hot_apply_ctx *ctx,
				  struct hot_fg_compare_slot *slots,
				  struct hot_fg_compare_span *spans,
				  struct hot_fg_ready_queue *dsa_ready,
				  size_t unclaimed_head,
				  size_t *unclaimed_tail,
				  size_t *active,
				  u64 *submit_sequence, u64 submit_ns)
{
	size_t i;

	/* Already-started first-difference chains always retain priority. */
	if (hot_fg_wavefront_fill(ctx, slots, dsa_ready, active,
				  submit_sequence, submit_ns))
		return -1;

	/* A new span leaves the shared deque only when a free slot can submit it
	 * immediately.  There is no private backlog of unstarted DSA work. */
	for (i = 0; i < HOT_DSA_COMPARE_INFLIGHT &&
	     *active < HOT_DSA_COMPARE_INFLIGHT &&
	     unclaimed_head < *unclaimed_tail; i++) {
		struct hot_fg_compare_span *span;
		size_t span_idx;

		if (slots[i].active)
			continue;
		span_idx = --*unclaimed_tail;
		span = &spans[span_idx];
		if (span->owner != HOT_FG_OWNER_NONE ||
		    span->state != HOT_FG_SPAN_UNPREFAULTED) {
			pr_err("DSA hybrid-demand DSA claim has invalid span=%zu owner=%u state=%u\n",
			       span_idx, span->owner, span->state);
			return -1;
		}
		span->owner = HOT_FG_OWNER_DSA;
		span->state = HOT_FG_SPAN_READY;
		if (ctx->profile) {
			ctx->profile_hybrid_dsa_claim_spans++;
			ctx->profile_hybrid_dsa_claim_pages += span->page_count;
		}
		if (hot_fg_compare_submit(ctx, &slots[i], span,
					  ++*submit_sequence, submit_ns))
			return -1;
		(*active)++;
	}
	return 0;
}

static int hot_fg_hybrid_tail_handoff(struct hot_apply_ctx *ctx,
				      struct hot_fg_compare_span *spans,
				      struct hot_fg_ready_queue *dsa_ready,
				      size_t unclaimed_head,
				      size_t unclaimed_tail,
				      size_t *cpu_current)
{
	struct hot_fg_compare_span *span;
	size_t span_idx;

	if (*cpu_current != SIZE_MAX ||
	    unclaimed_head != unclaimed_tail ||
	    !dsa_ready->nr)
		return 0;
	if (hot_fg_ready_queue_pop(dsa_ready, &span_idx))
		return -1;
	span = &spans[span_idx];
	if (span->owner != HOT_FG_OWNER_DSA ||
	    span->state != HOT_FG_SPAN_READY ||
	    span->cursor >= span->length) {
		pr_err("DSA hybrid-demand tail handoff has invalid span=%zu owner=%u state=%u cursor=%u length=%u\n",
		       span_idx, span->owner, span->state, span->cursor, span->length);
		return -1;
	}
	span->owner = HOT_FG_OWNER_CPU;
	*cpu_current = span_idx;
	if (ctx->profile) {
		ctx->profile_hybrid_dsa_to_cpu_handoff_spans++;
		ctx->profile_hybrid_dsa_to_cpu_handoff_pages +=
			span->page_count - span->finalized_pages;
		ctx->profile_hybrid_dsa_to_cpu_handoff_remaining_bytes +=
			span->length - span->cursor;
	}
	return 0;
}

static int hot_fg_hybrid_cpu_page(struct hot_apply_ctx *ctx,
				  struct hot_fg_raw_page *pages,
				  struct hot_fg_compare_span *spans,
				  size_t *cpu_current,
				  struct hot_fg_cpu_scan_stats *stats,
				  bool *span_done)
{
	struct hot_fg_compare_span *span;
	size_t span_idx;
	u32 page_end;

	*span_done = false;
	if (*cpu_current == SIZE_MAX)
		return -1;
	span_idx = *cpu_current;
	span = &spans[span_idx];
	if (span->owner != HOT_FG_OWNER_CPU ||
	    span->state != HOT_FG_SPAN_READY ||
	    span->cursor >= span->length) {
		pr_err("DSA hybrid-demand has invalid CPU span=%zu owner=%u state=%u cursor=%u length=%u\n",
		       span_idx, span->owner, span->state, span->cursor, span->length);
		return -1;
	}

	/* One page is the non-preemptible SIMD quantum.  The first load on a
	 * newly claimed CPU span intentionally services its normal demand fault. */
	page_end = (span->cursor & ~(PAGE_SIZE - 1)) + PAGE_SIZE;
	if (page_end > span->length)
		page_end = span->length;
	span->state = HOT_FG_SPAN_ACTIVE;
	while (span->cursor < page_end) {
		bool equal;
		u32 diff;
		u32 length = page_end - span->cursor;

		if (hot_fg_cpu_first_diff(HOT_FG_COMPARE_SIMD_AVX512,
					  span->raw + span->cursor,
					  span->parent + span->cursor,
					  length, &equal, &diff,
					  ctx->profile ? stats : NULL))
			return -1;
		if (equal) {
			span->cursor = page_end;
			if (hot_fg_span_finalize(span, pages, span->cursor))
				return -1;
			break;
		}
		if (hot_fg_span_record_diff(span, pages, span->cursor + diff))
			return -1;
	}
	if (ctx->profile)
		ctx->profile_hybrid_cpu_waves++;

	if (span->cursor == span->length) {
		if (hot_fg_span_finalize(span, pages, span->length) ||
		    span->finalized_pages != span->page_count) {
			pr_err("DSA hybrid-demand CPU span=%zu ended with unfinished pages\n",
			       span_idx);
			return -1;
		}
		span->state = HOT_FG_SPAN_DONE;
		*cpu_current = SIZE_MAX;
		*span_done = true;
		return 0;
	}
	span->state = HOT_FG_SPAN_READY;
	return 0;
}

static int hot_fg_compare_hybrid_demand(struct hot_apply_ctx *ctx,
					struct hot_fg_raw_page *pages,
					struct hot_fg_compare_span *spans,
					size_t nr_spans)
{
	struct hot_fg_compare_slot slots[HOT_DSA_COMPARE_INFLIGHT] = {};
	struct hot_fg_ready_queue dsa_ready;
	struct hot_fg_cpu_scan_stats cpu_stats = {};
	size_t unclaimed_head = 0;
	size_t unclaimed_tail = nr_spans;
	size_t cpu_current = SIZE_MAX;
	size_t done = 0;
	size_t active = 0;
	u64 submit_sequence = 0;
	bool unclaimed_empty_seen = false;
	size_t i;
	int ret = -1;

	if (!nr_spans)
		return 0;
	if (hot_fg_hybrid_validate_spans(pages, spans, nr_spans))
		return -1;
	if (hot_fg_ready_queue_init(&dsa_ready, spans, nr_spans))
		return -1;

	while (done < nr_spans) {
		u64 now_ns;
		struct hot_fg_compare_slot *expired_slot = NULL;
		size_t harvested = 0;
		bool had_active;

		/* Once all device work and shared work are exhausted, finish the one
		 * CPU-owned span without a watchdog clock read per 4-KiB quantum. */
		if (!active && !dsa_ready.nr &&
		    unclaimed_head == unclaimed_tail &&
		    cpu_current != SIZE_MAX) {
			bool cpu_done;

			if (hot_fg_hybrid_cpu_page(ctx, pages, spans, &cpu_current,
						   &cpu_stats, &cpu_done))
				goto out;
			if (cpu_done)
				done++;
			continue;
		}

		now_ns = hot_dsa_watchdog_now_ns();
		had_active = active != 0;
		if (!now_ns) {
			if (active) {
				for (i = 0; i < HOT_DSA_COMPARE_INFLIGHT; i++) {
					if (slots[i].active)
						hot_fg_completion_timeout_fatal(&slots[i], active,
							slots[i].completion_deadline_ns,
							"hybrid-scheduler-clock");
				}
			}
			pr_perror("DSA hybrid-demand completion watchdog clock failed");
			goto out;
		}
		if (had_active && ctx->profile) {
			ctx->profile_compare_poll_sweeps++;
			if (active > ctx->profile_compare_max_active)
				ctx->profile_compare_max_active = active;
		}

		for (i = 0; i < HOT_DSA_COMPARE_INFLIGHT; i++) {
			struct hot_fg_compare_slot *slot = &slots[i];
			struct hot_fg_compare_span *span;
			bool complete, equal;
			u32 diff;

			if (!slot->active)
				continue;
			if (hot_fg_compare_complete(slot, &complete, &equal, &diff)) {
				if (__atomic_load_n(&slot->comp.status, __ATOMIC_ACQUIRE)) {
					slot->active = false;
					active--;
				}
				goto out;
			}
			if (!complete) {
				if (ctx->profile)
					ctx->profile_compare_not_ready++;
				if (!expired_slot && now_ns >= slot->completion_deadline_ns)
					expired_slot = slot;
				continue;
			}
			span = slot->span;
			if (!span || span->owner != HOT_FG_OWNER_DSA ||
			    span->state != HOT_FG_SPAN_ACTIVE ||
			    slot->submitted_cursor != span->cursor) {
				pr_err("DSA hybrid-demand completion has stale span/cursor\n");
				slot->active = false;
				active--;
				goto out;
			}
			slot->active = false;
			active--;
			harvested++;
			if (ctx->profile && now_ns >= slot->submit_ns) {
				u64 age_us = (now_ns - slot->submit_ns) / 1000ULL;

				if (age_us > ctx->profile_max_completion_age_us)
					ctx->profile_max_completion_age_us = age_us;
			}
			if (equal) {
				span->cursor += slot->submitted_len;
				if (hot_fg_span_finalize(span, pages, span->cursor))
					goto out;
			} else {
				diff += slot->submitted_cursor;
				if (hot_fg_span_record_diff(span, pages, diff))
					goto out;
			}
			if (span->cursor == span->length) {
				if (hot_fg_span_finalize(span, pages, span->length) ||
				    span->finalized_pages != span->page_count) {
					pr_err("DSA hybrid-demand DSA span ended with unfinished pages\n");
					goto out;
				}
				span->state = HOT_FG_SPAN_DONE;
				done++;
			} else {
				span->state = HOT_FG_SPAN_READY;
				if (hot_fg_ready_queue_push(&dsa_ready,
							    (size_t)(span - spans))) {
					pr_err("DSA hybrid-demand DSA continuation queue overflow\n");
					goto out;
				}
			}
		}

		if (expired_slot &&
		    __atomic_load_n(&expired_slot->comp.status, __ATOMIC_ACQUIRE) == 0) {
			if (ctx->profile)
				ctx->profile_completion_timeout_count++;
			hot_fg_completion_timeout_fatal(expired_slot, active, now_ns,
						"hybrid-compare");
		}
		if (had_active && ctx->profile)
			ctx->profile_completions_harvested += harvested;

		/* CPU gets first refusal on the low-address end.  DSA then consumes
		 * the high-address end only as free slots submit work immediately. */
		if (cpu_current == SIZE_MAX && unclaimed_head < unclaimed_tail) {
			int claim = hot_fg_hybrid_claim_cpu(ctx, spans,
							  &unclaimed_head,
							  unclaimed_tail,
							  &cpu_current);

			if (claim < 0)
				goto out;
		}
		if (unclaimed_head == unclaimed_tail && !unclaimed_empty_seen) {
			unclaimed_empty_seen = true;
			if (ctx->profile)
				ctx->profile_hybrid_unclaimed_empty_count++;
		}
		if (hot_fg_hybrid_tail_handoff(ctx, spans, &dsa_ready,
					       unclaimed_head, unclaimed_tail,
					       &cpu_current))
			goto out;
		if (hot_fg_hybrid_fill_dsa(ctx, slots, spans, &dsa_ready,
					   unclaimed_head, &unclaimed_tail,
					   &active, &submit_sequence, now_ns))
			goto out;
		if (unclaimed_head == unclaimed_tail && !unclaimed_empty_seen) {
			unclaimed_empty_seen = true;
			if (ctx->profile)
				ctx->profile_hybrid_unclaimed_empty_count++;
		}

		if (cpu_current != SIZE_MAX) {
			bool cpu_done;

			if (hot_fg_hybrid_cpu_page(ctx, pages, spans, &cpu_current,
						   &cpu_stats, &cpu_done))
				goto out;
			if (cpu_done)
				done++;
		}

		if (!active && !dsa_ready.nr &&
		    cpu_current == SIZE_MAX &&
		    unclaimed_head == unclaimed_tail &&
		    done < nr_spans) {
			pr_err("DSA hybrid-demand lost work done=%zu total=%zu\n",
			       done, nr_spans);
			goto out;
		}
		if (active && cpu_current == SIZE_MAX)
			hot_dsa_cpu_relax();
	}

	if (unclaimed_head != unclaimed_tail ||
	    cpu_current != SIZE_MAX || dsa_ready.nr || active) {
		pr_err("DSA hybrid-demand ended with live work head=%zu tail=%zu cpu=%zu ready=%zu active=%zu\n",
		       unclaimed_head, unclaimed_tail, cpu_current,
		       dsa_ready.nr, active);
		goto out;
	}
	for (i = 0; i < nr_spans; i++) {
		if (spans[i].state != HOT_FG_SPAN_DONE ||
		    spans[i].owner == HOT_FG_OWNER_NONE ||
		    spans[i].cursor != spans[i].length ||
		    spans[i].finalized_pages != spans[i].page_count) {
			pr_err("DSA hybrid-demand final span mismatch span=%zu owner=%u state=%u cursor=%u length=%u finalized=%zu pages=%zu\n",
			       i, spans[i].owner, spans[i].state,
			       spans[i].cursor, spans[i].length,
			       spans[i].finalized_pages, spans[i].page_count);
			goto out;
		}
	}
	if (ctx->profile) {
		if (ctx->profile_hybrid_dsa_claim_spans +
		    ctx->profile_hybrid_cpu_claim_spans != nr_spans) {
			pr_err("DSA hybrid-demand claim accounting mismatch dsa=%" PRIu64
			       " cpu=%" PRIu64 " total=%zu\n",
			       ctx->profile_hybrid_dsa_claim_spans,
			       ctx->profile_hybrid_cpu_claim_spans, nr_spans);
			goto out;
		}
		ctx->profile_simd_vector_ops += cpu_stats.vector_ops;
		ctx->profile_simd_bytes_examined += cpu_stats.bytes_examined;
	}
	ret = 0;
out:
	if (active && hot_fg_wavefront_drain_slots(slots, &active))
		ret = -1;
	hot_fg_ready_queue_fini(&dsa_ready);
	return ret;
}

static int hot_fg_apply_raw_page(struct hot_apply_ctx *ctx,
				 struct hot_fg_raw_page *page)
{
	struct hot_memstore_seg *old;
	struct hot_vma_segment *seg;
	bool write_old;
	u16 i;

	if (page->state == HOT_FG_RAW_PARENT)
		return 0;
	old = hot_memstore_find_old_cover(ctx, page->vaddr, page->vaddr + PAGE_SIZE);
	seg = hot_memstore_find_vma_segment(ctx, page->vaddr, PAGE_SIZE);
	if (!seg) {
		pr_err("DSA hot memstore can't find destination VMA for raw page %lx\n",
		       page->vaddr);
		return -1;
	}
	write_old = hot_memstore_segment_reuses_old(seg, old, page->vaddr);
	if (page->state == HOT_FG_RAW_FULL) {
		if ((write_old && hot_memstore_write_to_old(ctx, old, page->raw,
						     page->vaddr, PAGE_SIZE)) ||
		    (!write_old && hot_memstore_write_to_segments(ctx, page->raw,
						      page->vaddr, PAGE_SIZE)))
			return -1;
		if (ctx->profile)
			ctx->memstore_bytes += PAGE_SIZE;
		return 0;
	}
	for (i = 0; i < page->patch_count; i++) {
		if ((write_old && hot_memstore_write_to_old(ctx, old,
						     page->raw + page->patches[i].off,
						     page->vaddr + page->patches[i].off,
						     page->patches[i].len)) ||
		    (!write_old && hot_memstore_write_to_segments(ctx,
						      page->raw + page->patches[i].off,
						      page->vaddr + page->patches[i].off,
						      page->patches[i].len)))
			return -1;
		if (ctx->profile)
			ctx->memstore_bytes += page->patches[i].len;
	}
	return 0;
}

static int hot_fg_encode_raw_wavefront(struct page_xfer *xfer,
				       struct hot_apply_ctx *ctx,
				       const unsigned char *shared)
{
	struct hot_fg_raw_page *pages = NULL;
	struct hot_fg_compare_span *spans = NULL;
	struct hot_fg_output_state *output = NULL;
	struct hot_fg_raw_page *validate_pages = NULL;
	struct hot_fg_compare_span *validate_spans = NULL;
	size_t nr = 0, cap = 0, nr_spans = 0, spans_cap = 0, i;
	size_t vma_cursor = 0;
	u32 desc_off;
	u32 raw_off = xfer->dsa_fg_raw_payload_base;
	u32 capture_run = 0;
	u32 max_xfer;
	u64 phase_start_us = 0;
	u64 compare_cpu_start_us = 0;
	u64 compare_cpu_end_us = 0;
	u64 compare_engine_end_us = 0;
	u64 compare_engine_cpu_start_us = 0;
	u64 compare_engine_cpu_end_us = 0;
	u64 prefault_wall_start_us = 0;
	u64 prefault_cpu_start_us = 0;
	u64 compare_core_wall_start_us = 0;
	u64 compare_core_cpu_start_us = 0;

	if (ctx->profile)
		phase_start_us = dsa_profile_wall_now_us();

	for (desc_off = xfer->dsa_fg_desc_area_off;
	     desc_off < xfer->dsa_fg_desc_head;
	     desc_off += sizeof(struct dsa_dump_descriptor)) {
		const struct dsa_dump_descriptor *desc =
			(const struct dsa_dump_descriptor *)(shared + desc_off);
		u32 page_off;

		if (!desc->copy_len || desc->copy_len % PAGE_SIZE ||
		    desc->src_addr & (PAGE_SIZE - 1) ||
		    raw_off > xfer->dsa_fg_raw_payload_head ||
		    desc->copy_len > xfer->dsa_fg_raw_payload_head - raw_off) {
			pr_err("DSA fine-grained raw descriptor is invalid off=%u src=%" PRIx64 " len=%u raw_off=%u raw_head=%u\n",
			       desc_off, desc->src_addr, desc->copy_len, raw_off,
			       xfer->dsa_fg_raw_payload_head);
			goto err;
		}
		for (page_off = 0; page_off < desc->copy_len; page_off += PAGE_SIZE) {
			if (hot_fg_raw_pages_append(ctx, &pages, &nr, &cap,
						    (unsigned long)desc->src_addr + page_off,
						    shared + raw_off + page_off,
						    capture_run))
				goto err;
		}
		raw_off += desc->copy_len;
		capture_run++;
	}
	if (raw_off != xfer->dsa_fg_raw_payload_head) {
		pr_err("DSA fine-grained raw capture size mismatch used=%u head=%u\n",
		       raw_off, xfer->dsa_fg_raw_payload_head);
		goto err;
	}
	if (ctx->profile) {
		ctx->profile_raw_index_us += dsa_profile_delta_us(phase_start_us,
							     dsa_profile_wall_now_us());
		ctx->profile_raw_pages = nr;
		ctx->profile_raw_bytes = xfer->dsa_fg_raw_payload_head -
			xfer->dsa_fg_raw_payload_base;
		ctx->profile_capture_runs = capture_run;
		phase_start_us = dsa_profile_wall_now_us();
	}
	max_xfer = ctx->dsa_max_transfer_size & ~(PAGE_SIZE - 1);
	if (max_xfer < PAGE_SIZE) {
		pr_err("DSA fine-grained compare max transfer is smaller than one page\n");
		goto err;
	}

	/* Build spans with three monotonic inputs already ordered by capture:
	 * raw capture runs, current VMA plans, and parent-map continuity.  A span
	 * never crosses any of those boundaries or the actual WQ transfer limit. */
	for (i = 0; i < nr;) {
		struct hot_fg_raw_page *first = &pages[i];
		size_t j;
		unsigned long vma_end;
		u32 length;

		if (first->state != HOT_FG_RAW_PENDING) {
			i++;
			continue;
		}
		while (vma_cursor < ctx->nr_vma_plans &&
		       ctx->vma_plans[vma_cursor].end <= first->vaddr)
			vma_cursor++;
		if (vma_cursor == ctx->nr_vma_plans ||
		    ctx->vma_plans[vma_cursor].start > first->vaddr ||
		    ctx->vma_plans[vma_cursor].end < first->vaddr + PAGE_SIZE) {
			pr_err("DSA fine-grained raw page lacks current VMA plan vaddr=%lx\n",
			       first->vaddr);
			goto err;
		}
		vma_end = ctx->vma_plans[vma_cursor].end;
		j = i + 1;
		length = PAGE_SIZE;
		while (j < nr && length + PAGE_SIZE <= max_xfer) {
			struct hot_fg_raw_page *prev = &pages[j - 1];
			struct hot_fg_raw_page *next = &pages[j];

			if (next->state != HOT_FG_RAW_PENDING ||
			    next->capture_run != first->capture_run ||
			    next->vaddr != prev->vaddr + PAGE_SIZE ||
			    next->raw != prev->raw + PAGE_SIZE ||
			    next->parent != prev->parent + PAGE_SIZE ||
			    (ctx->fg_compare_backend == HOT_FG_COMPARE_HYBRID_DEMAND &&
			     (next->vaddr & ~(HOT_FG_HYBRID_CHUNK_BYTES - 1)) !=
			     (first->vaddr & ~(HOT_FG_HYBRID_CHUNK_BYTES - 1))) ||
			    next->vaddr + PAGE_SIZE > vma_end)
				break;
			length += PAGE_SIZE;
			j++;
		}
		if (nr_spans == spans_cap) {
			size_t new_cap = spans_cap ? spans_cap * 2 : 256;
			void *new_spans = xrealloc(spans, new_cap * sizeof(*spans));

			if (!new_spans)
				goto err;
			spans = new_spans;
			spans_cap = new_cap;
		}
		spans[nr_spans] = (struct hot_fg_compare_span) {
			.raw = first->raw,
			.parent = first->parent,
			.first_page = i,
			.page_count = j - i,
			.length = length,
		};
		i = j;
		nr_spans++;
	}
	if (ctx->profile) {
		ctx->profile_span_build_us += dsa_profile_delta_us(phase_start_us,
							      dsa_profile_wall_now_us());
		ctx->profile_spans = nr_spans;
		for (i = 0; i < nr_spans; i++) {
			ctx->profile_span_pages += spans[i].page_count;
			if (spans[i].page_count > ctx->profile_max_span_pages)
				ctx->profile_max_span_pages = spans[i].page_count;
		}
		phase_start_us = dsa_profile_wall_now_us();
	}
	if (ctx->profile) {
		(void)hot_prq_profile_start(ctx);
		phase_start_us = dsa_profile_wall_now_us();
		compare_cpu_start_us = dsa_profile_thread_now_us();
		compare_engine_cpu_start_us = compare_cpu_start_us;
	}
	if (ctx->compare_breakdown && nr_spans) {
		prefault_wall_start_us = dsa_profile_wall_now_us();
		prefault_cpu_start_us = dsa_profile_thread_now_us();
		if (hot_fg_prefault_all(ctx, spans, nr_spans))
			goto err;
		ctx->profile_parent_prefault_wall_us +=
			dsa_profile_delta_us(prefault_wall_start_us,
					     dsa_profile_wall_now_us());
		ctx->profile_parent_prefault_cpu_us +=
			dsa_profile_delta_us(prefault_cpu_start_us,
					     dsa_profile_thread_now_us());
	}
	if (ctx->fg_compare_backend == HOT_FG_COMPARE_VALIDATE && nr_spans) {
		validate_pages = xmalloc(nr * sizeof(*validate_pages));
		validate_spans = xmalloc(nr_spans * sizeof(*validate_spans));
		if (!validate_pages || !validate_spans)
			goto err;
		memcpy(validate_pages, pages, nr * sizeof(*validate_pages));
		memcpy(validate_spans, spans, nr_spans * sizeof(*validate_spans));
	}
	if (ctx->compare_breakdown && nr_spans) {
		compare_core_wall_start_us = dsa_profile_wall_now_us();
		compare_core_cpu_start_us = dsa_profile_thread_now_us();
	}
	if (nr_spans) {
		switch (ctx->fg_compare_backend) {
		case HOT_FG_COMPARE_DSA:
			if (hot_fg_compare_wavefront(ctx, pages, spans, nr_spans))
				goto err;
			break;
		case HOT_FG_COMPARE_MEMCMP:
		case HOT_FG_COMPARE_SCALAR64:
		case HOT_FG_COMPARE_SIMD_AVX2:
		case HOT_FG_COMPARE_SIMD_AVX512:
			if (hot_fg_compare_cpu(ctx, pages, spans, nr_spans,
					       ctx->fg_compare_backend, true))
				goto err;
			break;
		case HOT_FG_COMPARE_HYBRID_DEMAND:
			if (hot_fg_compare_hybrid_demand(ctx, pages, spans, nr_spans))
				goto err;
			break;
		case HOT_FG_COMPARE_VALIDATE:
			if (hot_fg_compare_wavefront(ctx, pages, spans, nr_spans) ||
			    hot_fg_compare_cpu(ctx, validate_pages, validate_spans, nr_spans,
					       HOT_FG_COMPARE_SIMD_AVX512, false) ||
			    hot_fg_validate_compare_metadata(pages, validate_pages, nr,
						     spans, validate_spans, nr_spans))
				goto err;
			break;
		default:
			pr_err("DSA fine-grained compare backend is invalid\n");
			goto err;
		}
	}
	if (ctx->compare_breakdown && nr_spans) {
		ctx->profile_compare_core_wall_us +=
			dsa_profile_delta_us(compare_core_wall_start_us,
					     dsa_profile_wall_now_us());
		ctx->profile_compare_core_cpu_us +=
			dsa_profile_delta_us(compare_core_cpu_start_us,
					     dsa_profile_thread_now_us());
	}
	if (ctx->profile) {
		compare_engine_end_us = dsa_profile_wall_now_us();
		compare_engine_cpu_end_us = dsa_profile_thread_now_us();
		(void)hot_prq_profile_stop(ctx);
	}
	for (i = 0; i < nr; i++) {
		if (pages[i].state == HOT_FG_RAW_PENDING) {
			pr_err("DSA fine-grained compare barrier has pending page=%zu vaddr=%lx\n",
			       i, pages[i].vaddr);
			goto err;
		}
	}
	output = xzalloc(sizeof(*output));
	if (!output)
		goto err;
	output->ctx = ctx;
	output->pages = pages;
	output->nr_pages = nr;
	if (hot_fg_output_drain(output))
		goto err;
	if (ctx->profile) {
		compare_cpu_end_us = dsa_profile_thread_now_us();
		ctx->profile_compare_wall_us += dsa_profile_delta_us(phase_start_us,
							       dsa_profile_wall_now_us());
		ctx->profile_compare_cpu_us += dsa_profile_delta_us(compare_cpu_start_us,
							      compare_cpu_end_us);
		ctx->profile_compare_engine_wall_us +=
			dsa_profile_delta_us(phase_start_us, compare_engine_end_us);
		ctx->profile_compare_engine_cpu_us +=
			dsa_profile_delta_us(compare_engine_cpu_start_us,
					     compare_engine_cpu_end_us);
		if (ctx->profile_output_start_us)
			ctx->profile_output_wall_us +=
				dsa_profile_delta_us(ctx->profile_output_start_us,
						     dsa_profile_wall_now_us());
		phase_start_us = dsa_profile_wall_now_us();
	}
	for (i = 0; i < nr; i++) {
		if (hot_fg_apply_raw_page(ctx, &pages[i]))
			goto err;
	}
	if (ctx->profile)
		ctx->profile_hot_apply_us += dsa_profile_delta_us(phase_start_us,
							       dsa_profile_wall_now_us());
	xfer->dsa_fg_materialized = true;
	if (dsa_debug_enabled())
		pr_info("DSA_FG_RAW_ENCODE: pages_id=%u backend=%s raw_bytes=%u compare_ops=%" PRIu64 " copy_ops=%" PRIu64 " spans=%zu inflight=%u max_xfer=%u\n",
			xfer->pages_id,
			hot_fg_compare_backend_name(ctx->fg_compare_backend),
			xfer->dsa_fg_raw_payload_head - xfer->dsa_fg_raw_payload_base,
			ctx->fg_compare_ops, ctx->fg_copy_ops, nr_spans,
			ctx->fg_compare_backend == HOT_FG_COMPARE_DSA ||
			ctx->fg_compare_backend == HOT_FG_COMPARE_HYBRID_DEMAND ||
			ctx->fg_compare_backend == HOT_FG_COMPARE_VALIDATE ?
			HOT_DSA_COMPARE_INFLIGHT : 0, max_xfer);
	xfree(validate_spans);
	xfree(validate_pages);
	xfree(output);
	xfree(spans);
	xfree(pages);
	return 0;
err:
	if (ctx->profile_prq_active)
		(void)hot_prq_profile_stop(ctx);
	xfree(validate_spans);
	xfree(validate_pages);
	xfree(output);
	xfree(spans);
	xfree(pages);
	return -1;
}

static int hot_fg_write_pages_loc(struct page_xfer *xfer, int p,
			  unsigned long len,
			  struct hot_apply_extent *pending_entry)
{
	struct hot_apply_ctx *ctx = xfer->hot_apply;
	unsigned long curr;
	unsigned char page[PAGE_SIZE];

	if (!pending_entry || len % PAGE_SIZE) {
		pr_err("DSA fine-grained write requires page-aligned pending extent len=%lu\n",
		       len);
		return -1;
	}

	for (curr = 0; curr < len; curr += PAGE_SIZE) {
		uint64_t start_us;
		unsigned long vaddr = pending_entry->vaddr + curr;

		start_us = hot_now_us();
		if (read_full_fd(p, page, PAGE_SIZE)) {
			pr_perror("DSA fine-grained current page read failed");
			return -1;
		}
		if (hot_fg_write_page(ctx, vaddr, page))
			return -1;
		if (hot_memstore_write_to_segments(ctx, page, vaddr, PAGE_SIZE))
			return -1;
		ctx->append_splice_us += hot_now_us() - start_us;
		ctx->append_bytes += PAGE_SIZE;
		ctx->memstore_bytes += PAGE_SIZE;
	}

	return 0;
}

/*
 * The normal DSA dump has already copied the frozen target bytes into the
 * shared payload arena.  Encode that stable arena after thaw; do not read the
 * target address space again and do not route it back through the replay pipe.
 */
static int page_xfer_dsa_fg_encode_raw_capture(struct page_xfer *xfer)
{
	struct hot_apply_ctx *ctx;
	const unsigned char *shared;

	if (!xfer || !xfer->dsa_fg_raw_capture || !xfer->dsa_fg_shared) {
		pr_err("DSA fine-grained raw capture metadata is incomplete\n");
		return -1;
	}
	ctx = xfer->hot_apply;
	if (!ctx || !ctx->memstore || !ctx->fine_grained) {
		pr_err("DSA fine-grained raw capture requires an initialized hot memstore\n");
		return -1;
	}
	if (hot_apply_prepare_post_thaw(ctx))
		return -1;
	if (xfer->dsa_fg_desc_head < xfer->dsa_fg_desc_area_off ||
	    xfer->dsa_fg_raw_payload_head < xfer->dsa_fg_raw_payload_base) {
		pr_err("DSA fine-grained raw capture has invalid bounds\n");
		return -1;
	}

	shared = xfer->dsa_fg_shared;
	return hot_fg_encode_raw_wavefront(xfer, ctx, shared);

	/* Kept below temporarily as the old single-page implementation reference. */
#if 0
	raw_off = xfer->dsa_fg_raw_payload_base;
	start_us = hot_now_us();

	for (desc_off = xfer->dsa_fg_desc_area_off;
	     desc_off < xfer->dsa_fg_desc_head;
	     desc_off += sizeof(struct dsa_dump_descriptor)) {
		const struct dsa_dump_descriptor *desc =
			(const struct dsa_dump_descriptor *)(shared + desc_off);
		u32 page_off;

		if (!desc->copy_len || desc->copy_len % PAGE_SIZE ||
		    desc->src_addr & (PAGE_SIZE - 1) ||
		    raw_off > xfer->dsa_fg_raw_payload_head ||
		    desc->copy_len > xfer->dsa_fg_raw_payload_head - raw_off) {
			pr_err("DSA fine-grained raw descriptor is invalid off=%u src=%" PRIx64 " len=%u raw_off=%u raw_head=%u\n",
			       desc_off, desc->src_addr, desc->copy_len, raw_off,
			       xfer->dsa_fg_raw_payload_head);
			return -1;
		}

		for (page_off = 0; page_off < desc->copy_len; page_off += PAGE_SIZE) {
			unsigned long vaddr = (unsigned long)desc->src_addr + page_off;
			const void *cur = shared + raw_off + page_off;

			if (hot_fg_write_page(ctx, vaddr, cur))
				return -1;
			ctx->append_bytes += PAGE_SIZE;
		}
		raw_off += desc->copy_len;
	}

	if (raw_off != xfer->dsa_fg_raw_payload_head) {
		pr_err("DSA fine-grained raw capture size mismatch used=%u head=%u\n",
		       raw_off, xfer->dsa_fg_raw_payload_head);
		return -1;
	}

	/*
	 * Do not alter the hot parent while classification/sidecar generation is
	 * still running.  A descriptor is a compact cursor into the stable raw
	 * arena, so a second descriptor pass is enough: no second page buffer and
	 * no copy of PATCH/FULL data is needed.  If this pass fails CDP marks the
	 * hot cache INVALID rather than exposing a partially updated parent.
	 */
	raw_off = xfer->dsa_fg_raw_payload_base;
	for (desc_off = xfer->dsa_fg_desc_area_off;
	     desc_off < xfer->dsa_fg_desc_head;
	     desc_off += sizeof(struct dsa_dump_descriptor)) {
		const struct dsa_dump_descriptor *desc =
			(const struct dsa_dump_descriptor *)(shared + desc_off);
		u32 page_off;

		if (!desc->copy_len || desc->copy_len % PAGE_SIZE ||
		    raw_off > xfer->dsa_fg_raw_payload_head ||
		    desc->copy_len > xfer->dsa_fg_raw_payload_head - raw_off) {
			pr_err("DSA fine-grained hot apply descriptor is invalid off=%u\n", desc_off);
			return -1;
		}
		for (page_off = 0; page_off < desc->copy_len; page_off += PAGE_SIZE) {
			unsigned long vaddr = (unsigned long)desc->src_addr + page_off;
			const void *cur = shared + raw_off + page_off;

			if (hot_memstore_write_to_segments(ctx, cur, vaddr, PAGE_SIZE))
				return -1;
			if (ctx->profile)
				ctx->memstore_bytes += PAGE_SIZE;
		}
		raw_off += desc->copy_len;
	}

	if (ctx->profile) {
		ctx->append_splice_us += hot_now_us() - start_us;
		ctx->append_time_us += hot_now_us() - start_us;
	}
	xfer->dsa_fg_materialized = true;
	if (dsa_debug_enabled())
		pr_info("DSA_FG_RAW_ENCODE: pages_id=%u raw_bytes=%u compare_ops=%" PRIu64 " copy_ops=%" PRIu64 "\n",
			xfer->pages_id,
			xfer->dsa_fg_raw_payload_head - xfer->dsa_fg_raw_payload_base,
		ctx->fg_compare_ops, ctx->fg_copy_ops);
	return 0;
#endif
}

static void close_page_xfer(struct page_xfer *xfer)
{
	if (xfer->parent != NULL) {
		xfer->parent->close(xfer->parent);
		xfree(xfer->parent);
		xfer->parent = NULL;
	}
	if (xfer->hot_apply)
		hot_apply_abort(xfer);
	close_image(xfer->pi);
	close_image(xfer->pmi);
}

static int open_page_local_xfer(struct page_xfer *xfer, int fd_type, unsigned long img_id)
{
	u32 pages_id;

	xfer->pmi = open_image(fd_type, O_DUMP, img_id);
	if (!xfer->pmi)
		return -1;

	xfer->pi = open_pages_image(O_DUMP, xfer->pmi, &pages_id);
	if (!xfer->pi)
		goto err_pmi;

	/*
	 * Open page-read for parent images (if it exists). It will
	 * be used for two things:
	 * 1) when writing a page, those from parent will be dedup-ed
	 * 2) when writing a hole, the respective place would be checked
	 *    to exist in parent (either pagemap or hole)
	 */
	xfer->parent = NULL;
	if (fd_type == CR_FD_PAGEMAP || fd_type == CR_FD_SHMEM_PAGEMAP) {
		int ret;
		int pfd;
		int pr_flags = (fd_type == CR_FD_PAGEMAP) ? PR_TASK : PR_SHMEM;

		/* Image streaming lacks support for incremental images */
		if (opts.stream)
			goto out;

		if (open_parent(get_service_fd(IMG_FD_OFF), &pfd))
			goto err_pi;
		if (pfd < 0)
			goto out;

		xfer->parent = xmalloc(sizeof(*xfer->parent));
		if (!xfer->parent) {
			close(pfd);
			goto err_pi;
		}

		ret = open_page_read_at(pfd, img_id, xfer->parent, pr_flags);
		if (ret <= 0) {
			pr_perror("No parent image found, though parent directory is set");
			xfree(xfer->parent);
			xfer->parent = NULL;
			close(pfd);
			goto out;
		}
		close(pfd);
	}

out:
	if (hot_apply_init_xfer(xfer, fd_type, img_id, pages_id))
		goto err_parent;

	xfer->pages_id = pages_id;
	xfer->write_pagemap = write_pagemap_loc;
	xfer->write_pages = write_pages_loc;
	xfer->close = close_page_xfer;
	return 0;

err_parent:
	if (xfer->parent != NULL) {
		xfer->parent->close(xfer->parent);
		xfree(xfer->parent);
		xfer->parent = NULL;
	}
err_pi:
	close_image(xfer->pi);
err_pmi:
	close_image(xfer->pmi);
	return -1;
}

int open_page_xfer(struct page_xfer *xfer, int fd_type, unsigned long img_id)
{
	xfer->offset = 0;
	xfer->transfer_lazy = true;
	xfer->dsa_fine_grained = false;
	xfer->hot_apply = NULL;

	if (opts.use_page_server)
		return open_page_server_xfer(xfer, fd_type, img_id);
	else
		return open_page_local_xfer(xfer, fd_type, img_id);
}

int open_page_xfer_no_parent(struct page_xfer *xfer, int fd_type, unsigned long img_id)
{
	u32 pages_id;

	if (opts.use_page_server) {
		pr_err("DSA parent index mode does not support page server xfer\n");
		return -1;
	}

	xfer->offset = 0;
	xfer->transfer_lazy = true;
	xfer->dsa_fine_grained = false;
	xfer->parent = NULL;
	xfer->hot_apply = NULL;
	xfer->pmi = open_image(fd_type, O_DUMP, img_id);
	if (!xfer->pmi)
		return -1;

	xfer->pi = open_pages_image(O_DUMP, xfer->pmi, &pages_id);
	if (!xfer->pi) {
		close_image(xfer->pmi);
		return -1;
	}

	if (hot_apply_init_xfer(xfer, fd_type, img_id, pages_id)) {
		close_image(xfer->pi);
		close_image(xfer->pmi);
		return -1;
	}

	xfer->pages_id = pages_id;
	xfer->write_pagemap = write_pagemap_loc;
	xfer->write_pages = write_pages_loc;
	xfer->close = close_page_xfer;
	return 0;
}

int page_xfer_dsa_fg_enable(struct page_xfer *xfer)
{
	if (!xfer)
		return -1;
	xfer->dsa_fine_grained = true;
	return 0;
}

static int page_xfer_dump_hole(struct page_xfer *xfer, struct iovec *hole, u32 flags)
{
	BUG_ON(hole->iov_base < (void *)xfer->offset);
	hole->iov_base -= xfer->offset;
	pr_debug("\th %p [%u]\n", hole->iov_base, (unsigned int)(hole->iov_len / PAGE_SIZE));

	if (xfer->write_pagemap(xfer, hole, flags))
		return -1;

	return 0;
}

static int get_hole_flags(struct page_pipe *pp, int n)
{
	unsigned int hole_flags = pp->hole_flags[n];

	if (hole_flags == PP_HOLE_PARENT)
		return PE_PARENT;
	else
		BUG();

	return -1;
}

static int dump_holes(struct page_xfer *xfer, struct page_pipe *pp, unsigned int *cur_hole, void *limit)
{
	int ret;

	for (; *cur_hole < pp->free_hole; (*cur_hole)++) {
		struct iovec hole = pp->holes[*cur_hole];
		u32 hole_flags;

		if (limit && hole.iov_base >= limit)
			break;

		hole_flags = get_hole_flags(pp, *cur_hole);
		ret = page_xfer_dump_hole(xfer, &hole, hole_flags);
		if (ret)
			return ret;
	}

	return 0;
}

static inline u32 ppb_xfer_flags(struct page_xfer *xfer, struct page_pipe_buf *ppb)
{
	if (ppb->flags & PPB_LAZY)
		/*
		 * Pages that can be lazily restored are always marked as such.
		 * In the case we actually transfer them into image mark them
		 * as present as well.
		 */
		return (xfer->transfer_lazy ? PE_PRESENT : 0) | PE_LAZY;
	else
		return PE_PRESENT;
}

/*
 * Optimized pre-dump algorithm
 * ==============================
 *
 * Note: Please refer man(2) page of process_vm_readv syscall.
 *
 * The following discussion covers the possibly faulty-iov
 * locations in an iovec, which hinders process_vm_readv from
 * dumping the entire iovec in a single invocation.
 *
 * Memory layout of target process:
 *
 * Pages: A        B        C
 *	  +--------+--------+--------+--------+--------+--------+
 *	  |||||||||||||||||||||||||||||||||||||||||||||||||||||||
 *	  +--------+--------+--------+--------+--------+--------+
 *
 * Single "iov" representation: {starting_address, length_in_bytes}
 * An iovec is array of iov-s.
 *
 * NOTE: For easy representation and discussion purpose, we carry
 *	 out further discussion at "page granularity".
 *	 length_in_bytes will represent page count in iov instead
 *	 of byte count. Same assumption applies for the syscall's
 *	 return value. Instead of returning the number of bytes
 *	 read, it returns a page count.
 *
 * For above memory mapping, generated iovec: {A,1}{B,1}{C,4}
 *
 * This iovec remains unmodified once generated. At the same
 * time some of memory regions listed in iovec may get modified
 * (unmap/change protection) by the target process while syscall
 * is trying to dump iovec regions.
 *
 * Case 1:
 *	A is unmapped, {A,1} become faulty iov
 *
 *      A        B        C
 *      +--------+--------+--------+--------+--------+--------+
 *      |        ||||||||||||||||||||||||||||||||||||||||||||||
 *      +--------+--------+--------+--------+--------+--------+
 *      ^        ^
 *      |        |
 *      start    |
 *      (1)      |
 *               start
 *               (2)
 *
 *	process_vm_readv will return -1. Increment start pointer(2),
 *	syscall will process {B,1}{C,4} in one go and copy 5 pages
 *	to userbuf from iov-B and iov-C.
 *
 * Case 2:
 *	B is unmapped, {B,1} become faulty iov
 *
 *      A        B        C
 *      +--------+--------+--------+--------+--------+--------+
 *      |||||||||         |||||||||||||||||||||||||||||||||||||
 *      +--------+--------+--------+--------+--------+--------+
 *      ^                 ^
 *      |                 |
 *      start             |
 *      (1)               |
 *                        start
 *                        (2)
 *
 *	process_vm_readv will return 1, i.e. page A copied to
 *	userbuf successfully and syscall stopped, since B got
 *	unmapped.
 *
 *	Increment the start pointer to C(2) and invoke syscall.
 *	Userbuf contains 5 pages overall from iov-A and iov-C.
 *
 * Case 3:
 *	This case deals with partial unmapping of iov representing
 *	more than one pagesize region.
 *
 *	Syscall can't process such faulty iov as whole. So we
 *	process such regions part-by-part and form new sub-iovs
 *	in aux_iov from successfully processed pages.
 *
 *
 *	Part 3.1:
 *		First page of C is unmapped
 *
 *      A        B        C
 *      +--------+--------+--------+--------+--------+--------+
 *      ||||||||||||||||||         ||||||||||||||||||||||||||||
 *      +--------+--------+--------+--------+--------+--------+
 *      ^                          ^
 *      |                          |
 *      start                      |
 *      (1)                        |
 *                                 dummy
 *                                 (2)
 *
 *	process_vm_readv will return 2, i.e. pages A and B copied.
 *	We identify length of iov-C is more than 1 page, that is
 *	where this case differs from Case 2.
 *
 *	dummy-iov is introduced(2) as: {C+1,3}. dummy-iov can be
 *	directly placed at next page to failing page. This will copy
 *	remaining 3 pages from iov-C to userbuf. Finally create
 *	modified iov entry in aux_iov. Complete aux_iov look like:
 *
 *	aux_iov: {A,1}{B,1}{C+1,3}*
 *
 *
 *	Part 3.2:
 *		In between page of C is unmapped, let's say third
 *
 *      A        B        C
 *      +--------+--------+--------+--------+--------+--------+
 *      ||||||||||||||||||||||||||||||||||||         ||||||||||
 *      +--------+--------+--------+--------+--------+--------+
 *      ^                                            ^
 *      |                 |-----------------|        |
 *      start              partial_read_bytes        |
 *      (1)                                          |
 *                                                   dummy
 *                                                   (2)
 *
 *	process_vm_readv will return 4, i.e. pages A and B copied
 *	completely and first two pages of C are also copied.
 *
 *	Since, iov-C is not processed completely, we need to find
 *	"partial_read_byte" count to place out dummy-iov for
 *	remaining processing of iov-C. This function is performed by
 *	analyze_iov function.
 *
 *	dummy-iov will be(2): {C+3,1}. dummy-iov will be placed
 *	next to first failing address to process remaining iov-C.
 *	New entries in aux_iov will look like:
 *
 *	aux_iov: {A,1}{B,1}{C,2}*{C+3,1}*
 */

unsigned long handle_faulty_iov(int pid, struct iovec *riov, unsigned long faulty_index, struct iovec *bufvec,
				struct iovec *aux_iov, unsigned long *aux_len)
{
	struct iovec dummy;
	ssize_t bytes_read;
	unsigned long final_read_cnt = 0;

	/* Handling Case 3-Part 3.2*/
	dummy.iov_base = riov[faulty_index].iov_base;
	dummy.iov_len = riov[faulty_index].iov_len;

	while (dummy.iov_len) {
		bytes_read = process_vm_readv(pid, bufvec, 1, &dummy, 1, 0);
		if (bytes_read == -1) {
			/* Handling faulty page read in faulty iov */
			cnt_sub(CNT_PAGES_WRITTEN, 1);
			dummy.iov_base += PAGE_SIZE;
			dummy.iov_len -= PAGE_SIZE;
			continue;
		}

		/* If aux-iov can merge and expand or new entry required */
		if (aux_iov[(*aux_len) - 1].iov_base + aux_iov[(*aux_len) - 1].iov_len == dummy.iov_base)
			aux_iov[(*aux_len) - 1].iov_len += bytes_read;
		else {
			aux_iov[*aux_len].iov_base = dummy.iov_base;
			aux_iov[*aux_len].iov_len = bytes_read;
			(*aux_len) += 1;
		}

		dummy.iov_base += bytes_read;
		dummy.iov_len -= bytes_read;
		bufvec->iov_base += bytes_read;
		bufvec->iov_len -= bytes_read;
		final_read_cnt += bytes_read;
	}

	return final_read_cnt;
}

/*
 * This function will position start pointer to the latest
 * successfully read iov in iovec.
 */
static unsigned long analyze_iov(ssize_t bytes_read, struct iovec *riov, unsigned long *index, struct iovec *aux_iov,
				 unsigned long *aux_len)
{
	ssize_t processed_bytes = 0;

	/* correlating iovs with read bytes */
	while (processed_bytes < bytes_read) {
		processed_bytes += riov[*index].iov_len;
		aux_iov[*aux_len].iov_base = riov[*index].iov_base;
		aux_iov[*aux_len].iov_len = riov[*index].iov_len;

		(*aux_len) += 1;
		(*index) += 1;
	}

	/* handling partially processed faulty iov*/
	if (processed_bytes - bytes_read) {
		unsigned long partial_read_bytes = 0;

		(*index) -= 1;

		partial_read_bytes = riov[*index].iov_len - (processed_bytes - bytes_read);
		aux_iov[*aux_len - 1].iov_len = partial_read_bytes;
		riov[*index].iov_base += partial_read_bytes;
		riov[*index].iov_len -= partial_read_bytes;
	}

	return 0;
}

/*
 * This function iterates over complete ppb->iov entries and pass
 * them to process_vm_readv syscall.
 *
 * Since process_vm_readv returns count of successfully read bytes.
 * It does not point to iovec entry associated to last successful
 * byte read. The correlation between bytes read and corresponding
 * iovec is setup through analyze_iov function.
 *
 * If all iovecs are not processed in one go, it means there exists
 * some faulty iov entry(memory mapping modified after it was grabbed)
 * in iovec. process_vm_readv syscall stops at such faulty iov and
 * skip processing further any entry in iovec. This is handled by
 * handle_faulty_iov function.
 */
static long fill_userbuf(int pid, struct page_pipe_buf *ppb, struct iovec *bufvec, struct iovec *aux_iov,
			 unsigned long *aux_len)
{
	struct iovec *riov = ppb->iov;
	ssize_t bytes_read;
	unsigned long total_read = 0;
	unsigned long start = 0;

	while (start < ppb->nr_segs) {
		bytes_read = process_vm_readv(pid, bufvec, 1, &riov[start], ppb->nr_segs - start, 0);
		if (bytes_read == -1) {
			if (errno == ESRCH) {
				pr_debug("Target process PID:%d not found\n", pid);
				return -ESRCH;
			}
			if (errno != EFAULT) {
				pr_perror("process_vm_readv failed");
				return -1;
			}
			/* Handling Case 1*/
			if (riov[start].iov_len == PAGE_SIZE) {
				cnt_sub(CNT_PAGES_WRITTEN, 1);
				start += 1;
				continue;
			}
			total_read += handle_faulty_iov(pid, riov, start, bufvec, aux_iov, aux_len);
			start += 1;
			continue;
		}

		if (bytes_read > 0) {
			if (analyze_iov(bytes_read, riov, &start, aux_iov, aux_len) < 0)
				return -1;
			bufvec->iov_base += bytes_read;
			bufvec->iov_len -= bytes_read;
			total_read += bytes_read;
		}
	}

	return total_read;
}

/*
 * This function is similar to page_xfer_dump_pages, instead it uses
 * auxiliary_iov array for pagemap generation.
 *
 * The entries of ppb->iov may mismatch with actual process mappings
 * present at time of pre-dump. Such entries need to be adjusted as per
 * the pages read by process_vm_readv syscall. These adjusted entries
 * along with unmodified entries are present in aux_iov array.
 */

int page_xfer_predump_pages(int pid, struct page_xfer *xfer, struct page_pipe *pp)
{
	struct page_pipe_buf *ppb;
	unsigned int cur_hole = 0, i;
	unsigned long ret, bytes_read;
	unsigned long userbuf_len;
	struct iovec bufvec;

	struct iovec *aux_iov;
	unsigned long aux_len;
	void *userbuf;

	userbuf_len = PIPE_MAX_BUFFER_SIZE;
	userbuf = mmap(NULL, userbuf_len, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (userbuf == MAP_FAILED) {
		pr_perror("Unable to mmap a buffer");
		return -1;
	}
	aux_iov = xmalloc(userbuf_len / PAGE_SIZE * sizeof(aux_iov[0]));
	if (!aux_iov)
		goto err;

	list_for_each_entry(ppb, &pp->bufs, l) {
		if (ppb->pipe_size * PAGE_SIZE > userbuf_len) {
			void *addr;

			addr = mremap(userbuf, userbuf_len, ppb->pipe_size * PAGE_SIZE, MREMAP_MAYMOVE);
			if (addr == MAP_FAILED) {
				pr_perror("Unable to mmap a buffer");
				goto err;
			}
			userbuf_len = ppb->pipe_size * PAGE_SIZE;
			userbuf = addr;
			addr = xrealloc(aux_iov, ppb->pipe_size * sizeof(aux_iov[0]));
			if (!addr)
				goto err;
			aux_iov = addr;
		}
		timing_start(TIME_MEMDUMP);

		aux_len = 0;
		bufvec.iov_len = userbuf_len;
		bufvec.iov_base = userbuf;

		bytes_read = fill_userbuf(pid, ppb, &bufvec, aux_iov, &aux_len);
		if (bytes_read == -ESRCH) {
			timing_stop(TIME_MEMDUMP);
			munmap(userbuf, userbuf_len);
			xfree(aux_iov);
			return 0;
		}
		if (bytes_read < 0)
			goto err;

		bufvec.iov_base = userbuf;
		bufvec.iov_len = bytes_read;
		ret = vmsplice(ppb->p[1], &bufvec, 1, SPLICE_F_NONBLOCK | SPLICE_F_GIFT);

		if (ret == -1 || ret != bytes_read) {
			pr_err("vmsplice: Failed to splice user buffer to pipe %ld\n", ret);
			goto err;
		}

		timing_stop(TIME_MEMDUMP);
		timing_start(TIME_MEMWRITE);

		/* generating pagemap */
		for (i = 0; i < aux_len; i++) {
			struct iovec iov = aux_iov[i];
			u32 flags;

			ret = dump_holes(xfer, pp, &cur_hole, iov.iov_base);
			if (ret)
				goto err;

			BUG_ON(iov.iov_base < (void *)xfer->offset);
			iov.iov_base -= xfer->offset;
			pr_debug("\t p %p - %p\n", iov.iov_base, iov.iov_base + iov.iov_len);

			flags = ppb_xfer_flags(xfer, ppb);

			if (xfer->write_pagemap(xfer, &iov, flags))
				goto err;

			if (xfer->write_pages(xfer, ppb->p[0], iov.iov_len))
				goto err;
		}

		timing_stop(TIME_MEMWRITE);
	}

	munmap(userbuf, userbuf_len);
	xfree(aux_iov);
	timing_start(TIME_MEMWRITE);

	return dump_holes(xfer, pp, &cur_hole, NULL);
err:
	munmap(userbuf, userbuf_len);
	xfree(aux_iov);
	return -1;
}

int page_xfer_dump_pages(struct page_xfer *xfer, struct page_pipe *pp)
{
	struct page_pipe_buf *ppb;
	struct hot_apply_ctx *profile_ctx = xfer->hot_apply;
	unsigned int cur_hole = 0;
	int ret = -1;
	u64 phase_start_us = 0;

	hot_profile_begin(profile_ctx);

	if (profile_ctx && profile_ctx->profile)
		phase_start_us = dsa_profile_wall_now_us();
	if (xfer->hot_apply && !xfer->hot_apply->post_thaw_ready &&
	    hot_apply_prepare_post_thaw(xfer->hot_apply))
		goto out;
	if (profile_ctx && profile_ctx->profile)
		profile_ctx->profile_post_prepare_us += dsa_profile_delta_us(phase_start_us,
								      dsa_profile_wall_now_us());

	if (xfer->dsa_fg_raw_capture && !xfer->dsa_fg_materialized) {
		if (page_xfer_dsa_fg_encode_raw_capture(xfer))
			goto out;
	} else if (xfer->dsa_fine_grained && !xfer->dsa_fg_materialized) {
		uint64_t fg_start_us = hot_now_us();
		uint64_t fg_sidecar_us;
		uint64_t fg_apply_us;
		uint64_t fg_enable_us;

		if (page_xfer_dsa_fg_write_sidecar(xfer, xfer->dsa_fg_shared,
						   xfer->dsa_fg_desc_area_off,
						   xfer->dsa_fg_desc_head))
			goto out;
		fg_sidecar_us = hot_now_us() - fg_start_us;
		fg_start_us = hot_now_us();
		if (page_xfer_dsa_fg_apply_records(xfer, xfer->dsa_fg_shared,
						       xfer->dsa_fg_desc_area_off,
						       xfer->dsa_fg_desc_head))
			goto out;
		fg_apply_us = hot_now_us() - fg_start_us;
		fg_start_us = hot_now_us();
		if (page_xfer_dsa_fg_enable(xfer))
			goto out;
		fg_enable_us = hot_now_us() - fg_start_us;
		xfer->dsa_fg_materialized = true;
		pr_info("DSA_FG_MATERIALIZE: pages_id=%u sidecar_write_us=%" PRIu64 " hot_apply_us=%" PRIu64 " enable_us=%" PRIu64 " desc_bytes=%u\n",
			xfer->pages_id, fg_sidecar_us, fg_apply_us, fg_enable_us,
			xfer->dsa_fg_desc_head - xfer->dsa_fg_desc_area_off);
	}

	pr_debug("Transferring pages:\n");
	if (profile_ctx && profile_ctx->profile)
		phase_start_us = dsa_profile_wall_now_us();

	list_for_each_entry(ppb, &pp->bufs, l) {
		unsigned int i;

		pr_debug("\tbuf %lx/%d\n", ppb->pages_in, ppb->nr_segs);

		for (i = 0; i < ppb->nr_segs; i++) {
			struct iovec iov = ppb->iov[i];
			u32 flags;

			ret = dump_holes(xfer, pp, &cur_hole, iov.iov_base);
			if (ret)
				goto out;

			BUG_ON(iov.iov_base < (void *)xfer->offset);
			iov.iov_base -= xfer->offset;
			pr_debug("\tp %p - %p\n", iov.iov_base, iov.iov_base + iov.iov_len);

			flags = page_xfer_effective_flags(xfer, ppb_xfer_flags(xfer, ppb));

			if (xfer->write_pagemap(xfer, &iov, flags))
				goto out;
			if ((flags & PE_PRESENT) && !(flags & PE_DSA_FG) &&
			    xfer->write_pages(xfer, ppb->p[0], iov.iov_len))
				goto out;
			if (profile_ctx && profile_ctx->profile)
				profile_ctx->profile_pagemap_iovs++;
		}
	}

	ret = dump_holes(xfer, pp, &cur_hole, NULL);
	if (ret)
		goto out;
	if (profile_ctx && profile_ctx->profile)
		profile_ctx->profile_pagemap_plan_us += dsa_profile_delta_us(phase_start_us,
								    dsa_profile_wall_now_us());
	if (hot_fg_defer_pagemap(xfer)) {
		if (profile_ctx && profile_ctx->profile)
			phase_start_us = dsa_profile_wall_now_us();
		if (hot_fg_pagemap_validate(xfer))
			goto out;
		if (profile_ctx && profile_ctx->profile)
			profile_ctx->profile_parent_validate_us +=
				dsa_profile_delta_us(phase_start_us, dsa_profile_wall_now_us());
		if (profile_ctx && profile_ctx->profile)
			phase_start_us = dsa_profile_wall_now_us();
		if (hot_fg_pagemap_emit(xfer))
			goto out;
		if (profile_ctx && profile_ctx->profile)
			profile_ctx->profile_pagemap_pack_us +=
				dsa_profile_delta_us(phase_start_us, dsa_profile_wall_now_us());
	}
	if (profile_ctx && profile_ctx->profile)
		profile_ctx->profile_pagemap_us += profile_ctx->profile_pagemap_plan_us +
			profile_ctx->profile_parent_validate_us + profile_ctx->profile_pagemap_pack_us;
	if (profile_ctx && profile_ctx->profile)
		phase_start_us = dsa_profile_wall_now_us();
	ret = hot_apply_finish(xfer);
	if (profile_ctx && profile_ctx->profile)
		profile_ctx->profile_finish_us += dsa_profile_delta_us(phase_start_us,
								      dsa_profile_wall_now_us());
	goto out;

out:
	hot_profile_emit(profile_ctx, ret);
	return ret;
}

/*
 * Return:
 *	 1 - if a parent image exists
 *	 0 - if a parent image doesn't exist
 *	-1 - in error cases
 */
int check_parent_local_xfer(int fd_type, unsigned long img_id)
{
	char path[PATH_MAX];
	struct stat st;
	int ret, pfd;

	/* Image streaming lacks support for incremental images */
	if (opts.stream)
		return 0;

	if (open_parent(get_service_fd(IMG_FD_OFF), &pfd))
		return -1;
	if (pfd < 0)
		return 0;

	snprintf(path, sizeof(path), imgset_template[fd_type].fmt, img_id);
	ret = fstatat(pfd, path, &st, 0);
	if (ret == -1 && errno != ENOENT) {
		pr_perror("Unable to stat %s", path);
		close(pfd);
		return -1;
	}

	close(pfd);
	return (ret == 0);
}

/* page server */
static int page_server_check_parent(int sk, struct page_server_iov *pi)
{
	int type, ret;
	unsigned long id;

	type = decode_pm(pi->dst_id, &id);
	if (type == -1) {
		pr_err("Unknown pagemap type received\n");
		return -1;
	}

	ret = check_parent_local_xfer(type, id);
	if (ret < 0)
		return -1;

	if (__send(sk, &ret, sizeof(ret), 0) != sizeof(ret)) {
		pr_perror("Unable to send response");
		return -1;
	}

	return 0;
}

static int check_parent_server_xfer(int fd_type, unsigned long img_id)
{
	struct page_server_iov pi = {};
	int has_parent;

	pi.cmd = PS_IOV_PARENT;
	pi.dst_id = encode_pm(fd_type, img_id);

	if (send_psi(page_server_sk, &pi))
		return -1;

	tcp_nodelay(page_server_sk, true);

	if (__recv(page_server_sk, &has_parent, sizeof(int), 0) != sizeof(int)) {
		pr_perror("The page server doesn't answer");
		return -1;
	}

	return has_parent;
}

int check_parent_page_xfer(int fd_type, unsigned long img_id)
{
	if (opts.use_page_server)
		return check_parent_server_xfer(fd_type, img_id);
	else
		return check_parent_local_xfer(fd_type, img_id);
}

struct page_xfer_job {
	u64 dst_id;
	int p[2];
	unsigned pipe_size;
	struct page_xfer loc_xfer;
};

static struct page_xfer_job cxfer = {
	.dst_id = ~0,
};

static struct pipe_read_dest pipe_read_dest = {
	.sink_fd = -1,
};

static void page_server_close(void)
{
	if (cxfer.dst_id != ~0)
		cxfer.loc_xfer.close(&cxfer.loc_xfer);
	if (pipe_read_dest.sink_fd != -1) {
		close(pipe_read_dest.sink_fd);
		close(pipe_read_dest.p[0]);
		close(pipe_read_dest.p[1]);
	}
}

static int page_server_open(int sk, struct page_server_iov *pi)
{
	int type;
	unsigned long id;

	type = decode_pm(pi->dst_id, &id);
	if (type == -1) {
		pr_err("Unknown pagemap type received\n");
		return -1;
	}

	pr_info("Opening %d/%lu\n", type, id);

	page_server_close();

	if (open_page_local_xfer(&cxfer.loc_xfer, type, id))
		return -1;

	cxfer.dst_id = pi->dst_id;

	if (sk >= 0) {
		char has_parent = !!cxfer.loc_xfer.parent;
		if (__send(sk, &has_parent, 1, 0) != 1) {
			pr_perror("Unable to send response");
			close_page_xfer(&cxfer.loc_xfer);
			return -1;
		}
	}

	return 0;
}

static int prep_loc_xfer(struct page_server_iov *pi)
{
	if (cxfer.dst_id != pi->dst_id) {
		pr_warn("Deprecated IO w/o open\n");
		return page_server_open(-1, pi);
	} else
		return 0;
}

static int page_server_add(int sk, struct page_server_iov *pi, u32 flags)
{
	size_t len;
	struct page_xfer *lxfer = &cxfer.loc_xfer;
	struct iovec iov;

	pr_debug("Adding %" PRIx64 " - %" PRIx64 "\n",
		 pi->vaddr, pi->vaddr + pi->nr_pages * PAGE_SIZE);

	if (prep_loc_xfer(pi))
		return -1;

	psi2iovec(pi, &iov);
	if (lxfer->write_pagemap(lxfer, &iov, flags))
		return -1;

	if (!(flags & PE_PRESENT))
		return 0;

	len = iov.iov_len;
	while (len > 0) {
		ssize_t chunk;

		chunk = len;
		if (chunk > cxfer.pipe_size)
			chunk = cxfer.pipe_size;

		/*
		 * Splicing into a pipe may end up blocking if pipe is "full",
		 * and we need the SPLICE_F_NONBLOCK flag here. At the same time
		 * splicing from UNIX socket with this flag aborts splice with
		 * the EAGAIN if there's no data in it (TCP looks at the socket
		 * O_NONBLOCK flag _only_ and waits for data), so before doing
		 * the non-blocking splice we need to explicitly wait.
		 */

		if (sk_wait_data(sk) < 0) {
			pr_perror("Can't poll socket");
			return -1;
		}

		if (opts.tls) {
			if (tls_recv_data_to_fd(cxfer.p[1], chunk)) {
				pr_err("Can't read from socket\n");
				return -1;
			}
		} else {
			chunk = splice(sk, NULL, cxfer.p[1], NULL, chunk, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);

			if (chunk < 0) {
				pr_perror("Can't read from socket");
				return -1;
			}
			if (chunk == 0) {
				pr_err("A socket was closed unexpectedly\n");
				return -1;
			}
		}

		if (lxfer->write_pages(lxfer, cxfer.p[0], chunk))
			return -1;

		len -= chunk;
	}

	return 0;
}

static int page_server_get_pages(int sk, struct page_server_iov *pi)
{
	struct pstree_item *item;
	struct page_pipe *pp;
	unsigned long len, nr_pages;
	int ret;

	item = pstree_item_by_virt(pi->dst_id);
	pp = dmpi(item)->mem_pp;

	/* page_pipe_read() uses 'unsigned long *' but pi->nr_pages is u64.
	 * Use a temporary variable to fix the incompatible pointer type
	 * on 32-bit platforms (e.g. armv7). */
	nr_pages = pi->nr_pages;
	ret = page_pipe_read(pp, &pipe_read_dest, pi->vaddr, &nr_pages, PPB_LAZY);
	if (ret)
		return ret;

	/*
	 * The pi is reused for send_psi here, so .nr_pages, .vaddr and
	 * .dst_id all remain intact.
	 */

	pi->nr_pages = nr_pages;
	if (pi->nr_pages == 0) {
		pr_debug("no iovs found, zero pages\n");
		return -1;
	}

	pi->cmd = encode_ps_cmd(PS_IOV_ADD_F, PE_PRESENT);
	if (send_psi(sk, pi))
		return -1;

	len = pi->nr_pages * PAGE_SIZE;

	if (opts.tls) {
		if (tls_send_data_from_fd(pipe_read_dest.p[0], len))
			return -1;
	} else {
		ret = splice(pipe_read_dest.p[0], NULL, sk, NULL, len, SPLICE_F_MOVE);
		if (ret != len)
			return -1;
	}

	tcp_nodelay(sk, true);

	return 0;
}

static int page_server_serve(int sk)
{
	int ret = -1;
	bool flushed = false;
	bool receiving_pages = !opts.lazy_pages;

	if (receiving_pages) {
		/*
		 * This socket only accepts data except one thing -- it
		 * writes back the has_parent bit from time to time, so
		 * make it NODELAY all the time.
		 */
		tcp_nodelay(sk, true);

		if (pipe(cxfer.p)) {
			pr_perror("Can't make pipe for xfer");
			close(sk);
			return -1;
		}

		cxfer.pipe_size = fcntl(cxfer.p[0], F_GETPIPE_SZ, 0);
		pr_debug("Created xfer pipe size %u\n", cxfer.pipe_size);
	} else {
		pipe_read_dest_init(&pipe_read_dest);
		tcp_cork(sk, true);
	}

	while (1) {
		struct page_server_iov pi;
		u32 cmd;

		ret = __recv(sk, &pi, sizeof(pi), MSG_WAITALL);
		if (!ret)
			break;

		if (ret != sizeof(pi)) {
			pr_perror("Can't read pagemap from socket");
			ret = -1;
			break;
		}

		flushed = false;
		cmd = decode_ps_cmd(pi.cmd);

		switch (cmd) {
		case PS_IOV_OPEN:
			ret = page_server_open(-1, &pi);
			break;
		case PS_IOV_OPEN2:
			ret = page_server_open(sk, &pi);
			break;
		case PS_IOV_PARENT:
			ret = page_server_check_parent(sk, &pi);
			break;
		case PS_IOV_ADD_F:
		case PS_IOV_ADD:
		case PS_IOV_HOLE: {
			u32 flags;

			if (likely(cmd == PS_IOV_ADD_F))
				flags = decode_ps_flags(pi.cmd);
			else if (cmd == PS_IOV_ADD)
				flags = PE_PRESENT;
			else /* PS_IOV_HOLE */
				flags = PE_PARENT;

			ret = page_server_add(sk, &pi, flags);
			break;
		}
		case PS_IOV_CLOSE:
		case PS_IOV_FORCE_CLOSE: {
			int32_t status = 0;

			ret = 0;

			/*
			 * An answer must be sent back to inform another side,
			 * that all data were received
			 */
			if (__send(sk, &status, sizeof(status), 0) != sizeof(status)) {
				pr_perror("Can't send the final package");
				ret = -1;
			}

			flushed = true;
			break;
		}
		case PS_IOV_GET:
			ret = page_server_get_pages(sk, &pi);
			break;
		default:
			pr_err("Unknown command %u\n", pi.cmd);
			ret = -1;
			break;
		}

		if (ret)
			break;
		if (pi.cmd == PS_IOV_CLOSE || pi.cmd == PS_IOV_FORCE_CLOSE)
			break;
	}

	if (receiving_pages && !ret && !flushed) {
		pr_err("The data were not flushed\n");
		ret = -1;
	}

	tls_terminate_session(ret != 0);

	if (ret == 0 && opts.ps_socket == -1) {
		char c;

		/*
		 * Wait when a remote side closes the connection
		 * to avoid TIME_WAIT bucket
		 */
		if (read(sk, &c, sizeof(c)) != 0) {
			pr_perror("Unexpected data");
			ret = -1;
		}
	}

	page_server_close();

	pr_info("Session over\n");

	close(sk);
	return ret;
}

static int fill_page_pipe(struct page_read *pr, struct page_pipe *pp)
{
	struct page_pipe_buf *ppb;
	int i, ret;

	pr->reset(pr);

	while (pr->advance(pr)) {
		unsigned long vaddr = pr->pe->vaddr;

		for (i = 0; i < pr->pe->nr_pages; i++, vaddr += PAGE_SIZE) {
			if (pagemap_in_parent(pr->pe))
				ret = page_pipe_add_hole(pp, vaddr, PP_HOLE_PARENT);
			else
				ret = page_pipe_add_page(pp, vaddr, pagemap_lazy(pr->pe) ? PPB_LAZY : 0);
			if (ret) {
				pr_err("Failed adding page at %lx\n", vaddr);
				return -1;
			}
		}
	}

	list_for_each_entry(ppb, &pp->bufs, l) {
		for (i = 0; i < ppb->nr_segs; i++) {
			struct iovec iov = ppb->iov[i];

			if (splice(img_raw_fd(pr->pi), NULL, ppb->p[1], NULL, iov.iov_len, SPLICE_F_MOVE) !=
			    iov.iov_len) {
				pr_perror("Splice failed");
				return -1;
			}
		}
	}

	debug_show_page_pipe(pp);

	return 0;
}

static int page_pipe_from_pagemap(struct page_pipe **pp, int pid)
{
	struct page_read pr;
	unsigned long nr_pages = 0;
	int ret = -1;

	if (open_page_read(pid, &pr, PR_TASK) <= 0) {
		pr_err("Failed to open page read for %d\n", pid);
		return -1;
	}

	while (pr.advance(&pr))
		if (pagemap_present(pr.pe))
			nr_pages += pr.pe->nr_pages;

	*pp = create_page_pipe(nr_pages, NULL, 0);
	if (!*pp) {
		pr_err("Cannot create page pipe for %d\n", pid);
		goto err;
	}

	if (fill_page_pipe(&pr, *pp))
		goto err_pp;

	ret = 0;
err:
	pr.close(&pr);
	return ret;
err_pp:
	destroy_page_pipe(*pp);
	*pp = NULL;
	goto err;
}

static int page_server_init_send(void)
{
	struct pstree_item *pi;
	struct page_pipe *pp;

	BUILD_BUG_ON(sizeof(struct dmp_info) > sizeof(struct rst_info));

	if (prepare_dummy_pstree())
		return -1;

	for_each_pstree_item(pi) {
		if (prepare_dummy_task_state(pi))
			return -1;

		if (!task_alive(pi))
			continue;

		if (page_pipe_from_pagemap(&pp, vpid(pi))) {
			pr_err("%d: failed to open page-read\n", vpid(pi));
			return -1;
		}

		/*
		 * prepare_dummy_pstree presumes 'restore' behaviour,
		 * but page_server_get_pages uses dmpi() to get access
		 * to the page-pipe, so we are faking it here.
		 */
		memset(rsti(pi), 0, sizeof(struct rst_info));
		dmpi(pi)->mem_pp = pp;
	}

	return 0;
}

int cr_page_server(bool daemon_mode, bool lazy_dump, int cfd)
{
	int ask = -1;
	int sk = -1;
	int ret;

	if (init_stats(DUMP_STATS))
		return -1;

	if (!opts.lazy_pages)
		up_page_ids_base();
	else if (!lazy_dump)
		if (page_server_init_send())
			return -1;

	if (opts.ps_socket != -1) {
		ask = opts.ps_socket;
		pr_info("Reusing ps socket %d\n", ask);
		goto no_server;
	}

	sk = setup_tcp_server("page", opts.addr, &opts.port);
	if (sk == -1)
		return -1;
no_server:

	if (!daemon_mode && cfd >= 0) {
		struct ps_info info = { .pid = getpid(), .port = opts.port };
		int count;

		count = write(cfd, &info, sizeof(info));
		close_safe(&cfd);
		if (count != sizeof(info)) {
			pr_perror("Unable to write ps_info");
			exit(1);
		}
	}

	ret = run_tcp_server(daemon_mode, &ask, cfd, sk);
	if (ret != 0)
		return ret > 0 ? 0 : -1;

	if (tls_x509_init(ask, true)) {
		close_safe(&sk);
		return -1;
	}

	if (ask >= 0)
		ret = page_server_serve(ask);

	if (daemon_mode)
		exit(ret);

	return ret;
}

static int connect_to_page_server(void)
{
	if (!opts.use_page_server)
		return 0;

	if (opts.ps_socket != -1) {
		page_server_sk = opts.ps_socket;
		pr_info("Reusing ps socket %d\n", page_server_sk);
		goto out;
	}

	page_server_sk = setup_tcp_client(opts.addr);
	if (page_server_sk == -1)
		return -1;

	if (tls_x509_init(page_server_sk, false)) {
		close(page_server_sk);
		return -1;
	}
out:
	/*
	 * CORK the socket at the very beginning. As per ANK
	 * the corked by default socket with sporadic NODELAY-s
	 * on urgent data is the smartest mode ever.
	 */
	tcp_cork(page_server_sk, true);
	return 0;
}

int connect_to_page_server_to_send(void)
{
	return connect_to_page_server();
}

int disconnect_from_page_server(void)
{
	struct page_server_iov pi = {};
	int32_t status = -1;
	int ret = -1;

	if (!opts.use_page_server)
		return 0;

	if (page_server_sk == -1)
		return 0;

	pr_info("Disconnect from the page server\n");

	if (opts.ps_socket != -1)
		/*
		 * The socket might not get closed (held by
		 * the parent process) so we must order the
		 * page-server to terminate itself.
		 */
		pi.cmd = PS_IOV_FORCE_CLOSE;
	else
		pi.cmd = PS_IOV_CLOSE;

	if (send_psi(page_server_sk, &pi))
		goto out;

	if (__recv(page_server_sk, &status, sizeof(status), 0) != sizeof(status)) {
		pr_perror("The page server doesn't answer");
		goto out;
	}

	ret = 0;
out:
	tls_terminate_session(ret != 0);
	close_safe(&page_server_sk);

	return ret ?: status;
}

struct ps_async_read {
	unsigned long rb; /* read bytes */
	unsigned long goal;
	unsigned long nr_pages;

	struct page_server_iov pi;
	void *pages;

	ps_async_read_complete complete;
	void *priv;

	struct list_head l;
};

static LIST_HEAD(async_reads);

static inline void async_read_set_goal(struct ps_async_read *ar, unsigned long nr_pages)
{
	ar->goal = sizeof(ar->pi) + nr_pages * PAGE_SIZE;
	ar->nr_pages = nr_pages;
}

static void init_ps_async_read(struct ps_async_read *ar, void *buf, unsigned long nr_pages, ps_async_read_complete complete,
			       void *priv)
{
	ar->pages = buf;
	ar->rb = 0;
	ar->complete = complete;
	ar->priv = priv;
	async_read_set_goal(ar, nr_pages);
}

static int page_server_start_async_read(void *buf, unsigned long nr_pages, ps_async_read_complete complete, void *priv)
{
	struct ps_async_read *ar;

	ar = xmalloc(sizeof(*ar));
	if (ar == NULL)
		return -1;

	init_ps_async_read(ar, buf, nr_pages, complete, priv);
	list_add_tail(&ar->l, &async_reads);
	return 0;
}

/*
 * There are two possible event types we need to handle:
 * - page info is available as a reply to request_remote_page
 * - page data is available, and it follows page info we've just received
 * Since the on dump side communications are completely synchronous,
 * we can return to epoll right after the reception of page info and
 * for sure the next time socket event will occur we'll get page data
 * related to info we've just received
 */
static int page_server_read(struct ps_async_read *ar, int flags)
{
	int ret, need;
	void *buf;

	if (ar->rb < sizeof(ar->pi)) {
		/* Header */
		buf = ((void *)&ar->pi) + ar->rb;
		need = sizeof(ar->pi) - ar->rb;
	} else {
		/* page-serer may return less pages than we asked for */
		if (ar->pi.nr_pages < ar->nr_pages)
			async_read_set_goal(ar, ar->pi.nr_pages);
		/* Page(s) data itself */
		buf = ar->pages + (ar->rb - sizeof(ar->pi));
		need = ar->goal - ar->rb;
	}

	ret = __recv(page_server_sk, buf, need, flags);
	if (ret < 0) {
		if (flags == MSG_DONTWAIT && (errno == EAGAIN || errno == EINTR)) {
			ret = 0;
		} else {
			pr_perror("Error reading data from page server");
			return -1;
		}
	}

	ar->rb += ret;
	if (ar->rb < ar->goal)
		return 1;

	/*
	 * IO complete -- notify the caller and drop the request
	 */
	BUG_ON(ar->rb > ar->goal);
	return ar->complete((int)ar->pi.dst_id, (unsigned long)ar->pi.vaddr, (int)ar->pi.nr_pages, ar->priv);
}

static int page_server_async_read(struct epoll_rfd *f)
{
	struct ps_async_read *ar;
	int ret;

	BUG_ON(list_empty(&async_reads));
	ar = list_first_entry(&async_reads, struct ps_async_read, l);
	ret = page_server_read(ar, MSG_DONTWAIT);

	if (ret > 0)
		return 0;
	if (!ret) {
		list_del(&ar->l);
		xfree(ar);
	}

	return ret;
}

static int page_server_hangup_event(struct epoll_rfd *rfd)
{
	pr_err("Remote side closed connection\n");
	return -1;
}

static struct epoll_rfd ps_rfd;

int connect_to_page_server_to_recv(int epfd)
{
	if (connect_to_page_server())
		return -1;

	ps_rfd.fd = page_server_sk;
	ps_rfd.read_event = page_server_async_read;
	ps_rfd.hangup_event = page_server_hangup_event;

	return epoll_add_rfd(epfd, &ps_rfd);
}

int request_remote_pages(unsigned long img_id, unsigned long addr, unsigned long nr_pages)
{
	struct page_server_iov pi = {
		.cmd = PS_IOV_GET,
		.nr_pages = nr_pages,
		.vaddr = addr,
		.dst_id = img_id,
	};

	/* XXX: why MSG_DONTWAIT here? */
	if (send_psi_flags(page_server_sk, &pi, MSG_DONTWAIT))
		return -1;

	tcp_nodelay(page_server_sk, true);
	return 0;
}

static int page_server_start_sync_read(void *buf, unsigned long nr, ps_async_read_complete complete, void *priv)
{
	struct ps_async_read ar;
	int ret = 1;

	init_ps_async_read(&ar, buf, nr, complete, priv);
	while (ret == 1)
		ret = page_server_read(&ar, MSG_WAITALL);
	return ret;
}

int page_server_start_read(void *buf, unsigned long nr, ps_async_read_complete complete, void *priv, unsigned flags)
{
	if (flags & PR_ASYNC)
		return page_server_start_async_read(buf, nr, complete, priv);
	else
		return page_server_start_sync_read(buf, nr, complete, priv);
}
