#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/time.h>
#include <string.h>
#include "int.h"
#include "atomic.h"
#include "cr_options.h"
#include "rst-malloc.h"
#include "protobuf.h"
#include "stats.h"
#include "util.h"
#include "image.h"
#include "images/stats.pb-c.h"

struct timing {
	struct timeval start;
	struct timeval total;
};

struct dump_stats {
	struct timing timings[DUMP_TIME_NR_STATS];
	unsigned long counts[DUMP_CNT_NR_STATS];
	u64 work_ns[DUMP_WORK_SCOPE_NR];
};

struct restore_stats {
	struct timing timings[RESTORE_TIME_NS_STATS];
	atomic_t counts[RESTORE_CNT_NR_STATS];
};

struct dump_stats *dstats;
struct restore_stats *rstats;

struct workload_tls {
	bool active;
	int scope;
	u64 last_ns;
};

static __thread struct workload_tls workload_tls;

static inline u64 mono_time_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts))
		return 0;

	return (u64)ts.tv_sec * 1000000000ULL + (u64)ts.tv_nsec;
}

static inline int workload_scope_to_main(int scope)
{
	switch (scope) {
	case WORK_SCOPE_PREPARE:
		return WORK_MAIN_PREPARE;
	case WORK_SCOPE_OTHER_RES_DUMP:
		return WORK_MAIN_OTHER_RES_DUMP;
	case WORK_SCOPE_MEM_WRITE_SYNC:
	case WORK_SCOPE_MEM_WRITE_ASYNC:
	case WORK_SCOPE_MEM_WRITE_WAIT:
		return WORK_MAIN_MEM_WRITE;
	case WORK_SCOPE_MEM_SCAN_IOV:
	case WORK_SCOPE_MEM_DRAIN_BASE_RPC:
	case WORK_SCOPE_MEM_DSA_CTX_INIT:
	case WORK_SCOPE_MEM_DSA_BATCH_BUILD:
	case WORK_SCOPE_MEM_DSA_RPC:
	case WORK_SCOPE_MEM_DSA_REPLAY:
	case WORK_SCOPE_MEM_DUMP_MISC:
		return WORK_MAIN_MEM_DUMP;
	default:
		return -1;
	}
}

static inline int workload_scope_to_mem(int scope)
{
	switch (scope) {
	case WORK_SCOPE_MEM_SCAN_IOV:
		return WORK_MEM_SCAN_IOV;
	case WORK_SCOPE_MEM_DRAIN_BASE_RPC:
		return WORK_MEM_BASE_RPC;
	case WORK_SCOPE_MEM_DSA_CTX_INIT:
		return WORK_MEM_DSA_CTX_INIT;
	case WORK_SCOPE_MEM_DSA_BATCH_BUILD:
		return WORK_MEM_DSA_BATCH_BUILD;
	case WORK_SCOPE_MEM_DSA_RPC:
		return WORK_MEM_DSA_RPC;
	case WORK_SCOPE_MEM_DSA_REPLAY:
		return WORK_MEM_DSA_REPLAY;
	case WORK_SCOPE_MEM_DUMP_MISC:
		return WORK_MEM_MISC;
	default:
		return -1;
	}
}

static inline void workload_acc_scope_ns(int scope, u64 delta_ns)
{
	if (!dstats || !delta_ns)
		return;

	BUG_ON(scope < 0 || scope >= DUMP_WORK_SCOPE_NR);
	__sync_fetch_and_add(&dstats->work_ns[scope], delta_ns);
}

void workload_bind_scope(int scope)
{
	if (!dstats)
		return;

	BUG_ON(scope < 0 || scope >= DUMP_WORK_SCOPE_NR);

	if (workload_tls.active) {
		workload_switch_scope(scope);
		return;
	}

	workload_tls.active = true;
	workload_tls.scope = scope;
	workload_tls.last_ns = mono_time_ns();
}

void workload_switch_scope(int scope)
{
	u64 now;
	u64 delta;

	if (!dstats)
		return;

	BUG_ON(scope < 0 || scope >= DUMP_WORK_SCOPE_NR);

	if (!workload_tls.active) {
		workload_bind_scope(scope);
		return;
	}

	now = mono_time_ns();
	if (now > workload_tls.last_ns) {
		delta = now - workload_tls.last_ns;
		workload_acc_scope_ns(workload_tls.scope, delta);
	}

	workload_tls.scope = scope;
	workload_tls.last_ns = now;
}

void workload_unbind_scope(void)
{
	u64 now;
	u64 delta;

	if (!dstats || !workload_tls.active)
		return;

	now = mono_time_ns();
	if (now > workload_tls.last_ns) {
		delta = now - workload_tls.last_ns;
		workload_acc_scope_ns(workload_tls.scope, delta);
	}

	workload_tls.active = false;
	workload_tls.scope = WORK_SCOPE_PREPARE;
	workload_tls.last_ns = 0;
}

u64 workload_total_usecs(void)
{
	u64 total_ns = 0;
	int i;

	if (!dstats)
		return 0;

	for (i = 0; i < DUMP_WORK_SCOPE_NR; i++)
		total_ns += dstats->work_ns[i];

	return total_ns / 1000;
}

u64 workload_main_total_usecs(int main_id)
{
	u64 total_ns = 0;
	int i;

	if (!dstats)
		return 0;

	BUG_ON(main_id < 0 || main_id >= DUMP_WORK_MAIN_NR);

	for (i = 0; i < DUMP_WORK_SCOPE_NR; i++) {
		if (workload_scope_to_main(i) == main_id)
			total_ns += dstats->work_ns[i];
	}

	return total_ns / 1000;
}

u64 workload_mem_total_usecs(int mem_id)
{
	u64 total_ns = 0;
	int i;

	if (!dstats)
		return 0;

	BUG_ON(mem_id < 0 || mem_id >= DUMP_WORK_MEM_NR);

	for (i = 0; i < DUMP_WORK_SCOPE_NR; i++) {
		if (workload_scope_to_mem(i) == mem_id)
			total_ns += dstats->work_ns[i];
	}

	return total_ns / 1000;
}

void workload_dump_log(const char *tag)
{
	u64 total_us;
	u64 prepare_us;
	u64 memdump_us;
	u64 other_us;
	u64 memwrite_us;
	u64 scan_iov_us;
	u64 base_rpc_us;
	u64 dsa_ctx_us;
	u64 dsa_build_us;
	u64 dsa_rpc_us;
	u64 dsa_replay_us;
	u64 mem_misc_us;
	s64 main_delta;
	s64 mem_delta;

	if (!dstats)
		return;

	total_us = workload_total_usecs();
	prepare_us = workload_main_total_usecs(WORK_MAIN_PREPARE);
	memdump_us = workload_main_total_usecs(WORK_MAIN_MEM_DUMP);
	other_us = workload_main_total_usecs(WORK_MAIN_OTHER_RES_DUMP);
	memwrite_us = workload_main_total_usecs(WORK_MAIN_MEM_WRITE);

	scan_iov_us = workload_mem_total_usecs(WORK_MEM_SCAN_IOV);
	base_rpc_us = workload_mem_total_usecs(WORK_MEM_BASE_RPC);
	dsa_ctx_us = workload_mem_total_usecs(WORK_MEM_DSA_CTX_INIT);
	dsa_build_us = workload_mem_total_usecs(WORK_MEM_DSA_BATCH_BUILD);
	dsa_rpc_us = workload_mem_total_usecs(WORK_MEM_DSA_RPC);
	dsa_replay_us = workload_mem_total_usecs(WORK_MEM_DSA_REPLAY);
	mem_misc_us = workload_mem_total_usecs(WORK_MEM_MISC);

	main_delta = (s64)total_us -
		     (s64)(prepare_us + memdump_us + other_us + memwrite_us);
	mem_delta = (s64)memdump_us -
		    (s64)(scan_iov_us + base_rpc_us + dsa_ctx_us + dsa_build_us +
			  dsa_rpc_us + dsa_replay_us + mem_misc_us);

	pr_info("%s WORKLOAD_TASK: total_work=%llu us prepare=%llu us memdump=%llu us other_res=%llu us memwrite=%llu us\n",
		tag ? tag : "Dump",
		(unsigned long long)total_us,
		(unsigned long long)prepare_us,
		(unsigned long long)memdump_us,
		(unsigned long long)other_us,
		(unsigned long long)memwrite_us);

	pr_info("%s WORKLOAD_MEMDUMP_BREAKDOWN: scan_iov=%llu us base_rpc=%llu us dsa_ctx_init=%llu us dsa_batch_build=%llu us dsa_rpc=%llu us dsa_replay=%llu us misc=%llu us\n",
		tag ? tag : "Dump",
		(unsigned long long)scan_iov_us,
		(unsigned long long)base_rpc_us,
		(unsigned long long)dsa_ctx_us,
		(unsigned long long)dsa_build_us,
		(unsigned long long)dsa_rpc_us,
		(unsigned long long)dsa_replay_us,
		(unsigned long long)mem_misc_us);

	pr_info("%s WORKLOAD_CHECK: main_sum_delta=%lld us memdump_sum_delta=%lld us\n",
		tag ? tag : "Dump",
		(long long)main_delta,
		(long long)mem_delta);
}

void cnt_add(int c, unsigned long val)
{
	if (dstats != NULL) {
		BUG_ON(c >= DUMP_CNT_NR_STATS);
		dstats->counts[c] += val;
	} else if (rstats != NULL) {
		BUG_ON(c >= RESTORE_CNT_NR_STATS);
		atomic_add(val, &rstats->counts[c]);
	} else
		BUG();
}

void cnt_sub(int c, unsigned long val)
{
	if (dstats != NULL) {
		BUG_ON(c >= DUMP_CNT_NR_STATS);
		dstats->counts[c] -= val;
	} else if (rstats != NULL) {
		BUG_ON(c >= RESTORE_CNT_NR_STATS);
		atomic_add(-val, &rstats->counts[c]);
	} else
		BUG();
}

static void timeval_accumulate(const struct timeval *from, const struct timeval *to, struct timeval *res)
{
	suseconds_t usec;

	res->tv_sec += to->tv_sec - from->tv_sec;
	usec = to->tv_usec;
	if (usec < from->tv_usec) {
		usec += USEC_PER_SEC;
		res->tv_sec -= 1;
	}
	res->tv_usec += usec - from->tv_usec;
	if (res->tv_usec > USEC_PER_SEC) {
		res->tv_usec -= USEC_PER_SEC;
		res->tv_sec += 1;
	}
}

static struct timing *get_timing(int t)
{
	if (dstats != NULL) {
		BUG_ON(t >= DUMP_TIME_NR_STATS);
		return &dstats->timings[t];
	} else if (rstats != NULL) {
		/*
		 * FIXME -- this does _NOT_ work when called
		 * from different tasks.
		 */
		BUG_ON(t >= RESTORE_TIME_NS_STATS);
		return &rstats->timings[t];
	}

	BUG();
	return NULL;
}

void timing_start(int t)
{
	struct timing *tm;

	tm = get_timing(t);
	gettimeofday(&tm->start, NULL);
}

void timing_stop(int t)
{
	struct timing *tm;
	struct timeval now;

	/* stats haven't been initialized. */
	if (!dstats && !rstats)
		return;

	tm = get_timing(t);
	gettimeofday(&now, NULL);
	timeval_accumulate(&tm->start, &now, &tm->total);
}

u64 timing_total_usecs(int t)
{
	struct timing *tm;

	/* stats haven't been initialized. */
	if (!dstats && !rstats)
		return 0;

	tm = get_timing(t);

	return (u64)tm->total.tv_sec * USEC_PER_SEC + tm->total.tv_usec;
}

static void encode_time(int t, u_int32_t *to)
{
	struct timing *tm;

	tm = get_timing(t);
	*to = tm->total.tv_sec * USEC_PER_SEC + tm->total.tv_usec;
}

static void display_stats(int what, StatsEntry *stats)
{
	if (what == DUMP_STATS) {
		pr_msg("Displaying dump stats:\n");
		pr_msg("Freezing time: %d us\n", stats->dump->freezing_time);
		pr_msg("Frozen time: %d us\n", stats->dump->frozen_time);
		pr_msg("Memory dump time: %d us\n", stats->dump->memdump_time);
		pr_msg("Memory write time: %d us\n", stats->dump->memwrite_time);
		if (stats->dump->has_irmap_resolve)
			pr_msg("IRMAP resolve time: %d us\n", stats->dump->irmap_resolve);
		pr_msg("Memory pages scanned: %" PRIu64 " (0x%" PRIx64 ")\n", stats->dump->pages_scanned,
		       stats->dump->pages_scanned);
		pr_msg("Memory pages skipped from parent: %" PRIu64 " (0x%" PRIx64 ")\n",
		       stats->dump->pages_skipped_parent, stats->dump->pages_skipped_parent);
		pr_msg("Memory pages written: %" PRIu64 " (0x%" PRIx64 ")\n", stats->dump->pages_written,
		       stats->dump->pages_written);
		pr_msg("Lazy memory pages: %" PRIu64 " (0x%" PRIx64 ")\n", stats->dump->pages_lazy,
		       stats->dump->pages_lazy);
	} else if (what == RESTORE_STATS) {
		pr_msg("Displaying restore stats:\n");
		pr_msg("Pages compared: %" PRIu64 " (0x%" PRIx64 ")\n", stats->restore->pages_compared,
		       stats->restore->pages_compared);
		pr_msg("Pages skipped COW: %" PRIu64 " (0x%" PRIx64 ")\n", stats->restore->pages_skipped_cow,
		       stats->restore->pages_skipped_cow);
		if (stats->restore->has_pages_restored)
			pr_msg("Pages restored: %" PRIu64 " (0x%" PRIx64 ")\n", stats->restore->pages_restored,
			       stats->restore->pages_restored);
		pr_msg("Restore time: %d us\n", stats->restore->restore_time);
		pr_msg("Forking time: %d us\n", stats->restore->forking_time);
	} else
		return;
}

void write_stats(int what)
{
	StatsEntry stats = STATS_ENTRY__INIT;
	DumpStatsEntry ds_entry = DUMP_STATS_ENTRY__INIT;
	RestoreStatsEntry rs_entry = RESTORE_STATS_ENTRY__INIT;
	char *name;
	struct cr_img *img;

	pr_info("Writing stats\n");
	if (what == DUMP_STATS) {
		stats.dump = &ds_entry;

		encode_time(TIME_FREEZING, &ds_entry.freezing_time);
		encode_time(TIME_FROZEN, &ds_entry.frozen_time);
		encode_time(TIME_MEMDUMP, &ds_entry.memdump_time);
		encode_time(TIME_MEMWRITE, &ds_entry.memwrite_time);
		ds_entry.has_irmap_resolve = true;
		encode_time(TIME_IRMAP_RESOLVE, &ds_entry.irmap_resolve);

		ds_entry.pages_scanned = dstats->counts[CNT_PAGES_SCANNED];
		ds_entry.pages_skipped_parent = dstats->counts[CNT_PAGES_SKIPPED_PARENT];
		ds_entry.pages_written = dstats->counts[CNT_PAGES_WRITTEN];
		ds_entry.pages_lazy = dstats->counts[CNT_PAGES_LAZY];
		ds_entry.page_pipes = dstats->counts[CNT_PAGE_PIPES];
		ds_entry.has_page_pipes = true;
		ds_entry.page_pipe_bufs = dstats->counts[CNT_PAGE_PIPE_BUFS];
		ds_entry.has_page_pipe_bufs = true;

		ds_entry.shpages_scanned = dstats->counts[CNT_SHPAGES_SCANNED];
		ds_entry.has_shpages_scanned = true;
		ds_entry.shpages_skipped_parent = dstats->counts[CNT_SHPAGES_SKIPPED_PARENT];
		ds_entry.has_shpages_skipped_parent = true;
		ds_entry.shpages_written = dstats->counts[CNT_SHPAGES_WRITTEN];
		ds_entry.has_shpages_written = true;

		name = "dump";
	} else if (what == RESTORE_STATS) {
		stats.restore = &rs_entry;

		rs_entry.pages_compared = atomic_read(&rstats->counts[CNT_PAGES_COMPARED]);
		rs_entry.pages_skipped_cow = atomic_read(&rstats->counts[CNT_PAGES_SKIPPED_COW]);
		rs_entry.has_pages_restored = true;
		rs_entry.pages_restored = atomic_read(&rstats->counts[CNT_PAGES_RESTORED]);

		encode_time(TIME_FORK, &rs_entry.forking_time);
		encode_time(TIME_RESTORE, &rs_entry.restore_time);

		name = "restore";
	} else
		return;

	img = open_image_at(AT_FDCWD, CR_FD_STATS, O_DUMP, name);
	if (img) {
		pb_write_one(img, &stats, PB_STATS);
		close_image(img);
	}

	if (opts.display_stats)
		display_stats(what, &stats);
}

int init_stats(int what)
{
	if (what == DUMP_STATS) {
		/*
		 * Dumping happens via one process most of the time,
		 * so we are typically OK with the plain malloc, but
		 * when dumping namespaces we fork() a separate process
		 * for it and when it goes and dumps shmem segments
		 * it will alter the CNT_SHPAGES_ counters, so we need
		 * to have them in shmem.
		 */
		dstats = shmalloc(sizeof(*dstats));
		if (!dstats)
			return -1;

		memset(dstats, 0, sizeof(*dstats));
		return 0;
	}

	rstats = shmalloc(sizeof(struct restore_stats));
	if (!rstats)
		return -1;

	memset(rstats, 0, sizeof(*rstats));
	return 0;
}
