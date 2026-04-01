#ifndef __CR_STATS_H__
#define __CR_STATS_H__

enum {
	TIME_FREEZING,
	TIME_FROZEN,
	TIME_MEMDUMP,
	TIME_MEMWRITE,
	TIME_DSA_RPC,
	TIME_ASYNC_WAIT,
	TIME_IRMAP_RESOLVE,

	DUMP_TIME_NR_STATS,
};

enum dump_work_scope {
	WORK_SCOPE_PREPARE,
	WORK_SCOPE_OTHER_RES_DUMP,
	WORK_SCOPE_MEM_WRITE_SYNC,
	WORK_SCOPE_MEM_WRITE_ASYNC,
	WORK_SCOPE_MEM_WRITE_WAIT,
	WORK_SCOPE_MEM_SCAN_IOV,
	WORK_SCOPE_MEM_DRAIN_BASE_RPC,
	WORK_SCOPE_MEM_DSA_CTX_INIT,
	WORK_SCOPE_MEM_DSA_BATCH_BUILD,
	WORK_SCOPE_MEM_DSA_RPC,
	WORK_SCOPE_MEM_DSA_REPLAY,
	WORK_SCOPE_MEM_DUMP_MISC,

	DUMP_WORK_SCOPE_NR,
};

enum dump_work_main {
	WORK_MAIN_PREPARE,
	WORK_MAIN_MEM_DUMP,
	WORK_MAIN_OTHER_RES_DUMP,
	WORK_MAIN_MEM_WRITE,

	DUMP_WORK_MAIN_NR,
};

enum dump_work_mem {
	WORK_MEM_SCAN_IOV,
	WORK_MEM_BASE_RPC,
	WORK_MEM_DSA_CTX_INIT,
	WORK_MEM_DSA_BATCH_BUILD,
	WORK_MEM_DSA_RPC,
	WORK_MEM_DSA_REPLAY,
	WORK_MEM_MISC,

	DUMP_WORK_MEM_NR,
};

enum {
	TIME_FORK,
	TIME_RESTORE,

	RESTORE_TIME_NS_STATS,
};

extern void timing_start(int t);
extern void timing_stop(int t);
extern u64 timing_total_usecs(int t);

enum {
	CNT_PAGES_SCANNED,
	CNT_PAGES_SKIPPED_PARENT,
	CNT_PAGES_WRITTEN,
	CNT_PAGES_LAZY,
	CNT_PAGE_PIPES,
	CNT_PAGE_PIPE_BUFS,

	CNT_SHPAGES_SCANNED,
	CNT_SHPAGES_SKIPPED_PARENT,
	CNT_SHPAGES_WRITTEN,

	DUMP_CNT_NR_STATS,
};

enum {
	CNT_PAGES_COMPARED,
	CNT_PAGES_SKIPPED_COW,
	CNT_PAGES_RESTORED,

	RESTORE_CNT_NR_STATS,
};

extern void cnt_add(int c, unsigned long val);
extern void cnt_sub(int c, unsigned long val);

#define DUMP_STATS    1
#define RESTORE_STATS 2

extern int init_stats(int what);
extern void write_stats(int what);

extern void workload_bind_scope(int scope);
extern void workload_switch_scope(int scope);
extern void workload_unbind_scope(void);
extern u64 workload_total_usecs(void);
extern u64 workload_main_total_usecs(int main_id);
extern u64 workload_mem_total_usecs(int mem_id);
extern void workload_dump_log(const char *tag);

#endif /* __CR_STATS_H__ */
