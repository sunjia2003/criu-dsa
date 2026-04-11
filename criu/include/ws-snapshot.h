#ifndef __CR_WS_SNAPSHOT_H__
#define __CR_WS_SNAPSHOT_H__

#include <limits.h>
#include <pthread.h>
#include <stdbool.h>

enum ws_snapshot_state {
	WS_SNAPSHOT_DISABLED = 0,
	WS_SNAPSHOT_WAIT_START,
	WS_SNAPSHOT_RUNNING,
	WS_SNAPSHOT_DONE_OK,
	WS_SNAPSHOT_DONE_ERR,
};

struct workspace_snapshot_ctx {
	bool enabled;
	bool sync_prim_inited;
	bool thread_created;
	pthread_t tid;
	pthread_mutex_t lock;
	pthread_cond_t cond;
	bool start_requested;
	bool stop_requested;
	enum ws_snapshot_state state;
	int result_errno;
	char reason[256];
	char snapshot_name[128];
	char snapshot_path[PATH_MAX];
	char *source_root;
	char *snapshot_parent;
	char *snapshot_dir_name;
	char *meta_dir_name;
	bool strict_nested_subvol;
	int target_pid;
};

int ws_snapshot_ctx_init(struct workspace_snapshot_ctx *ctx, int target_pid,
			 const char *source_root,
			 const char *snapshot_parent,
			 const char *snapshot_dir_name,
			 const char *meta_dir_name,
			 bool strict_nested_subvol);
int ws_snapshot_start(struct workspace_snapshot_ctx *ctx);
int ws_snapshot_gate_check_nonblocking(struct workspace_snapshot_ctx *ctx);
int ws_snapshot_join_and_finalize(struct workspace_snapshot_ctx *ctx);
void ws_snapshot_ctx_destroy(struct workspace_snapshot_ctx *ctx);
bool ws_snapshot_ctx_enabled(const struct workspace_snapshot_ctx *ctx);

#endif /* __CR_WS_SNAPSHOT_H__ */
