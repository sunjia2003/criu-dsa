#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <inttypes.h>
#include <linux/btrfs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "log.h"
#include "common/xmalloc.h"
#include "util.h"
#include "ws-snapshot.h"

#ifndef BTRFS_FIRST_FREE_OBJECTID
#define BTRFS_FIRST_FREE_OBJECTID 256ULL
#endif

struct ws_nested_scan_ctx {
	uint64_t root_subvolid;
	bool found;
	int err;
};

static struct ws_nested_scan_ctx *g_ws_scan_ctx;

static void ws_set_error(struct workspace_snapshot_ctx *ctx, int err, const char *msg)
{
	if (!ctx)
		return;

	ctx->result_errno = err ? err : EINVAL;
	snprintf(ctx->reason, sizeof(ctx->reason), "%s", msg);
}

static int ws_validate_component_name(const char *name)
{
	if (!name || !name[0])
		return -1;

	if (!strcmp(name, ".") || !strcmp(name, ".."))
		return -1;

	if (strchr(name, '/'))
		return -1;

	return 0;
}

static int ws_mkdirat_if_missing(int dirfd, const char *name, mode_t mode)
{
	struct stat st;

	if (!mkdirat(dirfd, name, mode))
		return 0;

	if (errno != EEXIST)
		return -1;

	if (fstatat(dirfd, name, &st, AT_SYMLINK_NOFOLLOW))
		return -1;

	if (!S_ISDIR(st.st_mode)) {
		errno = ENOTDIR;
		return -1;
	}

	return 0;
}

static int ws_get_subvol_id(int fd, uint64_t *subvolid)
{
	struct btrfs_ioctl_ino_lookup_args args;

	memset(&args, 0, sizeof(args));
	args.treeid = 0;
	args.objectid = BTRFS_FIRST_FREE_OBJECTID;

	if (ioctl(fd, BTRFS_IOC_INO_LOOKUP, &args))
		return -1;

	*subvolid = args.treeid;
	return 0;
}

static int ws_nested_scan_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
	uint64_t subvolid;
	int fd;

	if (!g_ws_scan_ctx)
		return -1;

	if (typeflag != FTW_D)
		return 0;

	if (!ftwbuf || ftwbuf->level == 0)
		return 0;

	if ((uint64_t)sb->st_ino != BTRFS_FIRST_FREE_OBJECTID)
		return 0;

	fd = open(fpath, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (fd < 0) {
		g_ws_scan_ctx->err = errno;
		return -1;
	}

	if (ws_get_subvol_id(fd, &subvolid)) {
		g_ws_scan_ctx->err = errno;
		close(fd);
		return -1;
	}

	close(fd);

	if (subvolid != g_ws_scan_ctx->root_subvolid) {
		g_ws_scan_ctx->found = true;
		return 1;
	}

	return 0;
}

static int ws_detect_nested_subvolumes(const char *source_root, uint64_t root_subvolid)
{
	struct ws_nested_scan_ctx scan_ctx;
	int ret;

	memset(&scan_ctx, 0, sizeof(scan_ctx));
	scan_ctx.root_subvolid = root_subvolid;
	scan_ctx.found = false;
	scan_ctx.err = 0;

	g_ws_scan_ctx = &scan_ctx;
	ret = nftw(source_root, ws_nested_scan_cb, 32, FTW_PHYS);
	g_ws_scan_ctx = NULL;

	if (ret == 1 && scan_ctx.found)
		return 1;

	if (ret != 0) {
		errno = scan_ctx.err ? scan_ctx.err : EIO;
		return -1;
	}

	return 0;
}

static int ws_snapshot_create_ioctl(int snapshot_dir_fd, int source_fd, const char *name)
{
	int ret;

#ifdef BTRFS_IOC_SNAP_CREATE_V2
	struct btrfs_ioctl_vol_args_v2 v2;

	memset(&v2, 0, sizeof(v2));
	v2.fd = source_fd;
#ifdef BTRFS_SUBVOL_RDONLY
	v2.flags = BTRFS_SUBVOL_RDONLY;
#endif
	strncpy(v2.name, name, sizeof(v2.name) - 1);

	ret = ioctl(snapshot_dir_fd, BTRFS_IOC_SNAP_CREATE_V2, &v2);
	if (!ret)
		return 0;

	if (errno != ENOTTY && errno != EINVAL)
		return -1;
#endif

#ifdef BTRFS_IOC_SNAP_CREATE
	{
		struct btrfs_ioctl_vol_args v1;

		memset(&v1, 0, sizeof(v1));
		v1.fd = source_fd;
		strncpy(v1.name, name, sizeof(v1.name) - 1);
		ret = ioctl(snapshot_dir_fd, BTRFS_IOC_SNAP_CREATE, &v1);
		if (!ret)
			return 0;
	}
#endif

	return -1;
}

static int ws_snapshot_delete_ioctl(int snapshot_dir_fd, const char *name)
{
	int ret;

#ifdef BTRFS_IOC_SNAP_DESTROY_V2
	struct btrfs_ioctl_vol_args_v2 v2;

	memset(&v2, 0, sizeof(v2));
	strncpy(v2.name, name, sizeof(v2.name) - 1);

	ret = ioctl(snapshot_dir_fd, BTRFS_IOC_SNAP_DESTROY_V2, &v2);
	if (!ret)
		return 0;

	if (errno != ENOTTY && errno != EINVAL)
		return -1;
#endif

#ifdef BTRFS_IOC_SNAP_DESTROY
	{
		struct btrfs_ioctl_vol_args v1;

		memset(&v1, 0, sizeof(v1));
		strncpy(v1.name, name, sizeof(v1.name) - 1);
		ret = ioctl(snapshot_dir_fd, BTRFS_IOC_SNAP_DESTROY, &v1);
		if (!ret)
			return 0;
	}
#endif

	return -1;
}

static int ws_write_metadata(int meta_dir_fd, const struct workspace_snapshot_ctx *ctx, uint64_t source_subvolid)
{
	char meta_file[160];
	time_t now;
	int fd;
	int ret;

	snprintf(meta_file, sizeof(meta_file), "%s.meta", ctx->snapshot_name);

	fd = openat(meta_dir_fd, meta_file,
		    O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0)
		return -1;

	now = time(NULL);
	ret = dprintf(fd,
		      "snapshot_name=%s\n"
		      "snapshot_path=%s\n"
		      "source_root=%s\n"
		      "target_pid=%d\n"
		      "source_subvolid=%" PRIu64 "\n"
		      "created_at=%lld\n",
		      ctx->snapshot_name,
		      ctx->snapshot_path,
		      ctx->source_root,
		      ctx->target_pid,
		      source_subvolid,
		      (long long)now);
	if (ret < 0) {
		close(fd);
		return -1;
	}

	if (close(fd))
		return -1;

	return 0;
}

static void ws_build_snapshot_name(struct workspace_snapshot_ctx *ctx)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_REALTIME, &ts)) {
		ts.tv_sec = time(NULL);
		ts.tv_nsec = 0;
	}

	snprintf(ctx->snapshot_name, sizeof(ctx->snapshot_name),
		 "dump-%lld-%d", (long long)ts.tv_sec, ctx->target_pid);
}

static int ws_do_snapshot_work(struct workspace_snapshot_ctx *ctx)
{
	uint64_t source_subvolid;
	int source_fd;
	int parent_fd;
	int snapshot_dir_fd;
	int meta_dir_fd;
	int ret;
	int nested;
	bool snapshot_created;
	char msg[256];

	source_subvolid = 0;
	source_fd = -1;
	parent_fd = -1;
	snapshot_dir_fd = -1;
	meta_dir_fd = -1;
	snapshot_created = false;
	ret = -1;

	source_fd = open(ctx->source_root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (source_fd < 0) {
		snprintf(msg, sizeof(msg), "open source root failed");
		ws_set_error(ctx, errno, msg);
		goto out;
	}

	parent_fd = open(ctx->snapshot_parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (parent_fd < 0) {
		snprintf(msg, sizeof(msg), "open snapshot parent failed");
		ws_set_error(ctx, errno, msg);
		goto out;
	}

	if (ws_mkdirat_if_missing(parent_fd, ctx->snapshot_dir_name, 0700)) {
		snprintf(msg, sizeof(msg), "create snapshot dir failed");
		ws_set_error(ctx, errno, msg);
		goto out;
	}

	if (ws_mkdirat_if_missing(parent_fd, ctx->meta_dir_name, 0700)) {
		snprintf(msg, sizeof(msg), "create snapshot metadata dir failed");
		ws_set_error(ctx, errno, msg);
		goto out;
	}

	snapshot_dir_fd = openat(parent_fd, ctx->snapshot_dir_name,
				 O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (snapshot_dir_fd < 0) {
		snprintf(msg, sizeof(msg), "open snapshot dir failed");
		ws_set_error(ctx, errno, msg);
		goto out;
	}

	meta_dir_fd = openat(parent_fd, ctx->meta_dir_name,
			     O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (meta_dir_fd < 0) {
		snprintf(msg, sizeof(msg), "open snapshot metadata dir failed");
		ws_set_error(ctx, errno, msg);
		goto out;
	}

	if (ws_get_subvol_id(source_fd, &source_subvolid)) {
		snprintf(msg, sizeof(msg), "read source subvolume id failed");
		ws_set_error(ctx, errno, msg);
		goto out;
	}

	if (ctx->strict_nested_subvol) {
		nested = ws_detect_nested_subvolumes(ctx->source_root, source_subvolid);
		if (nested < 0) {
			snprintf(msg, sizeof(msg), "pre-check nested subvolume detection failed");
			ws_set_error(ctx, errno, msg);
			goto out;
		}

		if (nested > 0) {
			snprintf(msg, sizeof(msg), "source workspace contains nested subvolumes");
			ws_set_error(ctx, EINVAL, msg);
			goto out;
		}
	}

	ws_build_snapshot_name(ctx);

	if (ws_snapshot_create_ioctl(snapshot_dir_fd, source_fd, ctx->snapshot_name)) {
		snprintf(msg, sizeof(msg), "create snapshot failed");
		ws_set_error(ctx, errno, msg);
		goto out;
	}
	snapshot_created = true;

	snprintf(ctx->snapshot_path, sizeof(ctx->snapshot_path), "%s/%s/%s",
		 ctx->snapshot_parent, ctx->snapshot_dir_name, ctx->snapshot_name);

	if (ctx->strict_nested_subvol) {
		nested = ws_detect_nested_subvolumes(ctx->source_root, source_subvolid);
		if (nested < 0) {
			snprintf(msg, sizeof(msg), "post-check nested subvolume detection failed");
			ws_set_error(ctx, errno, msg);
			goto out;
		}

		if (nested > 0) {
			snprintf(msg, sizeof(msg), "nested subvolume detected after snapshot create");
			ws_set_error(ctx, EINVAL, msg);
			goto out;
		}
	}

	if (ws_write_metadata(meta_dir_fd, ctx, source_subvolid)) {
		snprintf(msg, sizeof(msg), "write snapshot metadata failed");
		ws_set_error(ctx, errno, msg);
		goto out;
	}

	ret = 0;
out:
	if (ret && snapshot_created) {
		if (ws_snapshot_delete_ioctl(snapshot_dir_fd, ctx->snapshot_name))
			pr_warn("Failed to cleanup snapshot %s after error\n",
				ctx->snapshot_name);
	}

	if (meta_dir_fd >= 0)
		close(meta_dir_fd);
	if (snapshot_dir_fd >= 0)
		close(snapshot_dir_fd);
	if (parent_fd >= 0)
		close(parent_fd);
	if (source_fd >= 0)
		close(source_fd);

	return ret;
}

static void *ws_snapshot_thread(void *arg)
{
	struct workspace_snapshot_ctx *ctx;
	int ret;

	ctx = arg;
	ret = 0;

	pthread_mutex_lock(&ctx->lock);
	while (!ctx->start_requested && !ctx->stop_requested)
		pthread_cond_wait(&ctx->cond, &ctx->lock);

	if (ctx->stop_requested) {
		ctx->state = WS_SNAPSHOT_DONE_ERR;
		ws_set_error(ctx, ECANCELED, "snapshot aborted before start");
		pthread_mutex_unlock(&ctx->lock);
		return NULL;
	}

	ctx->state = WS_SNAPSHOT_RUNNING;
	pthread_mutex_unlock(&ctx->lock);

	ret = ws_do_snapshot_work(ctx);

	pthread_mutex_lock(&ctx->lock);
	if (!ret)
		ctx->state = WS_SNAPSHOT_DONE_OK;
	else
		ctx->state = WS_SNAPSHOT_DONE_ERR;
	pthread_mutex_unlock(&ctx->lock);

	return NULL;
}

bool ws_snapshot_ctx_enabled(const struct workspace_snapshot_ctx *ctx)
{
	return ctx && ctx->enabled;
}

int ws_snapshot_ctx_init(struct workspace_snapshot_ctx *ctx, int target_pid,
			 const char *source_root,
			 const char *snapshot_parent,
			 const char *snapshot_dir_name,
			 const char *meta_dir_name,
			 bool strict_nested_subvol)
{
	if (!ctx || !source_root || !snapshot_parent)
		return -1;

	memset(ctx, 0, sizeof(*ctx));

	ctx->source_root = xstrdup(source_root);
	ctx->snapshot_parent = xstrdup(snapshot_parent);
	ctx->snapshot_dir_name = xstrdup(snapshot_dir_name ? snapshot_dir_name : "snaps");
	ctx->meta_dir_name = xstrdup(meta_dir_name ? meta_dir_name : "meta");
	if (!ctx->source_root || !ctx->snapshot_parent ||
	    !ctx->snapshot_dir_name || !ctx->meta_dir_name)
		goto err;

	if (ws_validate_component_name(ctx->snapshot_dir_name) ||
	    ws_validate_component_name(ctx->meta_dir_name)) {
		errno = EINVAL;
		goto err;
	}

	ctx->target_pid = target_pid;
	ctx->strict_nested_subvol = strict_nested_subvol;
	ctx->state = WS_SNAPSHOT_WAIT_START;

	if (pthread_mutex_init(&ctx->lock, NULL))
		goto err;
	if (pthread_cond_init(&ctx->cond, NULL)) {
		pthread_mutex_destroy(&ctx->lock);
		goto err;
	}
	ctx->sync_prim_inited = true;

	if (pthread_create(&ctx->tid, NULL, ws_snapshot_thread, ctx))
		goto err;

	ctx->thread_created = true;
	ctx->enabled = true;
	pr_info("Workspace snapshot thread initialized (source=%s parent=%s)\n",
		ctx->source_root, ctx->snapshot_parent);
	return 0;

err:
	ws_snapshot_ctx_destroy(ctx);
	return -1;
}

int ws_snapshot_start(struct workspace_snapshot_ctx *ctx)
{
	if (!ctx || !ctx->enabled)
		return 0;

	pthread_mutex_lock(&ctx->lock);
	if (!ctx->start_requested && ctx->state == WS_SNAPSHOT_WAIT_START) {
		ctx->start_requested = true;
		pthread_cond_signal(&ctx->cond);
	}
	pthread_mutex_unlock(&ctx->lock);

	return 0;
}

int ws_snapshot_gate_check_nonblocking(struct workspace_snapshot_ctx *ctx)
{
	enum ws_snapshot_state st;
	char reason[256];
	int ret;

	if (!ctx || !ctx->enabled)
		return 0;

	pthread_mutex_lock(&ctx->lock);
	st = ctx->state;
	snprintf(reason, sizeof(reason), "%s", ctx->reason);
	pthread_mutex_unlock(&ctx->lock);

	ret = 0;
	switch (st) {
	case WS_SNAPSHOT_DONE_OK:
		ret = 0;
		break;
	case WS_SNAPSHOT_DONE_ERR:
		pr_err("Workspace snapshot failed: %s\n", reason[0] ? reason : "unknown error");
		ret = -1;
		break;
	case WS_SNAPSHOT_WAIT_START:
		pr_err("Workspace snapshot did not start before unfreeze gate\n");
		ret = -1;
		break;
	case WS_SNAPSHOT_RUNNING:
		pr_err("Workspace snapshot still running at unfreeze gate\n");
		ret = -1;
		break;
	case WS_SNAPSHOT_DISABLED:
	default:
		ret = 0;
		break;
	}

	return ret;
}

int ws_snapshot_join_and_finalize(struct workspace_snapshot_ctx *ctx)
{
	enum ws_snapshot_state st;

	if (!ctx || !ctx->enabled)
		return 0;

	pthread_mutex_lock(&ctx->lock);
	if (ctx->state == WS_SNAPSHOT_WAIT_START && !ctx->start_requested) {
		ctx->stop_requested = true;
		pthread_cond_signal(&ctx->cond);
	}
	pthread_mutex_unlock(&ctx->lock);

	if (ctx->thread_created) {
		if (pthread_join(ctx->tid, NULL)) {
			pr_err("Can't join workspace snapshot thread\n");
			return -1;
		}
		ctx->thread_created = false;
	}

	pthread_mutex_lock(&ctx->lock);
	st = ctx->state;
	pthread_mutex_unlock(&ctx->lock);

	if (st != WS_SNAPSHOT_DONE_OK)
		return -1;

	return 0;
}

void ws_snapshot_ctx_destroy(struct workspace_snapshot_ctx *ctx)
{
	if (!ctx)
		return;

	if (ctx->sync_prim_inited && ctx->thread_created) {
		pthread_mutex_lock(&ctx->lock);
		ctx->stop_requested = true;
		pthread_cond_signal(&ctx->cond);
		pthread_mutex_unlock(&ctx->lock);
		pthread_join(ctx->tid, NULL);
		ctx->thread_created = false;
	}

	if (ctx->sync_prim_inited) {
		pthread_cond_destroy(&ctx->cond);
		pthread_mutex_destroy(&ctx->lock);
		ctx->sync_prim_inited = false;
	}

	xfree(ctx->source_root);
	xfree(ctx->snapshot_parent);
	xfree(ctx->snapshot_dir_name);
	xfree(ctx->meta_dir_name);

	memset(ctx, 0, sizeof(*ctx));
}
