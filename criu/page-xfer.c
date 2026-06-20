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
#include <dirent.h>
#include <linux/idxd.h>
#include <time.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#undef LOG_PREFIX
#define LOG_PREFIX "page-xfer: "

#include "types.h"
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
#include "rst_info.h"
#include "stats.h"
#include "tls.h"

#define HOT_APPLY_SCRATCH_PAGES 32
#define HOT_DSA_PORTAL_MAP_SIZE 0x1000UL
#define HOT_DSA_MAX_WQ 16
#define HOT_DSA_MAX_ENQ_RETRY 1000000U
#define HOT_DSA_MAX_POLL_RETRY 1000000U

static int page_server_sk = -1;

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
};

struct hot_apply_ctx {
	bool enabled;
	bool finished;
	int pipefd[2];
	int append_fd;
	int extent_fd;
	int fd_type;
	unsigned long img_id;
	u32 pages_id;
	u32 current_pages_id;
	const char *manifest_path;
	const char *current_dir;
	unsigned long next_seq;
	struct hot_apply_extent *entries;
	size_t nr_entries;
	size_t entries_cap;
	size_t pending_index;
	uint64_t append_bytes;
	uint64_t append_time_us;
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
	void *map;
	size_t map_size;
	off_t file_size;
	int dsa_wq_count;
	int dsa_wq_fds[HOT_DSA_MAX_WQ];
	void *dsa_portals[HOT_DSA_MAX_WQ];
	unsigned long dsa_portal_offset[HOT_DSA_MAX_WQ];
	unsigned int dsa_next_wq;
	struct hot_apply_extent pending;
};

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

static uint64_t hot_now_us(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000ULL + ts.tv_nsec / 1000ULL;
}

static bool dsa_hot_apply_enabled(void)
{
	const char *enabled = getenv("CRIU_DSA_HOT_APPLY");
	const char *current = getenv("CRIU_DSA_HOT_CURRENT_DIR");
	const char *dsa = getenv("CRIU_DSA_DUMP");

	return enabled && strcmp(enabled, "1") == 0 && current && current[0] &&
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

static size_t hot_align_up_size(size_t val, size_t align)
{
	return (val + align - 1) & ~(align - 1);
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

static void hot_dsa_close(struct hot_apply_ctx *ctx)
{
	int i;

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
	pr_info("DSA hot apply reorder opened %d DSA workqueues\n", nr);
	return 0;

err:
	ctx->dsa_wq_count = nr;
	hot_dsa_close(ctx);
	return -1;
}

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

static void hot_apply_unmap_current(struct hot_apply_ctx *ctx)
{
	if (ctx->map && ctx->map != MAP_FAILED)
		munmap(ctx->map, ctx->map_size);
	ctx->map = MAP_FAILED;
	ctx->map_size = 0;
	ctx->file_size = 0;
}

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

static int hot_apply_mkdir_root(const char *root)
{
	if (mkdir(root, 0755) && errno != EEXIST) {
		pr_perror("DSA hot apply can't create %s", root);
		return -1;
	}

	return 0;
}

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
	e->pages_id = ctx->current_pages_id;
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

	if (!final_pages)
		return 0;

	live_counts = xmalloc(final_pages * sizeof(live_counts[0]));
	dst_epoch = xzalloc(final_pages * sizeof(dst_epoch[0]));
	if (!live_counts || !dst_epoch)
		goto out;

	if (hot_apply_build_move_ranges(ctx, sources, final_pages,
					&ranges, &nr_ranges))
		goto out;
	cap_ranges = nr_ranges;
	pending_count = nr_ranges;
	batch = xmalloc(nr_ranges * sizeof(batch[0]));
	if (!batch)
		goto out;
	hot_apply_live_counts_build(live_counts, final_pages, ranges, nr_ranges);

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
	off_t append_size;
	int ret = -1;

	if (hot_apply_load_old_ranges(ctx, &old_ranges, &nr_old, &old_size))
		goto out;

	if (hot_apply_fill_sources(ctx, old_ranges, nr_old, old_size,
				   &sources, &final_pages, &final_size))
		goto out;

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

	if (hot_dsa_open(ctx))
		goto out;
	if (hot_apply_remap_current(ctx, append_size))
		goto out;

	if (hot_apply_move_pages(ctx, sources, final_pages))
		goto out;

	hot_apply_unmap_current(ctx);
	if (ftruncate(ctx->append_fd, final_size)) {
		pr_perror("DSA hot apply can't truncate current pages image");
		goto out;
	}

	if (hot_apply_rewrite_pagemap(ctx))
		goto out;

	ctx->reorder_time_us = hot_now_us() - start_us;
	pr_info("DSA hot apply reordered current img_id=%lu pages_id=%u old_size=%" PRId64 " final_size=%" PRId64 " entries=%zu append_bytes=%" PRIu64 " append_time_us=%" PRIu64 " reorder_time_us=%" PRIu64 " moved_pages=%" PRIu64 " moved_ranges=%" PRIu64 " range_count=%" PRIu64 " max_range_pages=%" PRIu64 " patch_pages=%" PRIu64 " patch_ranges=%" PRIu64 " scratch_uses=%" PRIu64 " scratch_bytes=%" PRIu64 " dsa_copy_pages=%" PRIu64 " dsa_copy_ranges=%" PRIu64 " dsa_copy_bytes=%" PRIu64 " dsa_submit_us=%" PRIu64 " dsa_poll_us=%" PRIu64 " dsa_enqcmd=%" PRIu64 " dsa_submit_batches=%" PRIu64 " dsa_max_batch_ranges=%" PRIu64 " ready_scan_us=%" PRIu64 " ready_rounds=%" PRIu64 " ready_empty_rounds=%" PRIu64 "\n",
		ctx->img_id, ctx->current_pages_id, (int64_t)old_size,
		(int64_t)final_size, ctx->nr_entries, ctx->append_bytes,
		ctx->append_time_us, ctx->reorder_time_us, ctx->moved_pages,
		ctx->moved_ranges, ctx->range_count, ctx->max_range_pages,
		ctx->patch_pages, ctx->patch_ranges, ctx->scratch_uses,
		ctx->scratch_bytes, ctx->dsa_copy_pages, ctx->dsa_copy_ranges,
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

static void hot_apply_abort(struct page_xfer *xfer)
{
	struct hot_apply_ctx *ctx = xfer->hot_apply;

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

	xfree(ctx->entries);
	xfree(ctx);
	xfer->hot_apply = NULL;
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
	if (ret == 0 && hot_apply_reorder_current(ctx))
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
	/*
	 * This implementation only appends dirty/new page bytes and records
	 * descriptors. The current full image is not ready for restore until
	 * the post-write reorder/pagemap rewrite phase runs.
	 */
	if (hot_apply_write_manifest(ctx->manifest_path, ret ? "failed" : "append_pending"))
		ret = -1;

	xfree(ctx->entries);
	ctx->entries = NULL;
	return ret;
}

static int hot_apply_init_xfer(struct page_xfer *xfer, int fd_type,
			       unsigned long img_id, u32 pages_id)
{
	const char *root = getenv("CRIU_DSA_HOT_CURRENT_DIR");
	const char *manifest = getenv("CRIU_DSA_HOT_MANIFEST");
	struct hot_apply_ctx *ctx;
	char name[128];
	char path[PATH_MAX];

	if (!dsa_hot_apply_enabled())
		return 0;

	ctx = xzalloc(sizeof(*ctx));
	if (!ctx)
		return -1;

	ctx->enabled = true;
	ctx->pipefd[0] = -1;
	ctx->pipefd[1] = -1;
	ctx->append_fd = -1;
	ctx->extent_fd = -1;
	ctx->fd_type = fd_type;
	ctx->img_id = img_id;
	ctx->pages_id = pages_id;
	ctx->current_dir = root;
	ctx->manifest_path = manifest;
	ctx->pending_index = (size_t)-1;

	if (hot_apply_mkdir_root(root))
		goto err;
	if (hot_apply_write_manifest(ctx->manifest_path, "updating"))
		goto err;
	if (hot_apply_read_current_pages_id(ctx, root))
		goto err;

	if (pipe2(ctx->pipefd, O_CLOEXEC)) {
		pr_perror("DSA hot apply can't create pipe");
		goto err;
	}

	snprintf(name, sizeof(name), "pages-%u.img", ctx->current_pages_id);
	ctx->append_fd = hot_apply_open_file(root, path, sizeof(path), name,
					     O_RDWR, 0644);
	if (ctx->append_fd < 0)
		goto err;

	snprintf(name, sizeof(name), "apply-extents-fd%d-id%lu-pages%u.log",
		 fd_type, img_id, pages_id);
	ctx->extent_fd = hot_apply_open_file(root, path, sizeof(path), name,
					     O_CREAT | O_TRUNC | O_WRONLY, 0644);
	if (ctx->extent_fd < 0)
		goto err;

	xfer->hot_apply = ctx;

	pr_info("DSA hot append enabled fd_type=%d img_id=%lu pages_id=%u root=%s\n",
		fd_type, img_id, pages_id, root);
	return 0;

err:
	xfer->hot_apply = ctx;
	hot_apply_abort(xfer);
	return -1;
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
	ctx->pending.pages_id = ctx->current_pages_id;
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
static int write_pages_loc(struct page_xfer *xfer, int p, unsigned long len)
{
	struct hot_apply_ctx *ctx = xfer->hot_apply;
	unsigned long curr = 0;
	off_t append_offset;

	if (!ctx)
		return splice_exact(p, img_raw_fd(xfer->pi), len);

	append_offset = lseek(ctx->append_fd, 0, SEEK_END);
	if (append_offset == (off_t)-1) {
		pr_perror("DSA hot apply can't seek append file");
		return -1;
	}

	if (hot_apply_log_pending(ctx, len, append_offset))
		return -1;

	while (curr < len) {
		uint64_t append_start_us;
		ssize_t ret;

		append_start_us = hot_now_us();
		ret = tee(p, ctx->pipefd[1], len - curr, 0);
		ctx->append_time_us += hot_now_us() - append_start_us;
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
		if (splice_exact(ctx->pipefd[0], ctx->append_fd, ret))
			return -1;
		ctx->append_time_us += hot_now_us() - append_start_us;
		ctx->append_bytes += ret;

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

static int write_pagemap_loc(struct page_xfer *xfer, struct iovec *iov, u32 flags)
{
	int ret;
	PagemapEntry pe = PAGEMAP_ENTRY__INIT;

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
	} else if (flags & PE_PARENT) {
		if (xfer->parent != NULL) {
			ret = check_pagehole_in_parent(xfer->parent, iov);
			if (ret) {
				pr_err("Hole %p - %p not found in parent\n",
				       iov->iov_base, iov->iov_base + iov->iov_len);
				return -1;
			}
		}
	}

	if (pb_write_one(xfer->pmi, &pe, PB_PAGEMAP) < 0)
		return -1;

	if (hot_apply_set_pending(xfer, iov, flags))
		return -1;
	return 0;
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

	xfer->write_pagemap = write_pagemap_loc;
	xfer->write_pages = write_pages_loc;
	xfer->close = close_page_xfer;
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
	unsigned int cur_hole = 0;
	int ret;

	pr_debug("Transferring pages:\n");

	list_for_each_entry(ppb, &pp->bufs, l) {
		unsigned int i;

		pr_debug("\tbuf %lx/%d\n", ppb->pages_in, ppb->nr_segs);

		for (i = 0; i < ppb->nr_segs; i++) {
			struct iovec iov = ppb->iov[i];
			u32 flags;

			ret = dump_holes(xfer, pp, &cur_hole, iov.iov_base);
			if (ret)
				return ret;

			BUG_ON(iov.iov_base < (void *)xfer->offset);
			iov.iov_base -= xfer->offset;
			pr_debug("\tp %p - %p\n", iov.iov_base, iov.iov_base + iov.iov_len);

			flags = ppb_xfer_flags(xfer, ppb);

			if (xfer->write_pagemap(xfer, &iov, flags))
				return -1;
			if ((flags & PE_PRESENT) && xfer->write_pages(xfer, ppb->p[0], iov.iov_len))
				return -1;
		}
	}

	ret = dump_holes(xfer, pp, &cur_hole, NULL);
	if (ret)
		return ret;

	return hot_apply_finish(xfer);
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
