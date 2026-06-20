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
#include <time.h>
#include <errno.h>
#include <inttypes.h>
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
	uint64_t scratch_uses;
	struct hot_apply_extent pending;
};

struct hot_old_range {
	unsigned long vaddr;
	unsigned long len;
	off_t off;
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

static int hot_copy_exact_at(int fd, off_t src, off_t dst, unsigned long len, void *buf,
			     size_t buf_len)
{
	while (len) {
		size_t chunk = len < buf_len ? len : buf_len;
		size_t done = 0;

		while (done < chunk) {
			ssize_t ret = pread(fd, (char *)buf + done, chunk - done, src + done);

			if (ret < 0) {
				if (errno == EINTR)
					continue;
				pr_perror("DSA hot apply read move failed");
				return -1;
			}
			if (ret == 0) {
				pr_err("DSA hot apply unexpected EOF while moving pages\n");
				return -1;
			}
			done += ret;
		}

		done = 0;
		while (done < chunk) {
			ssize_t ret = pwrite(fd, (char *)buf + done, chunk - done, dst + done);

			if (ret < 0) {
				if (errno == EINTR)
					continue;
				pr_perror("DSA hot apply write move failed");
				return -1;
			}
			if (ret == 0) {
				pr_err("DSA hot apply short write while moving pages\n");
				return -1;
			}
			done += ret;
		}

		src += chunk;
		dst += chunk;
		len -= chunk;
	}

	return 0;
}

static int hot_pread_full(int fd, void *buf, size_t len, off_t off)
{
	size_t done = 0;

	while (done < len) {
		ssize_t ret = pread(fd, (char *)buf + done, len - done, off + done);

		if (ret < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (ret == 0) {
			errno = EIO;
			return -1;
		}
		done += ret;
	}

	return 0;
}

static int hot_pwrite_full(int fd, const void *buf, size_t len, off_t off)
{
	size_t done = 0;

	while (done < len) {
		ssize_t ret = pwrite(fd, (const char *)buf + done, len - done, off + done);

		if (ret < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (ret == 0) {
			errno = EIO;
			return -1;
		}
		done += ret;
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

static int hot_apply_fill_src_pages(struct hot_apply_ctx *ctx,
				    struct hot_old_range *old_ranges, size_t nr_old,
				    off_t old_size, off_t **src_pages_out,
				    size_t *final_pages_out, off_t *final_size_out)
{
	off_t *src_pages = NULL;
	size_t final_pages = 0;
	size_t old_idx = 0;
	size_t i;

	*src_pages_out = NULL;
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

	src_pages = xmalloc(final_pages * sizeof(src_pages[0]));
	if (!src_pages)
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
			for (p = 0; p < pages; p++)
				src_pages[final_pages++] = e->append_offset / PAGE_SIZE + p;
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
			for (p = 0; p < pages; p++)
				src_pages[final_pages++] = src_off / PAGE_SIZE + p;

			pos += in_range;
			left -= in_range;
		}
	}

	*src_pages_out = src_pages;
	*final_pages_out = final_pages;
	*final_size_out = (off_t)final_pages * PAGE_SIZE;
	return 0;

err:
	xfree(src_pages);
	return -1;
}

static int hot_apply_copy_page(struct hot_apply_ctx *ctx, int fd, off_t src_page,
			       off_t dst_page, void *buf)
{
	if (src_page == dst_page)
		return 0;
	if (hot_copy_exact_at(fd, src_page * PAGE_SIZE, dst_page * PAGE_SIZE,
			      PAGE_SIZE, buf, PAGE_SIZE))
		return -1;
	ctx->moved_pages++;
	return 0;
}

static int hot_apply_rebuild_needed(off_t *src_pages, bool *pending, bool *needed,
				    size_t final_pages)
{
	size_t i;

	memset(needed, 0, final_pages * sizeof(needed[0]));
	for (i = 0; i < final_pages; i++) {
		if (!pending[i])
			continue;
		if (src_pages[i] >= 0 && (size_t)src_pages[i] < final_pages)
			needed[src_pages[i]] = true;
	}

	return 0;
}

static int hot_apply_enqueue_ready(off_t *src_pages, bool *pending, bool *needed,
				   size_t final_pages, size_t *queue, size_t *q_tail)
{
	size_t i;

	*q_tail = 0;
	for (i = 0; i < final_pages; i++) {
		if (pending[i] && !needed[i])
			queue[(*q_tail)++] = i;
	}

	return 0;
}

static int hot_apply_break_cycle(struct hot_apply_ctx *ctx, int fd, off_t *src_pages, bool *pending,
				 size_t final_pages, void *buf, size_t *pending_count)
{
	size_t start, d;

	for (start = 0; start < final_pages; start++) {
		if (pending[start])
			break;
	}
	if (start == final_pages)
		return 0;

	if (hot_pread_full(fd, buf, PAGE_SIZE, (off_t)start * PAGE_SIZE)) {
		pr_perror("DSA hot apply can't read scratch page");
		return -1;
	}
	ctx->scratch_uses++;

	d = start;
	while (pending[d]) {
		off_t s = src_pages[d];

		if (s == (off_t)start) {
			if (hot_pwrite_full(fd, buf, PAGE_SIZE, (off_t)d * PAGE_SIZE)) {
				pr_perror("DSA hot apply can't write scratch page");
				return -1;
			}
			pending[d] = false;
			(*pending_count)--;
			return 0;
		}

		if (hot_apply_copy_page(ctx, fd, s, d, buf))
			return -1;
		pending[d] = false;
		(*pending_count)--;

		if (s < 0 || (size_t)s >= final_pages)
			return 0;
		d = (size_t)s;
	}

	return 0;
}

static int hot_apply_move_pages(struct hot_apply_ctx *ctx, int fd, off_t *src_pages,
				size_t final_pages)
{
	bool *pending = NULL;
	bool *needed = NULL;
	size_t *queue = NULL;
	void *buf = NULL;
	size_t pending_count = 0;
	size_t i;
	int ret = -1;

	if (!final_pages)
		return 0;

	pending = xmalloc(final_pages * sizeof(pending[0]));
	needed = xmalloc(final_pages * sizeof(needed[0]));
	queue = xmalloc(final_pages * sizeof(queue[0]));
	buf = xmalloc(PAGE_SIZE);
	if (!pending || !needed || !queue || !buf)
		goto out;

	for (i = 0; i < final_pages; i++) {
		pending[i] = src_pages[i] != (off_t)i;
		if (pending[i])
			pending_count++;
	}

	while (pending_count) {
		size_t q_head = 0, q_tail = 0;

		hot_apply_rebuild_needed(src_pages, pending, needed, final_pages);
		hot_apply_enqueue_ready(src_pages, pending, needed, final_pages,
					queue, &q_tail);

		if (q_tail == 0) {
			if (hot_apply_break_cycle(ctx, fd, src_pages, pending, final_pages,
						  buf, &pending_count))
				goto out;
			continue;
		}

		while (q_head < q_tail) {
			size_t d = queue[q_head++];
			off_t s;

			if (!pending[d])
				continue;
			s = src_pages[d];
			if (hot_apply_copy_page(ctx, fd, s, d, buf))
				goto out;
			pending[d] = false;
			pending_count--;
		}
	}

	ret = 0;

out:
	xfree(buf);
	xfree(queue);
	xfree(needed);
	xfree(pending);
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
	off_t *src_pages = NULL;
	size_t nr_old = 0;
	size_t final_pages = 0;
	off_t old_size = 0;
	off_t final_size = 0;
	uint64_t start_us = hot_now_us();
	int ret = -1;

	if (hot_apply_load_old_ranges(ctx, &old_ranges, &nr_old, &old_size))
		goto out;

	if (hot_apply_fill_src_pages(ctx, old_ranges, nr_old, old_size,
				     &src_pages, &final_pages, &final_size))
		goto out;

	if (hot_apply_move_pages(ctx, ctx->append_fd, src_pages, final_pages))
		goto out;

	if (ftruncate(ctx->append_fd, final_size)) {
		pr_perror("DSA hot apply can't truncate current pages image");
		goto out;
	}

	if (hot_apply_rewrite_pagemap(ctx))
		goto out;

	ctx->reorder_time_us = hot_now_us() - start_us;
	pr_info("DSA hot apply reordered current img_id=%lu pages_id=%u old_size=%" PRId64 " final_size=%" PRId64 " entries=%zu append_bytes=%" PRIu64 " append_time_us=%" PRIu64 " reorder_time_us=%" PRIu64 " moved_pages=%" PRIu64 " scratch_uses=%" PRIu64 "\n",
		ctx->img_id, ctx->current_pages_id, (int64_t)old_size,
		(int64_t)final_size, ctx->nr_entries, ctx->append_bytes,
		ctx->append_time_us, ctx->reorder_time_us, ctx->moved_pages,
		ctx->scratch_uses);
	ret = 0;

out:
	xfree(src_pages);
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
