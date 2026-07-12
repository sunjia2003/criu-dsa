#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <linux/falloc.h>
#include <sys/uio.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <inttypes.h>

#include "types.h"
#include "image.h"
#include "cr_options.h"
#include "servicefd.h"
#include "pagemap.h"
#include "restorer.h"
#include "rst-malloc.h"
#include "page-xfer.h"

#include "fault-injection.h"
#include "xmalloc.h"
#include "protobuf.h"
#include "images/pagemap.pb-c.h"

#ifndef SEEK_DATA
#define SEEK_DATA 3
#define SEEK_HOLE 4
#endif

#define MAX_BUNCH_SIZE 256

static uint64_t page_read_now_us(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000ULL + ts.tv_nsec / 1000ULL;
}

struct hot_read_segment {
	unsigned long img_id;
	unsigned long vaddr;
	unsigned long len;
	off_t off;
	int fd;
	char file[PATH_MAX];
};

struct hot_read_ctx {
	struct hot_read_segment *segs;
	size_t nr;
};

static bool hot_restore_enabled(void)
{
	const char *enabled = getenv("CRIU_DSA_HOT_RESTORE");
	const char *manifest = getenv("CRIU_DSA_HOT_MEMORY_MANIFEST");

	return enabled && strcmp(enabled, "1") == 0 && manifest && manifest[0];
}

static void hot_read_close_ctx(struct hot_read_ctx *ctx)
{
	size_t i;

	if (!ctx)
		return;
	for (i = 0; i < ctx->nr; i++) {
		if (ctx->segs[i].fd >= 0)
			close(ctx->segs[i].fd);
	}
	xfree(ctx->segs);
	xfree(ctx);
}

static int hot_read_load_ctx(struct page_read *pr)
{
	const char *path = getenv("CRIU_DSA_HOT_MEMORY_MANIFEST");
	FILE *fp;
	struct hot_read_ctx *ctx;
	char line[PATH_MAX + 128];
	size_t cap = 0;
	uint64_t parse_us = 0;
	uint64_t open_us = 0;
	uint64_t start_us;

	ctx = xzalloc(sizeof(*ctx));
	if (!ctx)
		return -1;

	start_us = page_read_now_us();
	fp = fopen(path, "r");
	if (!fp) {
		pr_perror("hot page_read can't open manifest %s", path);
		xfree(ctx);
		return -1;
	}
	parse_us += page_read_now_us() - start_us;

	while (fgets(line, sizeof(line), fp)) {
		struct hot_read_segment seg;
		unsigned long long off;
		int n;
		uint64_t line_start_us;
		uint64_t open_start_us;

		memset(&seg, 0, sizeof(seg));
		seg.fd = -1;
		pr->manifest_bytes += strlen(line);
		line_start_us = page_read_now_us();
		n = sscanf(line, "seg %lu %lx %lu %4095s %llu",
			   &seg.img_id, &seg.vaddr, &seg.len, seg.file, &off);
		parse_us += page_read_now_us() - line_start_us;
		if (n != 5 || seg.img_id != pr->img_id)
			continue;
		seg.off = (off_t)off;
		open_start_us = page_read_now_us();
		seg.fd = open(seg.file, O_RDONLY | O_CLOEXEC);
		open_us += page_read_now_us() - open_start_us;
		if (seg.fd < 0) {
			pr_perror("hot page_read can't open segment %s", seg.file);
			fclose(fp);
			hot_read_close_ctx(ctx);
			return -1;
		}

		if (ctx->nr == cap) {
			size_t new_cap = cap ? cap * 2 : 256;
			void *new_segs = xrealloc(ctx->segs, new_cap * sizeof(ctx->segs[0]));

			if (!new_segs) {
				fclose(fp);
				close(seg.fd);
				hot_read_close_ctx(ctx);
				return -1;
			}
			ctx->segs = new_segs;
			cap = new_cap;
		}
		ctx->segs[ctx->nr++] = seg;
	}

	fclose(fp);
	pr->timing_manifest_parse_us += parse_us;
	pr->timing_segment_open_us += open_us;
	pr->segment_count = ctx->nr;
	if (!ctx->nr) {
		pr_err("hot page_read found no segments for img_id=%lu in %s\n",
		       pr->img_id, path);
		hot_read_close_ctx(ctx);
		return -1;
	}
	pr->hot = ctx;
	return 0;
}

static struct hot_read_segment *hot_read_find(struct page_read *pr,
					      unsigned long img_id,
					      unsigned long vaddr)
{
	struct hot_read_ctx *ctx = pr->hot;
	size_t i;
	uint64_t start_us = page_read_now_us();

	pr->hot_find_calls++;
	for (i = 0; i < ctx->nr; i++) {
		unsigned long start = ctx->segs[i].vaddr;
		unsigned long end = start + ctx->segs[i].len;

		if (ctx->segs[i].img_id == img_id && vaddr >= start && vaddr < end) {
			uint64_t steps = i + 1;

			pr->hot_find_steps += steps;
			if (steps > pr->hot_find_steps_max)
				pr->hot_find_steps_max = steps;
			pr->timing_hot_find_us += page_read_now_us() - start_us;
			return &ctx->segs[i];
		}
	}
	pr->hot_find_steps += ctx->nr;
	if (ctx->nr > pr->hot_find_steps_max)
		pr->hot_find_steps_max = ctx->nr;
	pr->timing_hot_find_us += page_read_now_us() - start_us;
	return NULL;
}

static int read_full_fd(int fd, void *buf, size_t len)
{
	size_t done = 0;

	while (done < len) {
		ssize_t ret = read(fd, buf + done, len - done);

		if (ret < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (!ret)
			return -1;
		done += ret;
	}
	return 0;
}

static int pread_full_fd(int fd, void *buf, size_t len, off_t off)
{
	size_t done = 0;

	while (done < len) {
		ssize_t ret = pread(fd, buf + done, len - done, off + done);

		if (ret < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (!ret)
			return -1;
		done += ret;
	}
	return 0;
}

static int open_fg_sidecar_at(int dfd, struct page_read *pr)
{
	char path[64];

	if (pr->fg_idx_fd >= 0)
		return 0;

	snprintf(path, sizeof(path), "pages-fg-%u.idx", pr->pages_img_id);
	pr->fg_idx_fd = openat(dfd, path, O_RDONLY | O_CLOEXEC);
	if (pr->fg_idx_fd < 0) {
		if (errno == ENOENT)
			return 0;
		pr_perror("Can't open DSA fine-grained index %s", path);
		return -1;
	}

	snprintf(path, sizeof(path), "pages-fg-%u.dat", pr->pages_img_id);
	pr->fg_dat_fd = openat(dfd, path, O_RDONLY | O_CLOEXEC);
	if (pr->fg_dat_fd < 0) {
		pr_perror("Can't open DSA fine-grained data %s", path);
		close(pr->fg_idx_fd);
		pr->fg_idx_fd = -1;
		return -1;
	}

	pr_info("Opened DSA fine-grained pages sidecar pages_id=%u\n",
		pr->pages_img_id);
	return 0;
}

/*
 * One "job" for the preadv() syscall in pagemap.c
 */
struct page_read_iov {
	off_t from;	  /* offset in pi file where to start reading from */
	off_t end;	  /* the end of the read == sum to.iov_len -s */
	struct iovec *to; /* destination iovs */
	unsigned int nr;  /* their number */

	struct list_head l;
};

static inline bool can_extend_bunch(struct iovec *bunch, unsigned long off, unsigned long len)
{
	return /* The next region is the continuation of the existing */
		((unsigned long)bunch->iov_base + bunch->iov_len == off) &&
		/* The resulting region is non empty and is small enough */
		(bunch->iov_len == 0 || bunch->iov_len + len < MAX_BUNCH_SIZE * PAGE_SIZE);
}

static int punch_hole(struct page_read *pr, unsigned long off, unsigned long len, bool cleanup)
{
	int ret;
	struct iovec *bunch = &pr->bunch;

	if (!cleanup && can_extend_bunch(bunch, off, len)) {
		pr_debug("pr%lu-%u:Extend bunch len from %zu to %lu\n", pr->img_id, pr->id, bunch->iov_len,
			 bunch->iov_len + len);
		bunch->iov_len += len;
	} else {
		if (bunch->iov_len > 0) {
			pr_debug("Punch!/%p/%zu/\n", bunch->iov_base, bunch->iov_len);
			ret = fallocate(img_raw_fd(pr->pi), FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
					(unsigned long)bunch->iov_base, bunch->iov_len);
			if (ret != 0) {
				pr_perror("Error punching hole");
				return -1;
			}
		}
		bunch->iov_base = (void *)off;
		bunch->iov_len = len;
		pr_debug("pr%lu-%u:New bunch/%p/%zu/\n", pr->img_id, pr->id, bunch->iov_base, bunch->iov_len);
	}
	return 0;
}

int dedup_one_iovec(struct page_read *pr, unsigned long off, unsigned long len)
{
	unsigned long iov_end;

	iov_end = off + len;
	while (1) {
		int ret;
		unsigned long piov_end;
		struct page_read *prp;

		ret = pr->seek_pagemap(pr, off);
		if (ret == 0) {
			if (off < pr->cvaddr && pr->cvaddr < iov_end) {
				pr_debug("pr%lu-%u:No range %lx-%lx in pagemap\n", pr->img_id, pr->id, off, pr->cvaddr);
				off = pr->cvaddr;
			} else {
				pr_debug("pr%lu-%u:No range %lx-%lx in pagemap\n", pr->img_id, pr->id, off, iov_end);
				return 0;
			}
		}

		if (!pr->pe)
			return -1;
		piov_end = pr->pe->vaddr + pagemap_len(pr->pe);
		if (!pagemap_in_parent(pr->pe)) {
			ret = punch_hole(pr, pr->pi_off, min(piov_end, iov_end) - off, false);
			if (ret == -1)
				return ret;
		}

		prp = pr->parent;
		if (prp) {
			/* recursively */
			pr_debug("pr%lu-%u:Go to next parent level\n", pr->img_id, pr->id);
			len = min(piov_end, iov_end) - off;
			ret = dedup_one_iovec(prp, off, len);
			if (ret != 0)
				return -1;
		}

		if (piov_end < iov_end) {
			off = piov_end;
			continue;
		} else
			return 0;
	}
	return 0;
}

static int advance(struct page_read *pr)
{
	pr->curr_pme++;
	if (pr->curr_pme >= pr->nr_pmes)
		return 0;

	pr->pe = pr->pmes[pr->curr_pme];
	pr->cvaddr = pr->pe->vaddr;

	return 1;
}

static void skip_pagemap_pages(struct page_read *pr, unsigned long len)
{
	if (!len)
		return;

	if (pagemap_dsa_fg(pr->pe) && !pr->hot_restore) {
		off_t off = (len / PAGE_SIZE) * sizeof(struct dsa_fg_page_meta);

		if (pr->fg_idx_fd >= 0 && lseek(pr->fg_idx_fd, off, SEEK_CUR) == (off_t)-1)
			pr_perror("Can't skip DSA fine-grained metadata");
	} else if (pagemap_present(pr->pe)) {
		pr->pi_off += len;
	}
	pr->cvaddr += len;
}

static int seek_pagemap(struct page_read *pr, unsigned long vaddr)
{
	if (!pr->pe)
		goto adv;

	do {
		unsigned long start = pr->pe->vaddr;
		unsigned long end = start + pagemap_len(pr->pe);

		if (vaddr < pr->cvaddr)
			break;

		if (vaddr >= start && vaddr < end) {
			skip_pagemap_pages(pr, vaddr - pr->cvaddr);
			return 1;
		}

		if (end <= vaddr)
			skip_pagemap_pages(pr, end - pr->cvaddr);
	adv:; /* otherwise "label at end of compound stmt" gcc error */
	} while (advance(pr));

	return 0;
}

static inline void pagemap_bound_check(PagemapEntry *pe, unsigned long vaddr, unsigned long int nr)
{
	if (vaddr < pe->vaddr || (vaddr - pe->vaddr) / PAGE_SIZE + nr > pe->nr_pages) {
		pr_err("Page read err %" PRIx64 ":%" PRIx64 " vs %lx:%lx\n", pe->vaddr, pe->nr_pages, vaddr, nr);
		BUG();
	}
}

static int read_parent_page(struct page_read *pr, unsigned long vaddr, unsigned long int nr, void *buf, unsigned flags)
{
	struct page_read *ppr = pr->parent;
	uint64_t start_us = page_read_now_us();
	int ret;

	if (!ppr) {
		pr_err("No parent for snapshot pagemap\n");
		return -1;
	}

	/*
	 * Parent pagemap at this point entry may be shorter
	 * than the current vaddr:nr needs, so we have to
	 * carefully 'split' the vaddr:nr into pieces and go
	 * to parent page-read with the longest requests it
	 * can handle.
	 */

	do {
		unsigned long int p_nr;
		uint64_t seek_start_us;
		uint64_t child_start_us;

		pr_debug("\tpr%lu-%u Read from parent\n", pr->img_id, pr->id);
		seek_start_us = page_read_now_us();
		ret = ppr->seek_pagemap(ppr, vaddr);
		pr->timing_parent_seek_us += page_read_now_us() - seek_start_us;
		if (ret <= 0) {
			pr_err("Missing %lx in parent pagemap\n", vaddr);
			return -1;
		}

		/*
		 * This is how many pages we have in the parent
		 * page_read starting from vaddr. Go ahead and
		 * read as much as we can.
		 */
		p_nr = ppr->pe->nr_pages - (vaddr - ppr->pe->vaddr) / PAGE_SIZE;
		pr_debug("\tparent has %lu pages in\n", p_nr);
		if (p_nr > nr)
			p_nr = nr;

		pr->parent_read_calls++;
		pr->parent_read_pages += p_nr;
		child_start_us = page_read_now_us();
		ret = ppr->read_pages(ppr, vaddr, p_nr, buf, flags);
		pr->timing_parent_child_incl_us += page_read_now_us() - child_start_us;
		if (ret == -1)
			return ret;

		/*
		 * OK, let's see how much data we have left and go
		 * to parent page-read again for the next pagemap
		 * entry.
		 */
		nr -= p_nr;
		vaddr += p_nr * PAGE_SIZE;
		buf += p_nr * PAGE_SIZE;
	} while (nr);

	pr->timing_parent_read_us += page_read_now_us() - start_us;
	return 0;
}

static int read_local_page(struct page_read *pr, unsigned long vaddr, unsigned long len, void *buf)
{
	int fd;
	ssize_t ret;
	size_t curr = 0;

	fd = img_raw_fd(pr->pi);
	if (fd < 0) {
		pr_err("Failed getting raw image fd\n");
		return -1;
	}
	/*
	 * Flush any pending async requests if any not to break the
	 * linear reading from the pages.img file.
	 */
	if (pr->sync(pr))
		return -1;

	pr_debug("\tpr%lu-%u Read page from self %lx/%" PRIx64 "\n", pr->img_id, pr->id, pr->cvaddr, pr->pi_off);
	while (1) {
		uint64_t start_us = page_read_now_us();

		ret = pread(fd, buf + curr, len - curr, pr->pi_off + curr);
		pr->timing_disk_pread_us += page_read_now_us() - start_us;
		pr->disk_pread_calls++;
		if (ret < 1) {
			pr_perror("Can't read mapping page %zd", ret);
			return -1;
		}
		curr += ret;
		if (curr == len)
			break;
	}

	if (opts.auto_dedup && !pr->disable_dedup) {
		ret = punch_hole(pr, pr->pi_off, len, false);
		if (ret == -1)
			return -1;
	}

	return 0;
}

static int read_fg_page_one(struct page_read *pr, unsigned long vaddr, void *buf,
			    unsigned flags)
{
	struct dsa_fg_page_meta meta;
	void *data = NULL;
	size_t entries_len;
	size_t bytes_off;
	uint64_t start_us = page_read_now_us();
	uint64_t part_start_us;
	u16 i;
	int ret = -1;

	if (pr->fg_idx_fd < 0 || pr->fg_dat_fd < 0) {
		pr_err("DSA fine-grained page requested without sidecar pages_id=%u\n",
		       pr->pages_img_id);
		return -1;
	}

	part_start_us = page_read_now_us();
	if (read_full_fd(pr->fg_idx_fd, &meta, sizeof(meta))) {
		pr_perror("Can't read DSA fine-grained page metadata");
		return -1;
	}
	pr->timing_fg_meta_us += page_read_now_us() - part_start_us;
	if (meta.vaddr != vaddr) {
		pr_err("DSA fine-grained metadata out of order want=%lx have=%" PRIx64 "\n",
		       vaddr, meta.vaddr);
		return -1;
	}

	if (meta.flags == DSA_FG_PAGE_FULL) {
		if (meta.data_len != PAGE_SIZE || meta.patch_count) {
			pr_err("Invalid DSA fine-grained full record vaddr=%lx len=%u patches=%u\n",
			       vaddr, meta.data_len, meta.patch_count);
			return -1;
		}
		part_start_us = page_read_now_us();
		if (pread_full_fd(pr->fg_dat_fd, buf, PAGE_SIZE, meta.data_off)) {
			pr_perror("Can't read DSA fine-grained full page");
			return -1;
		}
		pr->timing_fg_full_data_us += page_read_now_us() - part_start_us;
		pr->fg_pages_read++;
		pr->fg_full_pages_read++;
		pr->fg_patch_bytes_read += PAGE_SIZE;
		pr->timing_fg_read_us += page_read_now_us() - start_us;
		return 0;
	}

	if (meta.flags != DSA_FG_PAGE_PATCH) {
		pr_err("Unknown DSA fine-grained record flags=%u vaddr=%lx\n",
		       meta.flags, vaddr);
		return -1;
	}

	if (!pr->parent) {
		pr_err("DSA fine-grained patch page has no parent vaddr=%lx\n", vaddr);
		return -1;
	}
	part_start_us = page_read_now_us();
	if (read_parent_page(pr, vaddr, 1, buf, flags & ~(PR_ASYNC | PR_ASAP)) < 0)
		return -1;
	pr->timing_fg_patch_parent_incl_us += page_read_now_us() - part_start_us;

	entries_len = (size_t)meta.patch_count * sizeof(struct dsa_fg_patch_entry);
	if (entries_len > meta.data_len) {
		pr_err("Invalid DSA fine-grained patch record vaddr=%lx entries=%zu len=%u\n",
		       vaddr, entries_len, meta.data_len);
		return -1;
	}
	if (!meta.data_len)
		return 0;

	data = xmalloc(meta.data_len);
	if (!data)
		return -1;
	part_start_us = page_read_now_us();
	if (pread_full_fd(pr->fg_dat_fd, data, meta.data_len, meta.data_off)) {
		pr_perror("Can't read DSA fine-grained patch data");
		goto out;
	}
	pr->timing_fg_patch_data_us += page_read_now_us() - part_start_us;

	bytes_off = entries_len;
	part_start_us = page_read_now_us();
	for (i = 0; i < meta.patch_count; i++) {
		struct dsa_fg_patch_entry *patch = data;
		u16 off = patch[i].off;
		u16 len = patch[i].len;

		if ((unsigned int)off + len > PAGE_SIZE ||
		    bytes_off + len > meta.data_len) {
			pr_err("Invalid DSA fine-grained patch entry vaddr=%lx off=%u len=%u\n",
			       vaddr, off, len);
			goto out;
		}
		memcpy((char *)buf + off, (char *)data + bytes_off, len);
		bytes_off += len;
	}
	pr->timing_fg_patch_apply_us += page_read_now_us() - part_start_us;
	if (bytes_off != meta.data_len) {
		pr_err("DSA fine-grained patch trailing data vaddr=%lx used=%zu len=%u\n",
		       vaddr, bytes_off, meta.data_len);
		goto out;
	}

	ret = 0;
	pr->fg_pages_read++;
	pr->fg_patch_pages_read++;
	pr->fg_patch_bytes_read += meta.data_len;
out:
	xfree(data);
	pr->timing_fg_read_us += page_read_now_us() - start_us;
	return ret;
}

static int read_fg_pages(struct page_read *pr, unsigned long vaddr,
			 unsigned long nr, void *buf, unsigned flags)
{
	unsigned long i;

	for (i = 0; i < nr; i++) {
		if (read_fg_page_one(pr, vaddr + i * PAGE_SIZE,
				     (char *)buf + i * PAGE_SIZE, flags))
			return -1;
	}
	if (pr->io_complete)
		return pr->io_complete(pr, vaddr, nr);
	return 0;
}

static int enqueue_async_iov(struct page_read *pr, void *buf, unsigned long len, struct list_head *to)
{
	struct page_read_iov *pr_iov;
	struct iovec *iov;

	pr_iov = xzalloc(sizeof(*pr_iov));
	if (!pr_iov)
		return -1;

	pr_iov->from = pr->pi_off;
	pr_iov->end = pr->pi_off + len;

	iov = xzalloc(sizeof(*iov));
	if (!iov) {
		xfree(pr_iov);
		return -1;
	}

	iov->iov_base = buf;
	iov->iov_len = len;

	pr_iov->to = iov;
	pr_iov->nr = 1;

	list_add_tail(&pr_iov->l, to);

	return 0;
}

int pagemap_render_iovec(struct list_head *from, struct task_restore_args *ta)
{
	struct page_read_iov *piov;

	ta->vma_ios = (struct restore_vma_io *)rst_mem_align_cpos(RM_PRIVATE);
	ta->vma_ios_n = 0;

	list_for_each_entry(piov, from, l) {
		struct restore_vma_io *rio;

		pr_debug("`- render %d iovs (%p:%zd...)\n", piov->nr, piov->to[0].iov_base, piov->to[0].iov_len);
		rio = rst_mem_alloc(RIO_SIZE(piov->nr), RM_PRIVATE);
		if (!rio)
			return -1;

		rio->nr_iovs = piov->nr;
		rio->off = piov->from;
		memcpy(rio->iovs, piov->to, piov->nr * sizeof(struct iovec));

		ta->vma_ios_n++;
	}

	return 0;
}

int pagemap_enqueue_iovec(struct page_read *pr, void *buf, unsigned long len, struct list_head *to)
{
	struct page_read_iov *cur_async = NULL;
	struct iovec *iov;

	if (!list_empty(to))
		cur_async = list_entry(to->prev, struct page_read_iov, l);

	/*
	 * We don't have any async requests or we have new read
	 * request that should happen at pos _after_ some hole from
	 * the previous one.
	 * Start the new preadv request here.
	 */
	if (!cur_async || pr->pi_off != cur_async->end)
		return enqueue_async_iov(pr, buf, len, to);

	/*
	 * This read is pure continuation of the previous one. Let's
	 * just add another IOV (or extend one of the existing).
	 */
	iov = &cur_async->to[cur_async->nr - 1];
	if (iov->iov_base + iov->iov_len == buf) {
		/* Extendable */
		iov->iov_len += len;
	} else {
		/* Need one more target iovec */
		unsigned int n_iovs = cur_async->nr + 1;

		if (n_iovs >= IOV_MAX)
			return enqueue_async_iov(pr, buf, len, to);

		iov = xrealloc(cur_async->to, n_iovs * sizeof(*iov));
		if (!iov)
			return -1;

		cur_async->to = iov;

		iov += cur_async->nr;
		iov->iov_base = buf;
		iov->iov_len = len;

		cur_async->nr = n_iovs;
	}

	cur_async->end += len;

	return 0;
}

static int maybe_read_page_local(struct page_read *pr, unsigned long vaddr, unsigned long nr, void *buf, unsigned flags)
{
	int ret;
	unsigned long len = nr * PAGE_SIZE;

	/*
	 * There's no API in the kernel to start asynchronous
	 * cached read (or write), so in case someone is asking
	 * for us for urgent async read, just do the regular
	 * cached read.
	 */
	if ((flags & (PR_ASYNC | PR_ASAP)) == PR_ASYNC) {
		ret = pagemap_enqueue_iovec(pr, buf, len, &pr->async);
		if (ret == 0) {
			pr->async_enqueued_bytes += len;
			pr->async_enqueued_iovs++;
		}
	} else {
		ret = read_local_page(pr, vaddr, len, buf);
		if (ret == 0 && pr->io_complete)
			ret = pr->io_complete(pr, vaddr, nr);
	}

	pr->pi_off += len;
	if (ret == 0) {
		pr->pages_read += nr;
		pr->bytes_read += len;
	}

	return ret;
}

static int maybe_read_page_hot(struct page_read *pr, unsigned long vaddr, unsigned long nr, void *buf, unsigned flags)
{
	struct hot_read_ctx *ctx = pr->hot;
	unsigned long len = nr * PAGE_SIZE;
	unsigned long done = 0;

	(void)flags;
	if (!ctx) {
		pr_err("hot page_read has no context\n");
		return -1;
	}

	while (done < len) {
		struct hot_read_segment *seg;
		unsigned long addr = vaddr + done;
		unsigned long chunk;
		size_t curr = 0;

		seg = hot_read_find(pr, pr->img_id, addr);
		if (!seg) {
			pr_err("hot page_read missing img_id=%lu vaddr=%lx\n",
			       pr->img_id, addr);
			return -1;
		}

		chunk = seg->vaddr + seg->len - addr;
		if (chunk > len - done)
			chunk = len - done;

		while (curr < chunk) {
			uint64_t start_us = page_read_now_us();
			ssize_t ret = pread(seg->fd, buf + done + curr,
					    chunk - curr,
					    seg->off + (addr - seg->vaddr) + curr);
			pr->timing_hot_pread_us += page_read_now_us() - start_us;
			pr->hot_pread_calls++;
			if (ret < 1) {
				pr_perror("hot page_read failed segment=%s ret=%zd",
					  seg->file, ret);
				return -1;
			}
			curr += ret;
		}
		done += chunk;
		if (done < len)
			pr->hot_cross_segment_reads++;
	}

	pr->pi_off += len;
	pr->pages_read += nr;
	pr->bytes_read += len;
	if (pr->io_complete)
		return pr->io_complete(pr, vaddr, nr);
	return 0;
}

/*
 * We cannot use maybe_read_page_local() for streaming images as it uses
 * pread(), seeking in the file. Instead, we use this custom page reader.
 */
static int maybe_read_page_img_streamer(struct page_read *pr, unsigned long vaddr, unsigned long nr, void *buf, unsigned flags)
{
	unsigned long len = nr * PAGE_SIZE;
	int fd;
	int ret;
	size_t curr = 0;

	fd = img_raw_fd(pr->pi);
	if (fd < 0) {
		pr_err("Getting raw FD failed\n");
		return -1;
	}

	pr_debug("\tpr%lu-%u Read page from self %lx/%" PRIx64 "\n", pr->img_id, pr->id, pr->cvaddr, pr->pi_off);

	/* We can't seek. The requested address better match */
	BUG_ON(pr->cvaddr != vaddr);

	while (1) {
		ret = read(fd, buf + curr, len - curr);
		if (ret == 0) {
			pr_err("Reached EOF unexpectedly while reading page from image\n");
			return -1;
		} else if (ret < 0) {
			pr_perror("Can't read mapping page %d", ret);
			return -1;
		}
		curr += ret;
		if (curr == len)
			break;
	}

	if (opts.auto_dedup)
		pr_warn_once("Can't dedup when streaming images\n");

	if (pr->io_complete)
		ret = pr->io_complete(pr, vaddr, nr);

	pr->pi_off += len;

	return ret;
}

static int read_page_complete(unsigned long img_id, unsigned long vaddr, unsigned long int nr_pages, void *priv)
{
	int ret = 0;
	struct page_read *pr = priv;

	if (pr->img_id != img_id) {
		pr_err("Out of order read completed (want %lu have %lu)\n", pr->img_id, img_id);
		return -1;
	}

	if (pr->io_complete)
		ret = pr->io_complete(pr, vaddr, nr_pages);
	else
		pr_warn_once("Remote page read w/o io_complete!\n");

	return ret;
}

static int maybe_read_page_remote(struct page_read *pr, unsigned long vaddr, unsigned long nr, void *buf, unsigned flags)
{
	int ret;

	/* We always do PR_ASAP mode here (FIXME?) */
	ret = request_remote_pages(pr->img_id, vaddr, nr);
	if (!ret)
		ret = page_server_start_read(buf, nr, read_page_complete, pr, flags);
	return ret;
}

static int read_pagemap_page(struct page_read *pr, unsigned long vaddr, unsigned long nr, void *buf, unsigned flags)
{
	pr_debug("pr%lu-%u Read %lx %lu pages\n", pr->img_id, pr->id, vaddr, nr);
	pagemap_bound_check(pr->pe, vaddr, nr);

	if (pagemap_dsa_fg(pr->pe) && !pr->hot_restore) {
		if (read_fg_pages(pr, vaddr, nr, buf, flags) < 0)
			return -1;
	} else if (pagemap_in_parent(pr->pe) && !pr->hot_restore) {
		if (read_parent_page(pr, vaddr, nr, buf, flags) < 0)
			return -1;
	} else {
		if (pr->maybe_read_page(pr, vaddr, nr, buf, flags) < 0)
			return -1;
	}

	pr->cvaddr += nr * PAGE_SIZE;

	return 1;
}

static void free_pagemaps(struct page_read *pr)
{
	int i;

	for (i = 0; i < pr->nr_pmes; i++)
		pagemap_entry__free_unpacked(pr->pmes[i], NULL);

	xfree(pr->pmes);
	pr->pmes = NULL;
}

static void advance_piov(struct page_read_iov *piov, ssize_t len)
{
	ssize_t olen = len;
	int onr = piov->nr;
	piov->from += len;

	while (len) {
		struct iovec *cur = piov->to;

		if (cur->iov_len <= len) {
			piov->to++;
			piov->nr--;
			len -= cur->iov_len;
			continue;
		}

		cur->iov_base += len;
		cur->iov_len -= len;
		break;
	}

	pr_debug("Advanced iov %zu bytes, %d->%d iovs, %zu tail\n", olen, onr, piov->nr, len);
}

static int process_async_reads(struct page_read *pr)
{
	int fd, ret = 0;
	struct page_read_iov *piov, *n;
	uint64_t sync_start_us = page_read_now_us();

	fd = img_raw_fd(pr->pi);
	list_for_each_entry_safe(piov, n, &pr->async, l) {
		ssize_t ret;
		struct iovec *iovs = piov->to;

		pr_debug("Read piov iovs %d, from %ju, len %ju, first %p:%zu\n", piov->nr, piov->from,
			 piov->end - piov->from, piov->to->iov_base, piov->to->iov_len);
	more:
		{
			uint64_t start_us = page_read_now_us();
		ret = preadv(fd, piov->to, piov->nr, piov->from);
			pr->timing_disk_pread_us += page_read_now_us() - start_us;
			pr->disk_pread_calls++;
		}
		if (fault_injected(FI_PARTIAL_PAGES)) {
			/*
			 * We might have read everything, but for debug
			 * purposes let's try to force the advance_piov()
			 * and re-read tail.
			 */
			if (ret > 0 && piov->nr >= 2) {
				pr_debug("`- trim preadv %zu\n", ret);
				ret /= 2;
			}
		}

		if (ret < 0) {
			pr_err("Can't read async pr bytes (%zd / %ju read, %ju off, %d iovs)\n", ret,
			       piov->end - piov->from, piov->from, piov->nr);
			return -1;
		}

		if (ret == 0 && piov->end != piov->from) {
			pr_err("Unexpected EOF reading pages: expected %ju more bytes at offset %ju\n",
			       piov->end - piov->from, piov->from);
			return -1;
		}

		if (opts.auto_dedup && punch_hole(pr, piov->from, ret, false))
			return -1;

		if (ret != piov->end - piov->from) {
			/*
			 * The preadv() can return less than requested. It's
			 * valid and doesn't mean error or EOF. We should advance
			 * the iovecs and continue
			 *
			 * Modify the piov in-place, we're going to drop this one
			 * anyway.
			 */

			advance_piov(piov, ret);
			goto more;
		}

		BUG_ON(pr->io_complete); /* FIXME -- implement once needed */

		list_del(&piov->l);
		xfree(iovs);
		xfree(piov);
	}

	if (pr->parent)
		ret = process_async_reads(pr->parent);

	pr->timing_async_sync_us += page_read_now_us() - sync_start_us;
	return ret;
}

static int hot_read_sync(struct page_read *pr)
{
	(void)pr;
	return 0;
}

static void close_page_read(struct page_read *pr)
{
	int ret;
	uint64_t exclusive_total_us;

	BUG_ON(!list_empty(&pr->async));

	if (pr->bunch.iov_len > 0) {
		ret = punch_hole(pr, 0, 0, true);
		if (ret == -1)
			return;

		pr->bunch.iov_len = 0;
	}

	if (pr->parent) {
		close_page_read(pr->parent);
		xfree(pr->parent);
	}

	if (pr->pmi)
		close_image(pr->pmi);
	if (pr->pi)
		close_image(pr->pi);
	if (pr->fg_idx_fd >= 0) {
		close(pr->fg_idx_fd);
		pr->fg_idx_fd = -1;
	}
	if (pr->fg_dat_fd >= 0) {
		close(pr->fg_dat_fd);
		pr->fg_dat_fd = -1;
	}
	if (pr->hot) {
		hot_read_close_ctx(pr->hot);
		pr->hot = NULL;
	}

	pr_info("PAGE_READ_TIMING img_id=%lu pages_id=%u hot=%u pages=%" PRIu64 " bytes=%" PRIu64 " open_total_us=%" PRIu64 " manifest_parse_us=%" PRIu64 " segment_open_us=%" PRIu64 " init_pagemaps_us=%" PRIu64 " segment_count=%" PRIu64 " manifest_bytes=%" PRIu64 " hot_find_us=%" PRIu64 " hot_find_calls=%" PRIu64 " hot_find_steps=%" PRIu64 " hot_find_steps_max=%" PRIu64 " hot_pread_us=%" PRIu64 " hot_pread_calls=%" PRIu64 " hot_cross_segment_reads=%" PRIu64 " disk_pread_us=%" PRIu64 " disk_pread_calls=%" PRIu64 " fg_read_us=%" PRIu64 " fg_pages=%" PRIu64 " fg_full_pages=%" PRIu64 " fg_patch_pages=%" PRIu64 " fg_patch_bytes=%" PRIu64 " parent_read_us=%" PRIu64 " async_sync_us=%" PRIu64 " async_enqueued_bytes=%" PRIu64 " async_enqueued_iovs=%" PRIu64 "\n",
		pr->img_id, pr->pages_img_id, pr->hot_restore ? 1 : 0,
		pr->pages_read, pr->bytes_read, pr->timing_open_total_us,
		pr->timing_manifest_parse_us, pr->timing_segment_open_us,
		pr->timing_init_pagemaps_us, pr->segment_count, pr->manifest_bytes,
		pr->timing_hot_find_us, pr->hot_find_calls, pr->hot_find_steps,
		pr->hot_find_steps_max, pr->timing_hot_pread_us, pr->hot_pread_calls,
		pr->hot_cross_segment_reads, pr->timing_disk_pread_us,
		pr->disk_pread_calls, pr->timing_fg_read_us, pr->fg_pages_read,
		pr->fg_full_pages_read, pr->fg_patch_pages_read,
		pr->fg_patch_bytes_read, pr->timing_parent_read_us,
		pr->timing_async_sync_us, pr->async_enqueued_bytes,
		pr->async_enqueued_iovs);

	exclusive_total_us = pr->timing_hot_find_us + pr->timing_hot_pread_us +
		pr->timing_disk_pread_us + pr->timing_fg_meta_us +
		pr->timing_fg_full_data_us + pr->timing_fg_patch_data_us +
		pr->timing_fg_patch_apply_us + pr->timing_parent_seek_us +
		pr->timing_async_sync_us;
	pr_info("PAGE_READ_EXCLUSIVE_TIMING img_id=%lu pages_id=%u hot=%u pages=%" PRIu64 " bytes=%" PRIu64 " exclusive_total_us=%" PRIu64 " parent_calls=%" PRIu64 " parent_pages=%" PRIu64 " parent_seek_us=%" PRIu64 " parent_child_incl_us=%" PRIu64 " fg_meta_us=%" PRIu64 " fg_full_data_us=%" PRIu64 " fg_patch_parent_incl_us=%" PRIu64 " fg_patch_data_us=%" PRIu64 " fg_patch_apply_us=%" PRIu64 " hot_find_us=%" PRIu64 " hot_pread_us=%" PRIu64 " disk_pread_us=%" PRIu64 " async_sync_us=%" PRIu64 "\n",
		pr->img_id, pr->pages_img_id, pr->hot_restore ? 1 : 0,
		pr->pages_read, pr->bytes_read, exclusive_total_us,
		pr->parent_read_calls, pr->parent_read_pages,
		pr->timing_parent_seek_us, pr->timing_parent_child_incl_us,
		pr->timing_fg_meta_us, pr->timing_fg_full_data_us,
		pr->timing_fg_patch_parent_incl_us, pr->timing_fg_patch_data_us,
		pr->timing_fg_patch_apply_us, pr->timing_hot_find_us,
		pr->timing_hot_pread_us, pr->timing_disk_pread_us,
		pr->timing_async_sync_us);

	if (pr->pmes)
		free_pagemaps(pr);
}

static void reset_pagemap(struct page_read *pr)
{
	pr->cvaddr = 0;
	pr->pi_off = 0;
	pr->curr_pme = -1;
	pr->pe = NULL;
	if (pr->fg_idx_fd >= 0 && lseek(pr->fg_idx_fd, 0, SEEK_SET) == (off_t)-1)
		pr_perror("Can't reset DSA fine-grained metadata");

	/* FIXME: take care of bunch */

	if (pr->parent)
		reset_pagemap(pr->parent);
}

static int try_open_parent(int dfd, unsigned long id, struct page_read *pr, int pr_flags)
{
	int pfd, ret;
	struct page_read *parent = NULL;

	/* Image streaming lacks support for incremental images */
	if (opts.stream)
		goto out;

	if (open_parent(dfd, &pfd))
		goto err;
	if (pfd < 0)
		goto out;

	parent = xmalloc(sizeof(*parent));
	if (!parent)
		goto err_cl;

	ret = open_page_read_at(pfd, id, parent, pr_flags);
	if (ret < 0)
		goto err_free;

	if (!ret) {
		xfree(parent);
		parent = NULL;
	}

	close(pfd);
out:
	pr->parent = parent;
	return 0;

err_free:
	xfree(parent);
err_cl:
	close(pfd);
err:
	return -1;
}

static void init_compat_pagemap_entry(PagemapEntry *pe)
{
	/*
	 * pagemap image generated with older version will either
	 * contain a hole because the pages are in the parent
	 * snapshot or a pagemap that should be marked with
	 * PE_PRESENT
	 */
	if (pe->has_in_parent && pe->in_parent)
		pe->flags |= PE_PARENT;
	else if (!pe->has_flags)
		pe->flags = PE_PRESENT;

	if (!pe->has_nr_pages)
		pe->nr_pages = pe->compat_nr_pages;
}

/*
 * The pagemap entry size is at least 8 bytes for small mappings with
 * low address and may get to 18 bytes or even more for large mappings
 * with high address and in_parent flag set. 16 seems to be nice round
 * number to minimize {over,under}-allocations
 */
#define PAGEMAP_ENTRY_SIZE_ESTIMATE 16

static int init_pagemaps(struct page_read *pr)
{
	off_t fsize;
	int nr_pmes, nr_realloc;

	if (opts.stream) {
		/*
		 * TODO - There is no easy way to estimate the size of the
		 * pagemap that is still to be read from the pipe. Possible
		 * solution is to ask the image streamer for the size of the
		 * image. 1024 is a wild guess (more space is allocated if
		 * needed).
		 */
		fsize = 1024;
	} else {
		fsize = img_raw_size(pr->pmi);
	}

	if (fsize < 0)
		return -1;

	nr_pmes = fsize / PAGEMAP_ENTRY_SIZE_ESTIMATE + 1;
	nr_realloc = nr_pmes / 2;

	pr->pmes = xzalloc(nr_pmes * sizeof(*pr->pmes));
	if (!pr->pmes)
		return -1;

	pr->nr_pmes = 0;
	pr->curr_pme = -1;

	while (1) {
		int ret = pb_read_one_eof(pr->pmi, &pr->pmes[pr->nr_pmes], PB_PAGEMAP);
		if (ret < 0)
			goto free_pagemaps;
		if (ret == 0)
			break;

		init_compat_pagemap_entry(pr->pmes[pr->nr_pmes]);

		pr->nr_pmes++;
		if (pr->nr_pmes >= nr_pmes) {
			PagemapEntry **new;
			nr_pmes += nr_realloc;
			new = xrealloc(pr->pmes, nr_pmes * sizeof(*pr->pmes));
			if (!new)
				goto free_pagemaps;
			pr->pmes = new;
		}
	}

	close_image(pr->pmi);
	pr->pmi = NULL;

	return 0;

free_pagemaps:
	free_pagemaps(pr);
	return -1;
}

int open_page_read_at(int dfd, unsigned long img_id, struct page_read *pr, int pr_flags)
{
	int flags, i_typ;
	static unsigned ids = 1;
	bool remote = pr_flags & PR_REMOTE;
	bool hot_restore = hot_restore_enabled() && !(pr_flags & PR_REMOTE);
	uint64_t open_start_us = page_read_now_us();
	uint64_t init_start_us;

	/*
	 * Only the top-most page-read can be remote, all the
	 * others are always local.
	 */
	pr_flags &= ~PR_REMOTE;
	if (opts.auto_dedup)
		pr_flags |= PR_MOD;
	if (pr_flags & PR_MOD)
		flags = O_RDWR;
	else
		flags = O_RSTR;

	switch (pr_flags & PR_TYPE_MASK) {
	case PR_TASK:
		i_typ = CR_FD_PAGEMAP;
		break;
	case PR_SHMEM:
		i_typ = CR_FD_SHMEM_PAGEMAP;
		hot_restore = false;
		break;
	default:
		BUG();
		return -1;
	}

	INIT_LIST_HEAD(&pr->async);
	pr->pe = NULL;
	pr->parent = NULL;
	pr->cvaddr = 0;
	pr->pi_off = 0;
	pr->bunch.iov_len = 0;
	pr->bunch.iov_base = NULL;
	pr->pmes = NULL;
	pr->pi = NULL;
	pr->pmi = NULL;
	pr->hot = NULL;
	pr->fg_idx_fd = -1;
	pr->fg_dat_fd = -1;
	pr->hot_restore = hot_restore;
	pr->timing_open_total_us = 0;
	pr->timing_manifest_parse_us = 0;
	pr->timing_segment_open_us = 0;
	pr->timing_init_pagemaps_us = 0;
	pr->timing_hot_find_us = 0;
	pr->timing_hot_pread_us = 0;
	pr->timing_disk_pread_us = 0;
	pr->timing_fg_read_us = 0;
	pr->timing_parent_read_us = 0;
	pr->timing_async_sync_us = 0;
	pr->timing_parent_seek_us = 0;
	pr->timing_parent_child_incl_us = 0;
	pr->timing_fg_meta_us = 0;
	pr->timing_fg_full_data_us = 0;
	pr->timing_fg_patch_parent_incl_us = 0;
	pr->timing_fg_patch_data_us = 0;
	pr->timing_fg_patch_apply_us = 0;
	pr->hot_find_calls = 0;
	pr->hot_find_steps = 0;
	pr->hot_find_steps_max = 0;
	pr->hot_pread_calls = 0;
	pr->hot_cross_segment_reads = 0;
	pr->disk_pread_calls = 0;
	pr->parent_read_calls = 0;
	pr->parent_read_pages = 0;
	pr->fg_pages_read = 0;
	pr->fg_full_pages_read = 0;
	pr->fg_patch_pages_read = 0;
	pr->fg_patch_bytes_read = 0;
	pr->pages_read = 0;
	pr->bytes_read = 0;
	pr->async_enqueued_bytes = 0;
	pr->async_enqueued_iovs = 0;
	pr->segment_count = 0;
	pr->manifest_bytes = 0;
	pr->pieok = false;
	pr->disable_dedup = false;
	pr->img_id = img_id;

	pr->pmi = open_image_at(dfd, i_typ, O_RSTR, img_id);
	if (!pr->pmi)
		return -1;

	if (empty_image(pr->pmi)) {
		close_image(pr->pmi);
		return 0;
	}

	if (!hot_restore && try_open_parent(dfd, img_id, pr, pr_flags)) {
		close_image(pr->pmi);
		return -1;
	}

	if (hot_restore) {
		PagemapHead *h;

		if (opts.auto_dedup)
			pr_warn_once("hot page_read disables auto-dedup\n");
		if (pb_read_one(pr->pmi, &h, PB_PAGEMAP_HEAD) < 0) {
			close_page_read(pr);
			return -1;
		}
		pr->pages_img_id = h->pages_id;
		pagemap_head__free_unpacked(h, NULL);
	} else {
		pr->pi = open_pages_image_at(dfd, flags, pr->pmi, &pr->pages_img_id);
		if (!pr->pi) {
			close_page_read(pr);
			return -1;
		}
		if (open_fg_sidecar_at(dfd, pr)) {
			close_page_read(pr);
			return -1;
		}
	}

	init_start_us = page_read_now_us();
	if (init_pagemaps(pr)) {
		close_page_read(pr);
		return -1;
	}
	pr->timing_init_pagemaps_us += page_read_now_us() - init_start_us;

	if (hot_restore && hot_read_load_ctx(pr)) {
		close_page_read(pr);
		return -1;
	}

	pr->read_pages = read_pagemap_page;
	pr->advance = advance;
	pr->close = close_page_read;
	pr->skip_pages = skip_pagemap_pages;
	pr->sync = hot_restore ? hot_read_sync : process_async_reads;
	pr->seek_pagemap = seek_pagemap;
	pr->reset = reset_pagemap;
	pr->io_complete = NULL; /* set up by the client if needed */
	pr->id = ids++;

	if (hot_restore) {
		pr->maybe_read_page = maybe_read_page_hot;
		pr->pieok = false;
	} else if (remote)
		pr->maybe_read_page = maybe_read_page_remote;
	else if (opts.stream)
		pr->maybe_read_page = maybe_read_page_img_streamer;
	else {
		pr->maybe_read_page = maybe_read_page_local;
		if (!pr->parent && !opts.lazy_pages && pr->fg_idx_fd < 0)
			pr->pieok = true;
	}

	pr_debug("Opened %s page read %u (parent %u)\n", hot_restore ? "hot" : (remote ? "remote" : "local"), pr->id,
		 pr->parent ? pr->parent->id : 0);
	pr->timing_open_total_us += page_read_now_us() - open_start_us;

	return 1;
}

int open_page_read(unsigned long img_id, struct page_read *pr, int pr_flags)
{
	return open_page_read_at(get_service_fd(IMG_FD_OFF), img_id, pr, pr_flags);
}

#define DUP_IDS_BASE 1000

void page_read_disable_dedup(struct page_read *pr)
{
	pr_debug("disable dedup, id: %d\n", pr->id);
	pr->disable_dedup = true;
	if (pr->parent)
		page_read_disable_dedup(pr->parent);
}

void dup_page_read(struct page_read *src, struct page_read *dst)
{
	static int dup_ids = 1;

	memcpy(dst, src, sizeof(*dst));
	INIT_LIST_HEAD(&dst->async);
	dst->id = src->id + DUP_IDS_BASE * dup_ids++;
	dst->reset(dst);
}
