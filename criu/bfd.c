#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <errno.h>

#include "int.h"
#include "log.h"
#include "common/bug.h"
#include "bfd.h"
#include "common/list.h"
#include "util.h"
#include "xmalloc.h"
#include "page.h"

#undef LOG_PREFIX
#define LOG_PREFIX "bfd: "

/*
 * Kernel doesn't produce more than one page of
 * date per one read call on proc files.
 */
#define BUFSIZE (PAGE_SIZE)
#define DSA_DIRECT_BFD_CAPACITY (2U * 1024U * 1024U)

struct bfd_buf {
	char *mem;
	struct list_head l;
};

static LIST_HEAD(bufs);

#define BUFBATCH (16)

static int buf_get(struct xbuf *xb)
{
	struct bfd_buf *b;

	if (list_empty(&bufs)) {
		void *mem;
		int i;

		mem = mmap(NULL, BUFBATCH * BUFSIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
		if (mem == MAP_FAILED) {
			pr_perror("No buf");
			return -1;
		}

		for (i = 0; i < BUFBATCH; i++) {
			b = xmalloc(sizeof(*b));
			if (!b) {
				if (i == 0) {
					pr_err("No buffer for bfd\n");
					return -1;
				}

				pr_warn("BFD buffers partial refil!\n");
				break;
			}

			b->mem = mem + i * BUFSIZE;
			list_add_tail(&b->l, &bufs);
		}
	}

	b = list_first_entry(&bufs, struct bfd_buf, l);
	list_del_init(&b->l);

	xb->mem = b->mem;
	xb->data = xb->mem;
	xb->sz = 0;
	xb->buf = b;
	return 0;
}

static void buf_put(struct xbuf *xb)
{
	/*
	 * Don't unmap buffer back, it will get reused
	 * by next bfdopen call
	 */
	list_add(&xb->buf->l, &bufs);
	xb->buf = NULL;
	xb->mem = NULL;
	xb->data = NULL;
}

static int bfdopen(struct bfd *f, bool writable)
{
	if (buf_get(&f->b)) {
		close_safe(&f->fd);
		return -1;
	}

	f->writable = writable;
	f->direct = false;
	f->direct_finished = false;
	f->direct_external_buffer = false;
	f->direct_logical = 0;
	f->direct_capacity = 0;
	f->direct_write_calls = 0;
	return 0;
}

int bfdopenr(struct bfd *f)
{
	return bfdopen(f, false);
}

int bfdopenw(struct bfd *f)
{
	return bfdopen(f, true);
}

int bfdopenw_direct(struct bfd *f)
{
	void *mem;

	mem = mmap(NULL, DSA_DIRECT_BFD_CAPACITY, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (mem == MAP_FAILED) {
		pr_perror("No direct BFD buffer");
		close_safe(&f->fd);
		return -1;
	}
	f->b.mem = mem;
	f->b.data = mem;
	f->b.sz = 0;
	f->b.buf = NULL;
	f->writable = true;
	f->direct = true;
	f->direct_finished = false;
	f->direct_external_buffer = false;
	f->direct_logical = 0;
	f->direct_capacity = DSA_DIRECT_BFD_CAPACITY;
	f->direct_write_calls = 0;
	return 0;
}

int bfd_direct_rebind_buffer(struct bfd *f, void *mem, size_t capacity)
{
	void *old_mem;
	size_t old_capacity;

	if (!f || !f->direct || !bfd_buffered(f) || f->direct_finished ||
	    !mem || !capacity || capacity % PAGE_SIZE ||
	    (unsigned long)mem % PAGE_SIZE || f->b.sz > capacity ||
	    f->b.data != f->b.mem) {
		errno = EINVAL;
		return -1;
	}
	if (f->direct_external_buffer && f->b.mem == mem &&
	    f->direct_capacity == capacity)
		return 0;
	if (f->direct_external_buffer) {
		errno = EBUSY;
		return -1;
	}

	old_mem = f->b.mem;
	old_capacity = f->direct_capacity;
	if (f->b.sz)
		memcpy(mem, f->b.data, f->b.sz);
	if (munmap(old_mem, old_capacity))
		return -1;
	f->b.mem = mem;
	f->b.data = mem;
	f->direct_capacity = capacity;
	f->direct_external_buffer = true;
	return 0;
}

static int bflush(struct bfd *bfd);
static bool flush_failed = false;

int bfd_flush_images(void)
{
	return flush_failed ? -1 : 0;
}

void bclose(struct bfd *f)
{
	if (bfd_buffered(f)) {
		if (f->writable &&
		    (f->direct ? bfd_direct_finish(f) : bflush(f)) < 0) {
			/*
			 * This is to propagate error up. It's
			 * hardly possible by returning and
			 * checking it, but setting a static
			 * flag, failing further bfdopen-s and
			 * checking one at the end would work.
			 */
			flush_failed = true;
			pr_perror("Error flushing image");
		}

		if (f->direct) {
			if (!f->direct_external_buffer)
				munmap(f->b.mem, f->direct_capacity);
			f->b.mem = NULL;
			f->b.data = NULL;
		} else {
			buf_put(&f->b);
		}
	}
	close_safe(&f->fd);
}

/* The direct writer never exposes its padding as logical image data: it
 * retains a sub-page tail until finish, zero-pads exactly one final block,
 * truncates back to the logical length and then makes completion durable. */
int bfd_direct_finish(struct bfd *f)
{
	if (!f || !f->direct || f->direct_finished)
		return 0;
	if (!bfd_buffered(f)) {
		if (fdatasync(f->fd) < 0) {
			pr_perror("Can't fdatasync direct raw image");
			return -1;
		}
		f->direct_finished = true;
		return 0;
	}
	while (f->b.sz)
		if (bflush(f) < 0)
			return -1;
	if (ftruncate(f->fd, f->direct_logical) < 0) {
		pr_perror("Can't truncate direct image");
		return -1;
	}
	if (fdatasync(f->fd) < 0) {
		pr_perror("Can't fdatasync direct image");
		return -1;
	}
	f->direct_finished = true;
	return 0;
}

int bfd_direct_close(struct bfd *f)
{
	int ret = 0;

	if (!f || !f->direct)
		return 0;
	if (bfd_direct_finish(f))
		return -1;
	if (bfd_buffered(f)) {
		if (!f->direct_external_buffer)
			munmap(f->b.mem, f->direct_capacity);
		f->b.mem = NULL;
		f->b.data = NULL;
	}
	if (close(f->fd) < 0) {
		pr_perror("Can't close direct image");
		ret = -1;
	}
	f->fd = -1;
	return ret;
}

static int brefill(struct bfd *f)
{
	int ret;
	struct xbuf *b = &f->b;

	memmove(b->mem, b->data, b->sz);
	b->data = b->mem;

	ret = read_all(f->fd, b->mem + b->sz, BUFSIZE - b->sz);
	if (ret < 0) {
		pr_perror("Error reading file");
		return -1;
	}

	if (ret == 0)
		return 0;

	b->sz += ret;
	return 1;
}

static char *strnchr(char *str, unsigned int len, char c)
{
	while (len > 0 && *str != c) {
		str++;
		len--;
	}

	return len == 0 ? NULL : str;
}

char *breadline(struct bfd *f)
{
	return breadchr(f, '\n');
}

char *breadchr(struct bfd *f, char c)
{
	struct xbuf *b = &f->b;
	bool refilled = false;
	char *n;
	unsigned int ss = 0;

again:
	n = strnchr(b->data + ss, b->sz - ss, c);
	if (n) {
		char *ret;

		ret = b->data;
		b->data = n + 1; /* skip the \n found */
		*n = '\0';
		b->sz -= (b->data - ret);
		return ret;
	}

	if (refilled) {
		if (!b->sz)
			return NULL;

		if (b->sz == BUFSIZE) {
			pr_err("The bfd buffer is too small\n");
			return ERR_PTR(-EIO);
		}
		/*
		 * Last bytes may lack the \n at the
		 * end, need to report this as full
		 * line anyway
		 */
		b->data[b->sz] = '\0';

		/*
		 * The b->data still points to old data,
		 * but we say that no bytes left there
		 * so next call to breadline will not
		 * "find" these bytes again.
		 */
		b->sz = 0;
		return b->data;
	}

	/*
	 * small optimization -- we've scanned b->sz
	 * symbols already, no need to re-scan them after
	 * the buffer refill.
	 */
	ss = b->sz;

	/* no full line in the buffer -- refill one */
	if (brefill(f) < 0)
		return ERR_PTR(-EIO);

	refilled = true;

	goto again;
}

static int bflush(struct bfd *bfd)
{
	struct xbuf *b = &bfd->b;
	int ret;
	size_t aligned;

	if (!b->sz)
		return 0;

	if (!bfd->direct) {
		ret = write_all(bfd->fd, b->data, b->sz);
		if (ret != b->sz)
			return -1;
		b->sz = 0;
		return 0;
	}

	/* A regular flush writes whole 4 KiB units.  bclose/finish is the only
	 * place allowed to emit a padded tail. */
	aligned = b->sz & ~(PAGE_SIZE - 1);
	if (!aligned && !bfd->direct_finished)
		aligned = PAGE_SIZE;
	if (aligned > b->sz) {
		memset(b->data + b->sz, 0, aligned - b->sz);
		ret = write_all(bfd->fd, b->data, aligned);
		if (ret != (int)aligned)
			return -1;
		bfd->direct_write_calls++;
		bfd->direct_logical += b->sz;
		b->sz = 0;
		return 0;
	}
	if (aligned) {
		ret = write_all(bfd->fd, b->data, aligned);
		if (ret != (int)aligned)
			return -1;
		bfd->direct_write_calls++;
		bfd->direct_logical += aligned;
		if (aligned != b->sz)
			memmove(b->data, b->data + aligned, b->sz - aligned);
		b->sz -= aligned;
	}
	return 0;
}

static int __bwrite(struct bfd *bfd, const void *buf, int size)
{
	struct xbuf *b = &bfd->b;
	const char *p = buf;

	if (bfd->direct) {
		size_t capacity = bfd->direct_capacity;

		/* Do not use write_all on caller buffers: protobuf objects are not
		 * necessarily suitably aligned for O_DIRECT. */
		while (size) {
			size_t room = capacity - b->sz;
			size_t chunk = (size_t)size < room ? (size_t)size : room;
			memcpy(b->data + b->sz, p, chunk);
			b->sz += chunk;
			p += chunk;
			size -= chunk;
			if (b->sz == capacity && bflush(bfd) < 0)
				return -1;
		}
		return p - (const char *)buf;
	}

	if (b->sz + size > BUFSIZE) {
		int ret;
		ret = bflush(bfd);
		if (ret < 0)
			return ret;
	}

	if (size > BUFSIZE)
		return write_all(bfd->fd, buf, size);

	memcpy(b->data + b->sz, buf, size);
	b->sz += size;
	return size;
}

int bwrite(struct bfd *bfd, const void *buf, int size)
{
	if (!bfd_buffered(bfd))
		return write_all(bfd->fd, buf, size);

	return __bwrite(bfd, buf, size);
}

int bwritev(struct bfd *bfd, const struct iovec *iov, int cnt)
{
	int i, written = 0;

	if (!bfd_buffered(bfd)) {
		/*
		 * FIXME writev() should be called again if writev() writes
		 * less bytes than requested.
		 */
		return writev(bfd->fd, iov, cnt);
	}

	for (i = 0; i < cnt; i++) {
		int ret;

		ret = __bwrite(bfd, (const void *)iov[i].iov_base, iov[i].iov_len);
		if (ret < 0)
			return ret;

		written += ret;
		if (ret < iov[i].iov_len)
			break;
	}

	return written;
}

int bread(struct bfd *bfd, void *buf, int size)
{
	struct xbuf *b = &bfd->b;
	int more = 1, filled = 0;

	if (!bfd_buffered(bfd))
		return read_all(bfd->fd, buf, size);

	while (more > 0) {
		int chunk;

		chunk = size - filled;
		if (chunk > b->sz)
			chunk = b->sz;

		if (chunk) {
			memcpy(buf + filled, b->data, chunk);
			b->data += chunk;
			b->sz -= chunk;
			filled += chunk;
		}

		if (filled < size)
			more = brefill(bfd);
		else {
			BUG_ON(filled > size);
			more = 0;
		}
	}

	return more < 0 ? more : filled;
}
