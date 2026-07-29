#ifndef __CR_BFD_H__
#define __CR_BFD_H__

#include "common/err.h"

struct bfd_buf;
struct xbuf {
	char *mem;	 /* buffer */
	char *data;	 /* position we see bytes at */
	unsigned int sz; /* bytes sitting after b->pos */
	struct bfd_buf *buf;
};

struct bfd {
	int fd;
	bool writable;
	/* A DSA direct-output image keeps CRIU's normal logical byte stream,
	 * but flushes it in page-aligned O_DIRECT units.  This is deliberately
	 * opt-in: ordinary CRIU images retain the historical buffered BFD path. */
	bool direct;
	bool direct_finished;
	bool direct_external_buffer;
	off_t direct_logical;
	size_t direct_capacity;
	u64 direct_write_calls;
	struct xbuf b;
};

static inline bool bfd_buffered(struct bfd *b)
{
	return b->b.mem != NULL;
}

static inline void bfd_setraw(struct bfd *b)
{
	b->b.mem = NULL;
}

int bfdopenr(struct bfd *f);
int bfdopenw(struct bfd *f);
int bfdopenw_direct(struct bfd *f);
int bfd_direct_rebind_buffer(struct bfd *f, void *mem, size_t capacity);
int bfd_direct_finish(struct bfd *f);
int bfd_direct_close(struct bfd *f);
static inline bool bfd_direct(struct bfd *f)
{
	return f->direct;
}
static inline u64 bfd_direct_write_calls(struct bfd *f)
{
	return f->direct_write_calls;
}
void bclose(struct bfd *f);
char *breadline(struct bfd *f);
char *breadchr(struct bfd *f, char c);
int bwrite(struct bfd *f, const void *buf, int sz);
struct iovec;
int bwritev(struct bfd *f, const struct iovec *iov, int cnt);
int bread(struct bfd *f, void *buf, int sz);
int bfd_flush_images(void);
#endif
