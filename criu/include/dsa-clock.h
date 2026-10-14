#ifndef __CR_DSA_CLOCK_H__
#define __CR_DSA_CLOCK_H__

#include <time.h>

typedef int (*dsa_clock_fn)(clockid_t, struct timespec *);

struct dsa_trace_clock {
	dsa_clock_fn fast, fallback;
	u64 vdso_reads, syscall_reads, max_bracket_ns, last_ns;
	u32 requested, selected, checks, errors, failed;
};

static inline int dsa_clock_valid(const struct timespec *ts)
{
	return ts->tv_sec >= 0 && ts->tv_nsec >= 0 && ts->tv_nsec < 1000000000L;
}

static inline u64 dsa_clock_ns(const struct timespec *ts)
{
	return (u64)ts->tv_sec * 1000000000ULL + ts->tv_nsec;
}

static inline int dsa_clock_read(struct dsa_trace_clock *c, struct timespec *ts)
{
	if (c->failed)
		return -1;
	if (c->fast) {
		c->vdso_reads++;
		if (!c->fast(CLOCK_MONOTONIC, ts) && dsa_clock_valid(ts) &&
		    dsa_clock_ns(ts) >= c->last_ns) {
			c->last_ns = dsa_clock_ns(ts);
			return 0;
		}
		c->errors++;
		c->fast = NULL;
		c->selected = 0;
	}
	c->syscall_reads++;
	if (c->fallback(CLOCK_MONOTONIC, ts) || !dsa_clock_valid(ts) ||
	    dsa_clock_ns(ts) < c->last_ns) {
		c->errors++;
		c->failed = 1;
		return -1;
	}
	c->last_ns = dsa_clock_ns(ts);
	return 0;
}

static inline void dsa_clock_try_vdso(struct dsa_trace_clock *c, dsa_clock_fn candidate)
{
	u32 i;

	if (!candidate || !c->requested)
		return;
	for (i = 0; i < 16; i++) {
		struct timespec before = { 0 }, fast = { 0 }, after = { 0 };
		u64 b, v, a;
		int r1, r2, r3;

		c->syscall_reads++;
		r1 = c->fallback(CLOCK_MONOTONIC, &before);
		c->vdso_reads++;
		r2 = candidate(CLOCK_MONOTONIC, &fast);
		c->syscall_reads++;
		r3 = c->fallback(CLOCK_MONOTONIC, &after);
		if (r1 || r2 || r3 || !dsa_clock_valid(&before) ||
		    !dsa_clock_valid(&fast) || !dsa_clock_valid(&after)) {
			c->errors++;
			return;
		}
		b = dsa_clock_ns(&before);
		v = dsa_clock_ns(&fast);
		a = dsa_clock_ns(&after);
		if (!b || b > v || v > a || b < c->last_ns) {
			c->errors++;
			return;
		}
		if (a - b > c->max_bracket_ns)
			c->max_bracket_ns = a - b;
		c->last_ns = a;
		c->checks++;
	}
	c->fast = candidate;
	c->selected = 1;
}

#endif
