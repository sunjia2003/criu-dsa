#ifndef __CR_DSA_HOST_PREFETCH_H__
#define __CR_DSA_HOST_PREFETCH_H__

#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <limits.h>

struct dsa_prefetch;
struct dsa_prefetch_worker {
	struct dsa_prefetch *pool;
	pthread_t thread;
	unsigned int index;
};
struct dsa_prefetch_slot {
	uint64_t sequence;
	void *data;
	unsigned int ready;
};
struct dsa_prefetch {
	uint64_t next;
	char next_padding[64];
	uint64_t consumed;
	char consumed_padding[64];
	uint64_t task_count;
	unsigned int depth, started, spin, waiters, spin_limit;
	int stop, error, initialized;
	pthread_mutex_t lock;
	pthread_cond_t changed;
	struct dsa_prefetch_worker workers[2];
	struct dsa_prefetch_slot *slots;
	void *context;
	int (*run)(void *, unsigned int, uint64_t, void *);
};

static void dsa_prefetch_notify(struct dsa_prefetch *pool)
{
	__atomic_thread_fence(__ATOMIC_SEQ_CST);
	if (!__atomic_load_n(&pool->waiters, __ATOMIC_SEQ_CST))
		return;
	pthread_mutex_lock(&pool->lock);
	pthread_cond_broadcast(&pool->changed);
	pthread_mutex_unlock(&pool->lock);
}

static int dsa_prefetch_progress(struct dsa_prefetch *pool, uint64_t sequence, int window)
{
	if (__atomic_load_n(&pool->stop, __ATOMIC_ACQUIRE) ||
	    __atomic_load_n(&pool->error, __ATOMIC_ACQUIRE))
		return 1;
	if (window)
		return sequence - __atomic_load_n(&pool->consumed, __ATOMIC_ACQUIRE) < pool->depth;
	return __atomic_load_n(&pool->slots[sequence % pool->depth].ready, __ATOMIC_ACQUIRE);
}

static int dsa_prefetch_wait_progress(struct dsa_prefetch *pool, uint64_t sequence, int window)
{
	unsigned int attempts = pool->spin ? (pool->spin_limit ? pool->spin_limit : 4096) : 0;
	int error;

	while (!dsa_prefetch_progress(pool, sequence, window) && attempts) {
		dsa_host_relax();
		if (attempts != UINT_MAX)
			attempts--;
	}
	if (!dsa_prefetch_progress(pool, sequence, window)) {
		pthread_mutex_lock(&pool->lock);
		/* Register before checking the predicate, preventing a lost wake-up. */
		__atomic_add_fetch(&pool->waiters, 1, __ATOMIC_SEQ_CST);
		while (!dsa_prefetch_progress(pool, sequence, window))
			pthread_cond_wait(&pool->changed, &pool->lock);
		__atomic_sub_fetch(&pool->waiters, 1, __ATOMIC_SEQ_CST);
		pthread_mutex_unlock(&pool->lock);
	}
	error = __atomic_load_n(&pool->error, __ATOMIC_ACQUIRE);
	return error ? error : (__atomic_load_n(&pool->stop, __ATOMIC_ACQUIRE) ? -ECANCELED : 0);
}

static void *dsa_prefetch_loop(void *argument)
{
	struct dsa_prefetch_worker *worker = argument;
	struct dsa_prefetch *pool = worker->pool;

	for (;;) {
		uint64_t sequence = __atomic_fetch_add(&pool->next, 1, __ATOMIC_RELAXED);
		struct dsa_prefetch_slot *slot;
		int ret;

		if (sequence >= pool->task_count || dsa_prefetch_wait_progress(pool, sequence, 1))
			break;
		/* A ticket enters only the bounded window. Later generations cannot
		 * reuse its slot before the ordered consumer advances past it. */
		slot = &pool->slots[sequence % pool->depth];
		ret = pool->run(pool->context, worker->index, sequence, slot->data);
		if (ret) {
			int expected = 0;
			__atomic_compare_exchange_n(&pool->error, &expected, ret, 0,
						    __ATOMIC_RELEASE, __ATOMIC_RELAXED);
			dsa_prefetch_notify(pool);
			break;
		}
		slot->sequence = sequence;
		__atomic_store_n(&slot->ready, 1, __ATOMIC_RELEASE);
		dsa_prefetch_notify(pool);
	}
	return NULL;
}

static void dsa_prefetch_fini(struct dsa_prefetch *pool)
{
	unsigned int i;

	if (!pool->initialized)
		return;
	__atomic_store_n(&pool->stop, 1, __ATOMIC_RELEASE);
	dsa_prefetch_notify(pool);
	for (i = 0; i < pool->started; i++)
		pthread_join(pool->workers[i].thread, NULL);
	pthread_cond_destroy(&pool->changed);
	pthread_mutex_destroy(&pool->lock);
	free(pool->slots);
	pool->slots = NULL;
	pool->initialized = 0;
}

static int dsa_prefetch_init(struct dsa_prefetch *pool, unsigned int workers, unsigned int depth,
			     uint64_t tasks, void **data, void *context,
			     int (*run)(void *, unsigned int, uint64_t, void *), int spin)
{
	unsigned int i;
	int ret;

	if (!workers || workers > 2 || depth < workers || !tasks)
		return -EINVAL;
	pool->depth = depth;
	pool->task_count = tasks;
	pool->context = context;
	pool->run = run;
	pool->spin = spin;
	pool->slots = calloc(depth, sizeof(*pool->slots));
	if (!pool->slots)
		return -ENOMEM;
	ret = pthread_mutex_init(&pool->lock, NULL);
	if (ret)
		goto fail_slots;
	ret = pthread_cond_init(&pool->changed, NULL);
	if (ret)
		goto fail_lock;
	pool->initialized = 1;
	for (i = 0; i < depth; i++)
		pool->slots[i].data = data[i];
	for (i = 0; i < workers; i++) {
		pool->workers[i].pool = pool;
		pool->workers[i].index = i;
		ret = pthread_create(&pool->workers[i].thread, NULL, dsa_prefetch_loop, &pool->workers[i]);
		if (ret) {
			dsa_prefetch_fini(pool);
			return -ret;
		}
		pool->started++;
	}
	return 0;
fail_lock:
	pthread_mutex_destroy(&pool->lock);
fail_slots:
	free(pool->slots);
	pool->slots = NULL;
	return -ret;
}

static int dsa_prefetch_wait(struct dsa_prefetch *pool, uint64_t sequence, void **result)
{
	struct dsa_prefetch_slot *slot;
	int ret = dsa_prefetch_wait_progress(pool, sequence, 0);

	if (ret)
		return ret;
	slot = &pool->slots[sequence % pool->depth];
	if (slot->sequence != sequence)
		return -EINVAL;
	*result = slot->data;
	return 0;
}

static void dsa_prefetch_release(struct dsa_prefetch *pool, uint64_t sequence)
{
	__atomic_store_n(&pool->slots[sequence % pool->depth].ready, 0, __ATOMIC_RELAXED);
	__atomic_store_n(&pool->consumed, sequence + 1, __ATOMIC_RELEASE);
	dsa_prefetch_notify(pool);
}

#endif
