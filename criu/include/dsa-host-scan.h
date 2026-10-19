#ifndef __CR_DSA_HOST_SCAN_H__
#define __CR_DSA_HOST_SCAN_H__

#include <errno.h>
#include <pthread.h>

/* One bounded result per worker. The owner consumes it before resubmission. */
struct dsa_host_job {
	pthread_t thread;
	pthread_mutex_t lock;
	pthread_cond_t changed;
	int state, stop, ret, started, spin;
	int (*run)(void *);
	void *context;
};

static inline void dsa_host_relax(void)
{
#if defined(__x86_64__) || defined(__i386__)
	__asm__ __volatile__("pause" ::: "memory");
#else
	__asm__ __volatile__("" ::: "memory");
#endif
}

static void *dsa_host_job_loop(void *argument)
{
	struct dsa_host_job *job = argument;
	if (job->spin) {
		while (!__atomic_load_n(&job->stop, __ATOMIC_ACQUIRE)) {
			if (__atomic_load_n(&job->state, __ATOMIC_ACQUIRE) != 1) {
				dsa_host_relax();
				continue;
			}
			job->ret = job->run(job->context);
			__atomic_store_n(&job->state, 2, __ATOMIC_RELEASE);
		}
		return NULL;
	}

	pthread_mutex_lock(&job->lock);
	for (;;) {
		while (!job->stop && job->state != 1)
			pthread_cond_wait(&job->changed, &job->lock);
		if (job->stop)
			break;
		pthread_mutex_unlock(&job->lock);
		job->ret = job->run(job->context);
		pthread_mutex_lock(&job->lock);
		job->state = 2;
		pthread_cond_broadcast(&job->changed);
	}
	pthread_mutex_unlock(&job->lock);
	return NULL;
}

static int dsa_host_job_init(struct dsa_host_job *job, int (*run)(void *), void *context, int spin)
{
	int ret;

	job->run = run;
	job->context = context;
	job->spin = spin;
	ret = pthread_mutex_init(&job->lock, NULL);
	if (ret)
		return -ret;
	ret = pthread_cond_init(&job->changed, NULL);
	if (ret)
		goto mutex;
	ret = pthread_create(&job->thread, NULL, dsa_host_job_loop, job);
	if (ret)
		goto condition;
	job->started = 1;
	return 0;
condition:
	pthread_cond_destroy(&job->changed);
mutex:
	pthread_mutex_destroy(&job->lock);
	return -ret;
}

static int dsa_host_job_submit(struct dsa_host_job *job)
{
	int ret = 0;
	if (job->spin) {
		if (__atomic_load_n(&job->state, __ATOMIC_ACQUIRE) != 0)
			return -EBUSY;
		__atomic_store_n(&job->state, 1, __ATOMIC_RELEASE);
		return 0;
	}

	pthread_mutex_lock(&job->lock);
	if (job->state != 0 || job->stop)
		ret = -EBUSY;
	else {
		job->state = 1;
		pthread_cond_signal(&job->changed);
	}
	pthread_mutex_unlock(&job->lock);
	return ret;
}

static int dsa_host_job_wait(struct dsa_host_job *job)
{
	int ret;
	if (job->spin) {
		while (__atomic_load_n(&job->state, __ATOMIC_ACQUIRE) == 1)
			dsa_host_relax();
		return __atomic_load_n(&job->state, __ATOMIC_ACQUIRE) == 2 ? job->ret : -EINVAL;
	}

	pthread_mutex_lock(&job->lock);
	while (job->state == 1)
		pthread_cond_wait(&job->changed, &job->lock);
	ret = job->state == 2 ? job->ret : -EINVAL;
	pthread_mutex_unlock(&job->lock);
	return ret;
}

static void dsa_host_job_release(struct dsa_host_job *job)
{
	if (job->spin) {
		__atomic_store_n(&job->state, 0, __ATOMIC_RELEASE);
		return;
	}
	pthread_mutex_lock(&job->lock);
	job->state = 0;
	pthread_mutex_unlock(&job->lock);
}

static void dsa_host_job_fini(struct dsa_host_job *job)
{
	if (!job->started)
		return;
	if (job->spin) {
		__atomic_store_n(&job->stop, 1, __ATOMIC_RELEASE);
		pthread_join(job->thread, NULL);
		pthread_cond_destroy(&job->changed);
		pthread_mutex_destroy(&job->lock);
		job->started = 0;
		return;
	}
	pthread_mutex_lock(&job->lock);
	job->stop = 1;
	pthread_cond_broadcast(&job->changed);
	pthread_mutex_unlock(&job->lock);
	pthread_join(job->thread, NULL);
	pthread_cond_destroy(&job->changed);
	pthread_mutex_destroy(&job->lock);
	job->started = 0;
}

#endif
