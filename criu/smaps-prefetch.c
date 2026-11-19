#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "log.h"
#include "page.h"
#include "pstree.h"
#include "smaps-prefetch.h"
#include "util.h"

struct smaps_input {
	pid_t pid;
	int fd;
	char *text;
	size_t length;
	int error;
	uint64_t begin_ns, end_ns;
};

static struct {
	struct smaps_input *inputs;
	size_t count;
	pthread_t thread;
	bool running, trace;
	uint64_t network_begin_ns, network_end_ns;
} prefetch;

static uint64_t prefetch_now(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts))
		return 0;
	return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static bool env_is_one(const char *name)
{
	const char *value = getenv(name);

	return value && !strcmp(value, "1");
}

/* No CRIU buffered I/O, namespace helpers, callbacks or logging in this thread. */
static void *prefetch_read(void *unused)
{
	size_t i;

	(void)unused;
	for (i = 0; i < prefetch.count; i++) {
		struct smaps_input *input = &prefetch.inputs[i];
		size_t capacity = 64 * 1024;

		if (prefetch.trace)
			input->begin_ns = prefetch_now();
		input->text = malloc(capacity);
		if (!input->text) {
			input->error = ENOMEM;
			continue;
		}
		for (;;) {
			ssize_t bytes;
			size_t available;

			if (capacity - input->length < PAGE_SIZE + 1) {
				char *larger;

				if (capacity > SIZE_MAX / 2) {
					input->error = EOVERFLOW;
					break;
				}
				larger = realloc(input->text, capacity * 2);
				if (!larger) {
					input->error = ENOMEM;
					break;
				}
				input->text = larger;
				capacity *= 2;
			}
			available = PAGE_SIZE;
			bytes = read(input->fd, input->text + input->length, available);
			if (bytes < 0) {
				if (errno == EINTR)
					continue;
				input->error = errno;
				break;
			}
			if (!bytes)
				break;
			input->length += bytes;
		}
		input->text[input->length] = '\0';
		if (prefetch.trace)
			input->end_ns = prefetch_now();
	}
	return NULL;
}

static int prefetch_join(void)
{
	size_t i;
	int error;

	if (!prefetch.running)
		return 0;
	error = pthread_join(prefetch.thread, NULL);
	if (error) {
		pr_err("Can't join smaps reader: %s\n", strerror(error));
		return -1;
	}
	prefetch.running = false;
	for (i = 0; i < prefetch.count; i++) {
		close(prefetch.inputs[i].fd);
		prefetch.inputs[i].fd = -1;
	}
	return 0;
}

int smaps_prefetch_cleanup(void)
{
	size_t i;

	/* Never free an input or release its fd while the reader can access it. */
	if (prefetch_join())
		return -1;
	for (i = 0; i < prefetch.count; i++) {
		if (prefetch.inputs[i].fd >= 0)
			close(prefetch.inputs[i].fd);
		free(prefetch.inputs[i].text);
	}
	free(prefetch.inputs);
	memset(&prefetch, 0, sizeof(prefetch));
	return 0;
}

int smaps_prefetch_start(void)
{
	struct pstree_item *item;
	const char *enabled = getenv("CRIU_DSA_SMAPS_PREFETCH");
	const char *dsa = getenv("CRIU_DSA_DUMP");
	sigset_t blocked, previous;
	size_t index = 0;
	int error, restore_error;

	if (!enabled || !strcmp(enabled, "0") || !dsa || atoi(dsa) <= 0)
		return 0;
	if (strcmp(enabled, "1")) {
		pr_err("CRIU_DSA_SMAPS_PREFETCH must be 0 or 1\n");
		return -1;
	}
	if (prefetch.inputs) {
		pr_err("smaps prefetch already started\n");
		return -1;
	}
	for_each_pstree_item(item) {
		if (item->pid->state != TASK_DEAD)
			prefetch.count++;
	}
	if (!prefetch.count)
		return 0;
	prefetch.inputs = calloc(prefetch.count, sizeof(*prefetch.inputs));
	if (!prefetch.inputs) {
		prefetch.count = 0;
		return -1;
	}
	for (index = 0; index < prefetch.count; index++)
		prefetch.inputs[index].fd = -1;
	index = 0;
	for_each_pstree_item(item) {
		struct smaps_input *input;

		if (item->pid->state == TASK_DEAD)
			continue;
		input = &prefetch.inputs[index++];
		input->pid = item->pid->real;
		input->fd = open_proc(input->pid, "smaps");
		if (input->fd < 0)
			goto fail;
	}
	prefetch.trace = env_is_one("CRIU_DSA_SMAPS_PREFETCH_TRACE") && env_is_one("CRIU_DSA_PROFILE");
	/* Keep process-directed dump signals on the original control thread. */
	sigfillset(&blocked);
	error = pthread_sigmask(SIG_BLOCK, &blocked, &previous);
	if (error) {
		pr_err("Can't mask signals for smaps reader: %s\n", strerror(error));
		goto fail;
	}
	error = pthread_create(&prefetch.thread, NULL, prefetch_read, NULL);
	if (!error)
		prefetch.running = true;
	restore_error = pthread_sigmask(SIG_SETMASK, &previous, NULL);
	if (error || restore_error) {
		pr_err("Can't initialize smaps reader: %s\n", strerror(error ? error : restore_error));
		goto fail;
	}
	if (prefetch.trace)
		prefetch.network_begin_ns = prefetch_now();
	return 0;
fail:
	smaps_prefetch_cleanup();
	return -1;
}

void smaps_prefetch_network_done(void)
{
	if (prefetch.trace)
		prefetch.network_end_ns = prefetch_now();
}

int smaps_prefetch_take(pid_t pid, char **text, size_t *length)
{
	size_t i;
	uint64_t wait_begin = 0, wait_end = 0;

	*text = NULL;
	*length = 0;
	if (!prefetch.inputs)
		return 0;
	if (prefetch.trace)
		wait_begin = prefetch_now();
	/* Complete every input before the first injection into any shared mm. */
	if (prefetch_join())
		return -1;
	if (prefetch.trace)
		wait_end = prefetch_now();
	for (i = 0; i < prefetch.count; i++) {
		struct smaps_input *input = &prefetch.inputs[i];

		if (input->pid != pid)
			continue;
		if (input->error) {
			errno = input->error;
			pr_perror("Can't prefetch smaps for %d", pid);
			return -1;
		}
		if (!input->text) {
			pr_err("smaps input for %d was already consumed\n", pid);
			return -1;
		}
		*text = input->text;
		*length = input->length;
		input->text = NULL;
		pr_info("SMAPS_PREFETCH: pid=%d bytes=%zu source=cache\n", pid, *length);
		if (prefetch.trace)
			pr_info("SMAPS_PREFETCH_TRACE: pid=%d read_begin_ns=%llu read_end_ns=%llu "
				"network_begin_ns=%llu network_end_ns=%llu wait_begin_ns=%llu wait_end_ns=%llu\n",
				pid, (unsigned long long)input->begin_ns, (unsigned long long)input->end_ns,
				(unsigned long long)prefetch.network_begin_ns,
				(unsigned long long)prefetch.network_end_ns,
				(unsigned long long)wait_begin, (unsigned long long)wait_end);
		return 1;
	}
	return 0;
}
