#ifndef __CR_DSA_HOST_PERF_H__
#define __CR_DSA_HOST_PERF_H__

#include <linux/perf_event.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <unistd.h>

struct dsa_host_perf_sample {
	uint64_t cycles, instructions, enabled_ns, running_ns;
};

/* Diagnostic-only per-thread group. CLOEXEC descriptors are reclaimed when
 * this short-lived CRIU process exits; no target-process FD is introduced. */
static int dsa_host_perf_read(struct dsa_host_perf_sample *sample)
{
	static __thread int leader = -1;
	struct perf_event_attr attr = {
		.type = PERF_TYPE_HARDWARE,
		.size = sizeof(attr),
		.config = PERF_COUNT_HW_CPU_CYCLES,
		.exclude_hv = 1,
		.read_format = PERF_FORMAT_GROUP | PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING,
	};
	uint64_t values[5];
	int member;

	if (leader < 0) {
		leader = syscall(__NR_perf_event_open, &attr, 0, -1, -1, PERF_FLAG_FD_CLOEXEC);
		if (leader < 0)
			return -1;
		attr.config = PERF_COUNT_HW_INSTRUCTIONS;
		member = syscall(__NR_perf_event_open, &attr, 0, -1, leader, PERF_FLAG_FD_CLOEXEC);
		if (member < 0) {
			close(leader);
			leader = -1;
			return -1;
		}
		/* Keep both members open for the thread's diagnostic scopes. */
	}
	if (read(leader, values, sizeof(values)) != (ssize_t)sizeof(values) || values[0] != 2)
		return -1;
	sample->enabled_ns = values[1];
	sample->running_ns = values[2];
	sample->cycles = values[3];
	sample->instructions = values[4];
	return 0;
}

#endif
