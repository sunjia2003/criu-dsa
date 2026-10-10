# Host/parasite pipeline diagnostics

This diagnostic is enabled by `CRIU_DSA_SCAN_PROFILE=1` on the streaming DSA
capture path. CDP's `diagnostics=full` enables it; `off` and `profile` do not
enable the new consumer timestamps. Rebuild host and parasite together with
`make -j8 criu`. Diagnostic fields extend the shared stream header and slot
layout; these are internal, same-build interfaces, not an external ABI.

No copy-selection, queue-ordering, batch-size or completion-condition algorithm
is changed. Disabled diagnostics do not issue the new timing syscalls, but this
is not a claim of zero overhead: additional branches, structures and internal
layout changes still exist. Full results include timing and logging overhead
and must not be presented as a diagnostic-free performance measurement.

## Records and clock domains

- `DSA_PIPELINE_PROFILE` records one parasite consumer lifecycle and its
  cumulative counters per streaming RPC. `clock_valid=0` means the measurement
  must not be used. New parasite readings use `sys_clock_gettime` with
  `CLOCK_MONOTONIC`; values have nanosecond units, not nanosecond accuracy.
- `DSA_PIPELINE_HOST` records actual memory-phase boundaries. It reuses the
  existing MONOTONIC microsecond samples and converts their units to ns.
- `DSA_PIPELINE_FREEZE` records actual frozen-window phase boundaries on
  MONOTONIC without changing existing gettimeofday-based frozen-phase timers
  or native CRIU stats. The small differences between these boundaries are
  retained, not redistributed across phases.
- `DSA_PIPELINE_BATCH` records selected hardware submission groups. `id` is
  the consumer's submission-group id; `slot_seq` is the producer's shared-slot
  sequence. One producer slot can generate several hardware batches.

Host and target must share the same time namespace for cross-process MONOTONIC
alignment. Each timing interval is wall time and can include preemption and
instrumentation overhead; it is not thread CPU time. Errors and incomplete
captures must be excluded rather than repaired with invented timestamps.

## Consumer accounting

`consumer_end_ns - consumer_begin_ns` is the whole
`dsa_stream_consume_hw_runway` interval. The disjoint ledger satisfies:

```
control_ns + poll_scan_ns + accept_ns == consumer wall time
```

- `poll_scan_ns`: the scan over management slots, not-ready probes and harvest
  calls. It is not the hardware-copy duration.
- `accept_ns`: intake-loop work, including slot validation, metadata setup,
  descriptor preparation and submission.
- `control_ns`: other loop work, retirement, active-entry accounting,
  termination checks and producer-wait/relax work. It is not pure idle time.

The following are nested cumulative timers, reset for each streaming RPC:

- `prepare_ns`: sums hardware-descriptor preparation and queue selection in
  `dsa_raw_stream_batch_prepare`. It does not include all intake metadata work.
- `submit_call_ns`: sums calls to `dsa_submit_copy_desc`, including admission
  retries. It excludes subsequent device execution.
- `harvest_ns`: sums completed-batch handling calls, including fault recovery
  and resubmission when those occur. Thus recovery prepare/submit timers can
  also be nested inside harvest. Do not sum these timers into an additive pie.

`rpc_begin_ns` is sampled at the DSA setup boundary, after initial argument and
output-field handling. `ready_ns` is sampled just before consumer-ready
publication. `rpc_end_ns` is sampled before copying final RPC results; it does
not include all external RPC transport. These are deliberately not a complete
parasite-injection lifecycle.

Legacy `parasite_submit_us` / `parasite_poll_us` remain unchanged. Their clock
uses gettimeofday and microsecond endpoints. In the current runway, legacy
`poll_us` covers harvest handling, not all outer not-ready polling or waiting.
Short per-call intervals can quantize to zero. `DSA_SCAN_PROFILE` and
`DSA_MEMDUMP_DETAIL` repeat the same legacy ledger; never add both copies.

## Batch observations and sampling

Every accepted group receives an id. Its record stores:

1. `publish_ns`: a Host sample immediately before shared-slot READY publication;
2. `accept_ns`: the intake call entry for the slot;
3. `prepare_begin_ns` / `prepare_end_ns`: the first hardware preparation;
4. `submit_begin_ns` / `submit_end_ns`: the first submission call;
5. `completion_observed_ns`: a sample after the completion-ready check succeeds,
   immediately before final harvest handling.

If a group faults and is resubmitted, its record spans the first submission to
the final successful completion observation; it does not pretend the hardware
ran continuously throughout that interval. The span includes admission,
queueing and polling/detection delay and is not a device execution timestamp.

The first 8 groups are retained, together with a ring of the last 128 completed
events. The emitter excludes duplicates between head and tail. The middle is
not retained. `submitted_groups` and `completed_events` are whole-RPC counts,
not the number of stored records; successful captures should have equal counts.
An observed overlap between selected in-flight intervals is meaningful, but
this sampled trace cannot establish whole-run hardware utilization or a
complete overlap ratio. Plot missing sections as unobserved, not interpolated.

Memory-phase logging is bounded to 32 transitions and frozen-phase logging to
64. Consumers of these diagnostic records must validate lifecycle/phase
enclosure, phase continuity, native CSV agreement, monotonic batch ordering and
ledger closure. The four single-process workloads satisfy these limits; this
is not an exhaustive arbitrary-process-tree tracer.

## What runs concurrently

The Host starts an RPC helper thread and waits for `consumer_ready` before
entering its producer scan. The helper waits for the remote RPC; it is not the
hardware-copy worker. The target's parasite executes the consumer. Producer
scanning/publication, parasite consumption and asynchronous DSA operations can
overlap. Within the parasite, intake, preparation, submission, polling and
harvest still run serially in one consumer loop.

The producer releases a final `finish` token, and the consumer verifies all
accepted descriptors and payload bytes before returning. Host join is therefore
a drain/cleanup/RPC boundary, not a pure hardware-copy timer. Fine-grained
post-thaw comparison/output is a separate pipeline and can overlap resumed
application execution; it is outside the measured frozen capture window.

Lifecycle overlap does not prove simultaneous instruction execution on separate
CPU cores, device busy time or speedup over a serial implementation. Those
claims require scheduling/CPU measurements, hardware observations or a proper
serial comparison, respectively.

## Validation and measurement limits

Rebuild Host and parasite from the same sources and record the executable hash.
Use real captures to check log versions, source PID, phase continuity, lifecycle
enclosure, timestamp order, submitted/completed counts and native stats/CSV
boundary agreement. Preserve small differences between independently placed
boundaries instead of distributing them over phases. Check each original log's
hash when regenerating a report. Parser tests should also reject deliberately
missing, duplicate, out-of-order and nonclosing records; synthetic fixtures are
software tests, not benchmark measurements.

Disjoint ledger closure is a mathematical integrity check on adjacent samples,
not independent proof of timer accuracy. Similarly, native-stats agreement does
not establish observer-free performance. A timer microbenchmark can calibrate
libc and the actual Compel syscall wrapper separately and can bracket
cross-process timestamps, but idle calibration cannot be subtracted from the
checkpoint run as an exact overhead correction.

Host scan switches can occur millions of times per capture. The consumer also
issues several timing syscalls per loop, changing polling/detection cadence.
Both affect the measured execution. Use independent, balanced, matched-state
instrumentation-on/off comparisons before making uninstrumented performance
claims. Continuous checkpoints from one run are not independent run repeats.
No thread-CPU or scheduling ledger is recorded by these probes.

Small producer slot waits, short end-of-scan drain and short join support a
producer-limited interpretation for that instrumented workload. They do not
rule out consumer CPU cost, shared-memory contention or a bottleneck shift
after producer optimization. Sampled publication-to-accept latencies cannot
prove that the unrecorded middle never queued. CPU-cost optimization and
frozen-time critical-path optimization should be reported separately.
