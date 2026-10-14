#!/usr/bin/env python3
"""Compile the production accounting helpers against a deterministic clock.

Synthetic times are test fixtures, never checkpoint measurements. Real DSA
captures separately validate emitted records and completed descriptor ledgers.
"""
import pathlib
import importlib.util
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]


class ExclusiveAccountingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        header = (ROOT / 'criu/include/parasite.h').read_text()
        source = (ROOT / 'criu/pie/parasite.c').read_text()
        declarations = header[header.index('#define DSA_PIPELINE_HEAD_COUNT'):header.index('struct parasite_dsa_stream_hdr {')]
        helpers = source[source.index('static u64 dsa_pipeline_mono_ns(void)'):source.index('static void dsa_pipeline_record_batch(')]
        if 'DSA_PIPELINE_PREPARE' not in declarations or 'dsa_pipeline_enter(' not in helpers:
            raise AssertionError('Production code does not expose exclusive phases')
        fixture = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
typedef uint32_t u32;
typedef uint64_t u64;
static u64 fake_ns;
static int calls, clock_failed;
static long sys_clock_gettime(int id, struct timespec *ts) {
    assert(id == CLOCK_MONOTONIC);
    calls++;
    if (clock_failed) return -1;
    ts->tv_sec = fake_ns / 1000000000ULL;
    ts->tv_nsec = fake_ns % 1000000000ULL;
    return 0;
}
__DECLARATIONS__
#include "dsa-clock.h"
static struct dsa_trace_clock dsa_trace_clock;
static struct parasite_dsa_pipeline *dsa_pipeline;
static struct dsa_pipeline_event *dsa_pipeline_events;
__HELPERS__
int main(int argc, char **argv) {
    struct parasite_dsa_pipeline p = {0};
    struct dsa_pipeline_event events[32] = {0};
    assert(argc == 2);
    if (!strcmp(argv[1], "disabled")) {
        assert(dsa_pipeline_enter(DSA_PIPELINE_PREPARE).phase == DSA_PIPELINE_CONTROL);
        dsa_pipeline_switch(DSA_PIPELINE_CONTROL);
        assert(calls == 0);
        return 0;
    }
    dsa_pipeline = &p;
    fake_ns = 100;
    p.clock_valid = 1;
    p.last_ns = p.consumer_begin_ns = fake_ns;
    p.occurrence = p.next_occurrence = 1;
    p.phase_calls[DSA_PIPELINE_CONTROL] = 1;
    if (!strcmp(argv[1], "invalid")) {
        clock_failed = 1;
        dsa_pipeline_switch(DSA_PIPELINE_ACCEPT);
        assert(p.clock_valid == 0);
        return 0;
    }
    if (!strcmp(argv[1], "backwards")) {
        fake_ns = 50;
        dsa_pipeline_switch(DSA_PIPELINE_ACCEPT);
        assert(p.clock_valid == 0);
        return 0;
    }
    if (!strcmp(argv[1], "coalesce")) {
        dsa_pipeline_events = events;
        p.trace_capacity = 1;
        fake_ns += 10; dsa_pipeline_switch(DSA_PIPELINE_CONTROL);
        fake_ns += 10; dsa_pipeline_switch(DSA_PIPELINE_CONTROL);
        assert(p.trace_count == 1 && p.trace_dropped == 0);
        assert(events[0].start_ns == 100 && events[0].end_ns == 120);
        assert(p.phase_calls[DSA_PIPELINE_CONTROL] == 1);
        assert(p.phase_segments[DSA_PIPELINE_CONTROL] == 1);
        return 0;
    }
    if (!strcmp(argv[1], "zero")) {
        dsa_pipeline_events = events;
        p.trace_capacity = 32;
        dsa_pipeline_enter(DSA_PIPELINE_PREPARE);
        dsa_pipeline_switch(DSA_PIPELINE_CONTROL);
        assert(p.trace_count == 2);
        assert(events[1].start_ns == events[1].end_ns);
        assert(events[1].phase == DSA_PIPELINE_PREPARE);
        return 0;
    }
    if (!strcmp(argv[1], "trace") || !strcmp(argv[1], "overflow") || !strcmp(argv[1], "export")) {
        dsa_pipeline_events = events;
        p.trace_capacity = !strcmp(argv[1], "overflow") ? 2 : 32;
    } else {
        assert(!strcmp(argv[1], "exclusive"));
    }
    struct dsa_pipeline_scope accept, prepare, submit, harvest;
    fake_ns += 10; accept = dsa_pipeline_enter(DSA_PIPELINE_ACCEPT);
    fake_ns += 20; prepare = dsa_pipeline_enter(DSA_PIPELINE_PREPARE);
    fake_ns += 30; dsa_pipeline_resume(prepare);
    fake_ns += 40; submit = dsa_pipeline_enter(DSA_PIPELINE_SUBMIT);
    fake_ns += 50; dsa_pipeline_resume(submit);
    fake_ns += 60; dsa_pipeline_resume(accept);
    fake_ns += 70; dsa_pipeline_switch(DSA_PIPELINE_CONTROL);
    fake_ns += 80; harvest = dsa_pipeline_enter(DSA_PIPELINE_HARVEST);
    /* Real fault-recovery call shape: harvest -> prepare/submit -> harvest. */
    fake_ns += 90; prepare = dsa_pipeline_enter(DSA_PIPELINE_PREPARE);
    fake_ns += 100; dsa_pipeline_resume(prepare);
    fake_ns += 110; submit = dsa_pipeline_enter(DSA_PIPELINE_SUBMIT);
    fake_ns += 120; dsa_pipeline_resume(submit);
    fake_ns += 130; dsa_pipeline_resume(harvest);
    fake_ns += 140; dsa_pipeline_switch(DSA_PIPELINE_CONTROL);
    fake_ns += 150; dsa_pipeline_switch(DSA_PIPELINE_CONTROL);
    assert(p.phase_ns[DSA_PIPELINE_CONTROL] == 450);
    assert(p.phase_ns[DSA_PIPELINE_POLL_SCAN] == 0);
    assert(p.phase_ns[DSA_PIPELINE_ACCEPT] == 120);
    assert(p.phase_ns[DSA_PIPELINE_PREPARE] == 130);
    assert(p.phase_ns[DSA_PIPELINE_SUBMIT] == 170);
    assert(p.phase_ns[DSA_PIPELINE_HARVEST] == 330);
    u64 sum = 0;
    for (u32 i = 0; i < DSA_PIPELINE_PHASE_NR; ++i) sum += p.phase_ns[i];
    assert(sum == fake_ns - p.consumer_begin_ns);
    assert(p.clock_valid == 1);
    assert(p.phase_calls[DSA_PIPELINE_PREPARE] == 2);
    assert(p.phase_calls[DSA_PIPELINE_ACCEPT] == 1);
    if (dsa_pipeline_events) {
        assert(p.phase_segments[DSA_PIPELINE_ACCEPT] == 3);
        assert(p.trace_segments == 13);
        assert(p.trace_count + p.trace_dropped == p.trace_segments);
        if (!strcmp(argv[1], "overflow")) {
            assert(p.trace_count == 2 && p.trace_dropped == 11);
            assert(events[1].end_ns == 130); /* Never extend across dropped work. */
        } else {
            assert(events[0].start_ns == 100);
            assert(events[p.trace_count-1].end_ns == fake_ns);
            u64 totals[DSA_PIPELINE_PHASE_NR] = {0};
            u64 last = p.consumer_begin_ns;
            for (u32 i = 0; i < p.trace_count; i++) {
                assert(events[i].start_ns == last);
                last = events[i].end_ns;
                totals[events[i].phase] += events[i].end_ns - events[i].start_ns;
            }
            for (u32 i = 0; i < DSA_PIPELINE_PHASE_NR; i++)
                assert(totals[i] == p.phase_ns[i]);
            assert(events[1].occurrence == events[3].occurrence);
            assert(events[3].flags == DSA_PIPELINE_EVENT_RESUMED);
            if (!strcmp(argv[1], "export")) {
                struct dsa_pipeline_trace_file h = {
                    .magic = DSA_PIPELINE_TRACE_MAGIC, .version = DSA_PIPELINE_TRACE_VERSION,
                    .header_size = sizeof(h), .event_size = sizeof(events[0]),
                    .consumer_begin_ns = p.consumer_begin_ns, .consumer_end_ns = fake_ns,
                    .event_count = p.trace_count, .pid = 42, .clock_valid = p.clock_valid,
                    .capacity = p.trace_capacity, .flags = DSA_PIPELINE_TRACE_COMPLETE,
                };
                memcpy(h.phase_ns, p.phase_ns, sizeof(h.phase_ns));
                memcpy(h.phase_calls, p.phase_calls, sizeof(h.phase_calls));
                memcpy(h.phase_segments, p.phase_segments, sizeof(h.phase_segments));
                FILE *file = fopen("trace.bin", "wb");
                assert(file);
                assert(fwrite(&h, sizeof(h), 1, file) == 1);
                assert(fwrite(events, sizeof(events[0]), p.trace_count, file) == p.trace_count);
                assert(fclose(file) == 0);
            }
        }
    }
    return 0;
}
'''
        fixture = fixture.replace('__DECLARATIONS__', declarations).replace('__HELPERS__', helpers)
        cls.temporary = tempfile.TemporaryDirectory(prefix='dsa-exclusive-accounting-')
        cls.addClassCleanup(cls.temporary.cleanup)
        directory = pathlib.Path(cls.temporary.name)
        c_file, cls.binary = directory / 'accounting.c', directory / 'accounting'
        c_file.write_text(fixture)
        subprocess.run(['cc', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
                        '-iquote'+str(ROOT/'criu/include'), str(c_file), '-o', str(cls.binary)], check=True)

    def test_fault_recovery_is_exclusive_and_closes(self):
        subprocess.run([str(self.binary), 'exclusive'], check=True)

    def test_disabled_diagnostics_issue_no_new_clock_calls(self):
        subprocess.run([str(self.binary), 'disabled'], check=True)

    def test_clock_failure_invalidates_measurement(self):
        subprocess.run([str(self.binary), 'invalid'], check=True)

    def test_backwards_clock_invalidates_measurement(self):
        subprocess.run([str(self.binary), 'backwards'], check=True)

    def test_full_trace_is_contiguous_and_matches_exclusive_counters(self):
        subprocess.run([str(self.binary), 'trace'], check=True)

    def test_overflow_is_explicit_and_preserves_only_a_prefix(self):
        subprocess.run([str(self.binary), 'overflow'], check=True)

    def test_adjacent_same_invocation_is_not_counted_twice(self):
        subprocess.run([str(self.binary), 'coalesce'], check=True)

    def test_zero_duration_call_is_retained_as_an_event(self):
        subprocess.run([str(self.binary), 'zero'], check=True)

    def test_python_reader_accepts_production_c_layout_and_counters(self):
        spec = importlib.util.spec_from_file_location('trace_reader', ROOT/'scripts/dsa_pipeline_trace.py')
        reader = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(reader)
        subprocess.run([str(self.binary), 'export'], cwd=self.temporary.name, check=True)
        result = reader.validate(pathlib.Path(self.temporary.name)/'trace.bin')
        self.assertEqual(result['records'], 13)
        self.assertEqual(result['phases']['accept_batch'], dict(exclusive_ns=120, calls=1, fragments=3))


if __name__ == '__main__':
    unittest.main()
