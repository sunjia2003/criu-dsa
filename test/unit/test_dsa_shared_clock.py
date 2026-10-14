"""Production phase/flow helpers with a deterministic clock, not timing data."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class SharedBoundaryClockTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        header = (ROOT/'criu/include/parasite.h').read_text()
        source = (ROOT/'criu/pie/parasite.c').read_text()
        declarations = header[header.index('#define DSA_PIPELINE_HEAD_COUNT'):
                              header.index('struct parasite_dsa_stream_hdr {')]
        ledger = source[source.index('static u64 dsa_pipeline_mono_ns(void)'):
                        source.index('static void dsa_pipeline_record_batch(')]
        flow = source[source.index('static u64 dsa_flow_now_ns(void)'):
                      source.index('static void dsa_flow_snapshot(')]
        fixture = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
typedef uint32_t u32;
typedef uint64_t u64;
#include "dsa-flow.h"
static u64 fake_ns = 100;
static unsigned calls;
static int clock_failed;
static long sys_clock_gettime(int id, struct timespec *ts) {
  assert(id == CLOCK_MONOTONIC);
  calls++;
  if (clock_failed) return -1;
  fake_ns += 10;
  ts->tv_sec = fake_ns / 1000000000ULL;
  ts->tv_nsec = fake_ns % 1000000000ULL;
  return 0;
}
__DECLARATIONS__
static struct parasite_dsa_pipeline *dsa_pipeline;
static struct dsa_pipeline_event *dsa_pipeline_events;
static struct dsa_flow_buffer dsa_consumer_flow;
__LEDGER__
__FLOW__
int main(int argc, char **argv) {
  assert(argc == 2);
  struct parasite_dsa_pipeline p = {0};
  struct dsa_pipeline_event events[32] = {0};
  union { struct dsa_flow_header align; unsigned char bytes[4096]; } memory = {0};
  bool ledger = strcmp(argv[1], "disabled") && strcmp(argv[1], "flow_only");
  bool flow = strcmp(argv[1], "disabled") && strcmp(argv[1], "ledger_only");
  if (ledger) {
    dsa_pipeline = &p;
    dsa_pipeline_events = events;
    p.clock_valid = 1;
    p.last_ns = p.consumer_begin_ns = 100;
    p.occurrence = p.next_occurrence = 1;
    p.phase_calls[DSA_PIPELINE_CONTROL] = 1;
    p.trace_capacity = 32;
  }
  if (flow) {
    dsa_flow_bind(&dsa_consumer_flow, memory.bytes, sizeof(memory.bytes));
    dsa_consumer_flow.header->clock_valid = 1;
  }
  if (!strcmp(argv[1], "invalid")) clock_failed = 1;
  if (!strcmp(argv[1], "backwards")) {
    fake_ns = 10;
    dsa_consumer_flow.header->end_ns = 100;
  }
  if (!strcmp(argv[1], "overflow")) dsa_consumer_flow.capacity = 1;
  struct dsa_pipeline_scope parent = dsa_pipeline_enter(DSA_PIPELINE_PREPARE);
  dsa_flow_cons_phase_event(DSA_FLOW_PREPARE_BEGIN, 7, 8, 9, 10, 11, 12, 13);
  fake_ns += 20;
  dsa_pipeline_resume(parent);
  dsa_flow_cons_phase_event(DSA_FLOW_PREPARE_END, 7, 8, 9, 10, 11, 12, 13);
  parent = dsa_pipeline_enter(DSA_PIPELINE_SUBMIT);
  dsa_flow_cons_phase_event(DSA_FLOW_SUBMIT_BEGIN, 7, 8, 9, 10, 11, 12, 13);
  fake_ns += 20;
  dsa_pipeline_resume(parent);
  dsa_flow_cons_phase_event(DSA_FLOW_SUBMIT_END, 7, 8, 9, 10, 11, 12, 13);
  assert(calls == (ledger || flow ? 4U : 0U));
  if (!strcmp(argv[1], "invalid") || !strcmp(argv[1], "backwards")) {
    assert(!p.clock_valid && !dsa_consumer_flow.header->clock_valid);
    assert(dsa_consumer_flow.header->event_count == 0);
    return 0;
  }
  if (!strcmp(argv[1], "overflow")) {
    assert(dsa_consumer_flow.header->event_count == 1);
    assert(dsa_consumer_flow.header->dropped == 3);
    return 0;
  }
  if (flow) {
    assert(dsa_consumer_flow.header->event_count == 4);
    assert(dsa_consumer_flow.events[0].kind == DSA_FLOW_PREPARE_BEGIN);
    assert(dsa_consumer_flow.events[3].kind == DSA_FLOW_SUBMIT_END);
    assert(dsa_consumer_flow.events[0].seq == 7 && dsa_consumer_flow.events[0].id == 8);
    assert(dsa_consumer_flow.events[0].e == 13);
    for (unsigned i=1; i<4; i++)
      assert(dsa_consumer_flow.events[i-1].ns <= dsa_consumer_flow.events[i].ns);
    if (ledger) {
      assert(dsa_consumer_flow.events[0].ns == events[1].start_ns);
      assert(dsa_consumer_flow.events[1].ns == events[1].end_ns);
      assert(dsa_consumer_flow.events[2].ns == events[3].start_ns);
      assert(dsa_consumer_flow.events[3].ns == events[3].end_ns);
    }
    /* Ordinary observations must still sample their actual later location. */
    dsa_flow_cons_event(DSA_FLOW_SNAPSHOT, 7, 8, 0, 0, 0, 0, 0);
    assert(calls == 5 && dsa_consumer_flow.events[4].ns > dsa_consumer_flow.events[3].ns);
  }
  if (ledger) {
    dsa_pipeline_switch(DSA_PIPELINE_CONTROL);
    u64 sum=0;
    for (unsigned i=0; i<DSA_PIPELINE_PHASE_NR; i++) sum += p.phase_ns[i];
    assert(sum == p.last_ns-p.consumer_begin_ns);
    assert(p.phase_ns[DSA_PIPELINE_PREPARE] == 30 && p.phase_ns[DSA_PIPELINE_SUBMIT] == 30);
  }
  return 0;
}
'''
        fixture = fixture.replace('__DECLARATIONS__', declarations).replace('__LEDGER__', ledger).replace('__FLOW__', flow)
        cls.temporary = tempfile.TemporaryDirectory(prefix='dsa-shared-clock-')
        cls.addClassCleanup(cls.temporary.cleanup)
        source_file = Path(cls.temporary.name)/'clock.c'
        cls.binary = Path(cls.temporary.name)/'clock'
        source_file.write_text(fixture)
        subprocess.run(['cc', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
                        '-iquote'+str(ROOT/'criu/include'), str(source_file), '-o', str(cls.binary)], check=True)

    def test_four_boundaries_read_four_clocks_not_eight(self):
        subprocess.run([str(self.binary), 'both'], check=True)

    def test_disabled_boundaries_issue_no_clock_calls(self):
        subprocess.run([str(self.binary), 'disabled'], check=True)

    def test_flow_only_samples_without_a_ledger(self):
        subprocess.run([str(self.binary), 'flow_only'], check=True)

    def test_ledger_only_does_not_read_clocks_for_absent_flow(self):
        subprocess.run([str(self.binary), 'ledger_only'], check=True)

    def test_failed_clock_invalidates_both_records(self):
        subprocess.run([str(self.binary), 'invalid'], check=True)

    def test_backwards_clock_is_not_hidden_by_reuse(self):
        subprocess.run([str(self.binary), 'backwards'], check=True)

    def test_overflow_remains_explicit(self):
        subprocess.run([str(self.binary), 'overflow'], check=True)

    def test_only_prepare_and_submit_share_phase_samples(self):
        source = (ROOT/'criu/pie/parasite.c').read_text()
        for kind in ('PREPARE_BEGIN', 'PREPARE_END', 'SUBMIT_BEGIN', 'SUBMIT_END'):
            self.assertIn('dsa_flow_cons_phase_event(DSA_FLOW_'+kind, source)
            self.assertNotIn('dsa_flow_cons_event(DSA_FLOW_'+kind, source)
        self.assertEqual(source.count('dsa_flow_cons_phase_event('), 5)
        for kind in ('COMPLETE_OBSERVED', 'RECYCLE', 'H_CREATE'):
            self.assertIn('dsa_flow_cons_event(DSA_FLOW_'+kind, source)


if __name__ == '__main__':
    unittest.main()
