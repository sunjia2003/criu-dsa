"""Production-header checks and synthetic chronology contracts, not performance data."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('flow_reader', ROOT/'scripts/dsa_pipeline_flow.py')
reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reader)


def event(kind, ns, seq=0, identifier=reader.NO_ID, a=0, b=0, c=0, d=0, e=0, flags=0):
    return dict(kind=kind, ns=ns, seq=seq, id=identifier, a=a, b=b, c=c, d=d, e=e, flags=flags)


class FlowTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='dsa-flow-test-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.host = [event('begin', 1), event('first_task', 10),
                     event('publish_pre', 20, a=2, b=8192, c=4096),
                     event('publish_post', 24, a=2, b=8192, c=4096),
                     event('finish_pre', 25, seq=1, a=8192, b=2),
                     event('finish_post', 26, seq=1, a=8192, b=2), event('end', 60)]
        self.parasite = [event('begin', 2), event('loop_begin', 5),
                        event('snapshot', 6),
                        event('accept', 23, a=21, b=2, c=8192, d=1),
                        event('h_create', 24, identifier=0, a=2, b=8192),
                        event('prepare_begin', 27, identifier=0, a=2, b=8192),
                        event('prepare_end', 28, identifier=0, a=2, b=8192),
                        event('submit_begin', 29, identifier=0, a=2, b=8192),
                        event('submit_end', 30, identifier=0, a=2, b=8192),
                        event('snapshot', 31, a=1, b=1, d=1, flags=1),
                        event('complete_observed', 41, identifier=0, a=40, b=2, c=8192),
                        event('recycle', 42, a=2, b=8192),
                        event('snapshot', 43, a=1, b=1, c=1, flags=1),
                        event('loop_end', 44, seq=1, a=2, b=8192),
                        event('cleanup_begin', 45)]

    def write(self, role, events):
        path = self.root / f'{role}.bin'
        header = reader.HEADER.pack(reader.MAGIC, 1, reader.HEADER.size, reader.EVENT.size,
                                    events[0]['ns'], 60, len(events), 0, 42, role, 1, 1)
        path.write_bytes(header+b''.join(reader.EVENT.pack(
            row['ns'], row['a'], row['b'], row['c'], row['d'], row['e'],
            reader.KINDS.index(row['kind'])+1, row['seq'], row['id'], row['flags']) for row in events))
        return path

    def result(self):
        return reader.correlate(reader.load(self.write(1, self.host)),
                                reader.load(self.write(2, self.parasite)))

    def test_concurrent_release_acquire_brackets_overlap_legitimately(self):
        result = self.result()
        self.assertEqual(result['slots'][0]['handoff_lower_ns'], 0)
        self.assertEqual(result['slots'][0]['handoff_upper_ns'], 3)
        self.assertEqual(result['groups'][0]['observed_ready_ns'], 40)
        self.assertEqual(result['groups'][0]['harvest_end_ns'], 41)
        self.assertEqual(result['empty_input_observation_intervals'], [])

    def test_observed_wait_is_not_inferred_from_held_queue_snapshot(self):
        self.parasite[3:3] = [event('empty_input_begin', 7), event('empty_input_end', 22, a=1)]
        self.assertEqual(self.result()['empty_input_observation_intervals'], [(7, 22)])

    def test_missing_middle_request_is_rejected(self):
        self.parasite = [row for row in self.parasite if row['kind'] != 'submit_end']
        with self.assertRaisesRegex(ValueError, 'Incomplete'):
            self.result()

    def test_payload_mismatch_is_rejected(self):
        self.parasite[3]['c'] += 4096
        with self.assertRaisesRegex(ValueError, 'payload'):
            self.result()

    def test_fault_resubmission_keeps_one_logical_request(self):
        retry = [event('prepare_begin', 32, identifier=0, a=1, b=4096),
                 event('prepare_end', 33, identifier=0, a=1, b=4096),
                 event('submit_begin', 34, identifier=0, a=1, b=4096),
                 event('submit_end', 35, identifier=0, a=1, b=4096)]
        self.parasite[10:10] = retry
        result = self.result()
        self.assertEqual(result['hardware_groups'], 1)
        self.assertEqual(result['submit_attempts'], 2)
        self.assertEqual(result['total_descriptors'], 2)

    def test_invalid_queue_state_is_rejected(self):
        self.parasite[9]['c'] = 2
        with self.assertRaisesRegex(ValueError, 'queue'):
            self.result()

    def test_invalid_clock_dropped_or_partial_file_is_rejected(self):
        path = self.write(1, self.host)
        raw = path.read_bytes()
        fields = list(reader.HEADER.unpack(raw[:reader.HEADER.size]))
        for field, value in ((7, 1), (10, 0), (11, 0), (3, 32)):
            original = fields[field]
            fields[field] = value
            path.write_bytes(reader.HEADER.pack(*fields)+raw[reader.HEADER.size:])
            with self.assertRaises(ValueError):
                reader.load(path)
            fields[field] = original
        path.write_bytes(raw[:-1])
        with self.assertRaises(ValueError):
            reader.load(path)

    def test_complete_observation_before_last_submit_is_rejected(self):
        self.parasite[10]['a'] = 29
        with self.assertRaisesRegex(ValueError, 'READY'):
            self.result()

    def test_duplicate_software_slot_is_rejected(self):
        self.host.insert(3, self.host[2].copy())
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            self.result()

    def test_production_header_disabled_overflow_clock_and_layout(self):
        source = self.root/'header.c'
        source.write_text(r'''
#include <stdint.h>
#include <assert.h>
typedef uint32_t u32;
typedef uint64_t u64;
#include "dsa-flow.h"
int main(void) {
  unsigned char memory[128] = {0};
  struct dsa_flow_buffer b = {0};
  dsa_flow_push(&b, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0);
  dsa_flow_bind(&b, memory, sizeof(memory));
  assert(b.capacity == 1);
  b.header->clock_valid = 1;
  dsa_flow_push(&b, 10, 1, 2, 3, 0, 4, 5, 6, 7, 8);
  assert(b.header->event_count == 1 && b.events[0].e == 8);
  dsa_flow_push(&b, 11, 1, 2, 3, 0, 0, 0, 0, 0, 0);
  assert(b.header->dropped == 1 && b.header->end_ns == 11);
  dsa_flow_push(&b, 9, 1, 2, 3, 0, 0, 0, 0, 0, 0);
  assert(b.header->clock_valid == 0 && b.header->end_ns == 11);
  assert(dsa_flow_layout_valid(8192, 4096, 4096, 32));
  assert(dsa_flow_layout_valid(4096, 0, 4096, 32));
  assert(!dsa_flow_layout_valid(4096, 4096, 4096, 32));
  assert(!dsa_flow_layout_valid(4096, 8192, 4096, 32));
  assert(!dsa_flow_layout_valid(8320, 4096, 4096, 32));
  assert(!dsa_flow_layout_valid(8192, 4097, 4096, 32));
  return 0;
}
''')
        binary = self.root/'header'
        subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                        '-I'+str(ROOT/'criu/include'), str(source), '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True)


if __name__ == '__main__':
    unittest.main()
