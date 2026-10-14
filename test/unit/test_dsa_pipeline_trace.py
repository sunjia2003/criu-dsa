"""Synthetic binary fixtures validate the reader, not checkpoint performance."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('pipeline_trace_reader', ROOT/'scripts/dsa_pipeline_trace.py')
reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reader)


class TraceReaderTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='dsa-trace-reader-')
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name)/'dsa-pipeline-42.bin'
        self.events = [(100, 110, 1, 0, 0), (110, 130, 2, 2, 0),
                       (130, 160, 3, 3, 0), (160, 200, 2, 2, 1),
                       (200, 220, 1, 0, 1)]
        self.fields = [reader.MAGIC, 1, reader.HEADER.size, reader.EVENT.size,
                       100, 220, 5, 0, *[30, 0, 60, 30, 0, 0],
                       *[1, 0, 1, 1, 0, 0], *[2, 0, 2, 1, 0, 0], 42, 1, 10, 1]

    def write(self):
        self.path.write_bytes(reader.HEADER.pack(*self.fields)+
                              b''.join(reader.EVENT.pack(*event) for event in self.events))

    def test_real_duration_and_invocation_count_are_distinct(self):
        self.write()
        result = reader.validate(self.path)
        self.assertEqual(result['consumer_wall_ns'], 120)
        self.assertEqual(result['phases']['accept'], dict(exclusive_ns=60, calls=1, fragments=2))

    def test_missing_and_overlapping_intervals_are_rejected(self):
        for start in (159, 161):
            self.events[3] = (start, 200, 2, 2, 1)
            self.write()
            with self.assertRaises(ValueError):
                reader.validate(self.path)

    def test_dropped_trace_is_not_accepted_as_complete(self):
        self.fields[7] = 3
        self.write()
        with self.assertRaises(ValueError):
            reader.validate(self.path)

    def test_truncated_file_is_rejected(self):
        self.events.pop()
        self.write()
        with self.assertRaises(ValueError):
            reader.validate(self.path)

    def test_nested_counter_or_wrong_call_count_is_rejected(self):
        for index in (10, 16):
            self.fields[index] += 1
            self.write()
            with self.assertRaises(ValueError):
                reader.validate(self.path)
            self.fields[index] -= 1

    def test_invalid_clock_or_incompatible_layout_is_rejected(self):
        for index in (0, 1, 3, 27):
            original = self.fields[index]
            self.fields[index] = 0
            self.write()
            with self.assertRaises(ValueError):
                reader.validate(self.path)
            self.fields[index] = original

    def test_resumed_invocation_cannot_change_phase(self):
        self.events[3] = (160, 200, 2, 1, 1)
        self.write()
        with self.assertRaises(ValueError):
            reader.validate(self.path)

    def test_matching_raw_log_is_verified_and_mismatch_rejected(self):
        self.write()
        profile = ('DSA_PIPELINE_PROFILE: version=2 pid=42 clock_valid=1 consumer_begin_ns=100 '
                   'consumer_end_ns=220 control_ns=30 poll_scan_ns=0 accept_ns=60 '
                   'prepare_ns=30 submit_call_ns=0 harvest_ns=0')
        counts = [f'DSA_PIPELINE_PHASE_COUNTS: version=1 pid=42 phase={i} calls={self.fields[14+i]} '
                  f'segments={self.fields[20+i]} exclusive_ns={self.fields[8+i]}' for i in range(6)]
        log = self.path.parent/'dump.log'
        text = '\n'.join([profile, *counts, 'DSA_PIPELINE_TRACE_FILE: version=1 pid=42 records=5 dropped=0 complete=1'])
        log.write_text(text)
        self.assertTrue(reader.validate(self.path, log)['dump_log_verified'])
        log.write_text(text.replace('accept_ns=60', 'accept_ns=61'))
        with self.assertRaises(ValueError):
            reader.validate(self.path, log)

    def test_v2_reports_reserved_poll_as_not_collected(self):
        self.fields[1] = 2
        self.write()
        result = reader.validate(self.path)
        self.assertEqual(result['version'], 2)
        self.assertEqual(result['phases']['accept_batch']['exclusive_ns'], 60)
        self.assertFalse(result['phases']['reserved_poll']['collected'])
        self.assertEqual(result['phases']['reserved_poll']['merged_into'], 'background_check')

    def test_v2_rejects_reserved_phase_events(self):
        self.fields[1] = 2
        self.events[1] = (110, 130, 2, 1, 0)
        self.write()
        with self.assertRaisesRegex(ValueError, 'Reserved poll phase'):
            reader.validate(self.path)


if __name__ == '__main__':
    unittest.main()
