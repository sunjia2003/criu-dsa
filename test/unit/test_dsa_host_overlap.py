"""Check explanatory worker-wall intersections, distinct from CPU utilization."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('host_compare', ROOT/'scripts/compare_host_scan_suites.py')
compare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(compare)


def block(worker, vma, begin, end):
    return dict(worker=worker, vma_start=vma, classify_start_us=begin, classify_end_us=end)


class WorkerOverlapTests(unittest.TestCase):
    def test_same_and_cross_vma_intersections_are_separate(self):
        result = compare.block_overlap([block(0,100,10,20), block(1,100,15,25), block(0,200,20,30)])
        self.assertEqual(result['worker_wall_sum_us'],30)
        self.assertEqual(result['same_vma_overlap_us'],5)
        self.assertEqual(result['cross_vma_overlap_us'],5)
        self.assertEqual(result['classifier_union_us'],20)

    def test_touching_intervals_do_not_overlap(self):
        self.assertEqual(compare.block_overlap([block(0,100,10,20),block(1,200,20,30)])['cross_vma_overlap_us'],0)

    def test_same_worker_overlap_is_rejected(self):
        with self.assertRaisesRegex(ValueError,'worker has overlapping'):
            compare.block_overlap([block(0,100,10,20),block(0,200,15,25)])

    def test_backwards_clock_is_rejected(self):
        with self.assertRaisesRegex(ValueError,'Backwards'):
            compare.block_overlap([block(0,100,20,10)])

    def test_ready_window_and_consumer_overlap_use_real_boundaries(self):
        blocks = [block(0,100,10,20),block(1,100,15,25),block(0,100,20,35)]
        for i,b in enumerate(blocks):
            b.update(sequence=i,consume_start_us=30+i*10,consume_end_us=40+i*10,
                     classify_cpu_us=[8,5,12][i],worker_cpu=[18,19,18][i])
        result=compare.block_pipeline(blocks)
        self.assertEqual(result['ready_blocks_at_consume_max'],2)
        self.assertAlmostEqual(result['ready_blocks_at_consume_mean'],5/3)
        self.assertEqual(result['classifier_and_consumer_scope_overlap_us'],5)
        self.assertEqual(result['classifier_thread_cpu_sum_us'],25)
        self.assertEqual(result['observed_worker_cpus'],[18,19])

    def test_consumer_cannot_precede_its_classification(self):
        value=block(0,100,10,20)
        value.update(sequence=0,consume_start_us=19,consume_end_us=30,classify_cpu_us=5,worker_cpu=18)
        with self.assertRaisesRegex(ValueError,'ordered consume'):
            compare.block_pipeline([value])


if __name__ == '__main__':
    unittest.main()
