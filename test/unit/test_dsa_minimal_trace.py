"""Guard probe placement in production hot paths; accounting is tested separately."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class MinimalProbePlacementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.host = (ROOT/'criu/mem.c').read_text()
        cls.parasite = (ROOT/'criu/pie/parasite.c').read_text()

    def test_page_selection_has_no_detail_clocks_or_diagnostic_extent_tracking(self):
        code = self.host[self.host.index('static int generate_iovs_dsa_desc_scan('):
                         self.host.index('static int generate_vma_iovs_dsa_desc_scan(')]
        for probe in ('dsa_scan_detail_', 'dsa_wall_now_us', 'dsa_desc_scan_raw_', 'scan_profile'):
            self.assertNotIn(probe, code)
        for operation in ('should_dump_page(', 'page_info.next', 'is_stack(',
                          'dsa_parent_coverage_contains_range(', 'page_pipe_add_hole(',
                          'page_pipe_add_page_unbounded(', 'dsa_desc_scan_batch_append('):
            self.assertIn(operation, code)

    def test_consumer_loop_closes_once_without_per_iteration_phase_switches(self):
        code = self.parasite[self.parasite.index('static int dsa_stream_consume_hw_runway('):
                             self.parasite.index('static int dsa_legacy_single_rpc_consume(')]
        self.assertEqual(code.count('dsa_pipeline_switch('), 1)
        self.assertIn('dsa_pipeline_enter(DSA_PIPELINE_HARVEST)', code)
        for operation in ('dsa_raw_stream_batch_ready(', 'dsa_raw_stream_accept_slot(',
                          'dsa_flow_input_state(', 'dsa_flow_snapshot(', 'dsa_cpu_relax()'):
            self.assertIn(operation, code)

    def test_accept_scope_starts_only_after_capacity_is_available(self):
        code = self.parasite[self.parasite.index('static int dsa_raw_stream_accept_slot('):
                             self.parasite.index('static void dsa_raw_stream_recycle_slot(')]
        capacity = code.index('if (free_count < needed)\n\t\treturn 0;')
        scope = code.index('dsa_pipeline_enter(DSA_PIPELINE_ACCEPT)')
        self.assertLess(capacity, scope)
        self.assertNotIn('dsa_pipeline_now()', code[:scope])
        self.assertNotIn('dsa_flow_now_ns()', code[:scope])
        self.assertIn('dsa_pipeline_resume(pipeline_parent);\n\treturn 1;', code)

    def test_fast_reusable_slot_does_not_enter_wait_phase(self):
        code = self.host[self.host.index('static int dsa_stream_wait_slot('):
                         self.host.index('static void dsa_desc_scan_reset_batch(')]
        actual_wait = code.index('if (!wait_start) {')
        phase = code.index('dsa_scan_detail_switch(sc, DSA_SCAN_SLOT_WAIT)')
        self.assertLess(actual_wait, phase)
        self.assertIn('DSA_STREAM_SLOT_EMPTY', code[:actual_wait])
        self.assertIn('DSA_STREAM_SLOT_DONE', code[:actual_wait])
        self.assertIn('DSA_STREAM_WAIT_SLOT_TIMEOUT_US', code)
        self.assertIn('dsa_scan_detail_resume(sc, detail_parent)', code)


if __name__ == '__main__':
    unittest.main()
