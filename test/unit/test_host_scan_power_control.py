"""Exercise restoration paths with mocked CPU policy I/O; no privilege required."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[2]/'scripts/host_scan_power_control.py'
SPEC = importlib.util.spec_from_file_location('host_scan_power_control', SCRIPT)
power = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(power)


class PowerControlTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.output = Path(self.directory.name)/'record'
        self.before = {str(cpu): {'scaling_driver':'intel_pstate',
            'scaling_governor':'powersave',
            'energy_performance_preference':'balance_performance',
            'scaling_min_freq':'800000', 'scaling_max_freq':'3800000',
            'related_cpus':str(cpu)} for cpu in power.CPUS}
        self.active = copy.deepcopy(self.before)
        for state in self.active.values():
            state.update(scaling_governor='performance',
                         energy_performance_preference='performance')

    def run_mocked(self, snapshots, privileged_effect=None):
        argv = [str(SCRIPT), '--run', '--smoke-test', '--record-dir', str(self.output)]
        with patch('sys.argv', argv), patch.object(power.os, 'geteuid', return_value=1000), \
             patch.object(power, 'snapshot', side_effect=snapshots), \
             patch.object(power, 'privileged', side_effect=privileged_effect) as action, \
             patch.object(power.signal, 'signal'):
            try:
                power.main()
            finally:
                self.actions = [call.args[0] for call in action.call_args_list]

    def record(self):
        return json.loads((self.output/'power-control.json').read_text())

    def test_success_restores_exact_state(self):
        self.run_mocked([self.before, self.active, self.active, self.before])
        self.assertEqual(self.actions, ['performance', 'restore'])
        self.assertTrue(self.record()['restored'])

    def test_partial_apply_failure_still_restores(self):
        with self.assertRaisesRegex(RuntimeError, 'apply failed'):
            self.run_mocked([self.before, self.before], [RuntimeError('apply failed'), None])
        self.assertEqual(self.actions, ['performance', 'restore'])
        self.assertTrue(self.record()['restored'])

    def test_interruption_still_restores(self):
        with self.assertRaises(KeyboardInterrupt):
            self.run_mocked([self.before, KeyboardInterrupt(), self.before])
        self.assertEqual(self.actions, ['performance', 'restore'])
        self.assertTrue(self.record()['restored'])

    def test_policy_change_during_run_is_not_accepted(self):
        changed = copy.deepcopy(self.active)
        changed['18']['scaling_min_freq'] = '900000'
        with self.assertRaisesRegex(RuntimeError, 'changed during'):
            self.run_mocked([self.before, self.active, changed, self.before])
        self.assertTrue(self.record()['restored'])

    def test_failed_restoration_is_reported(self):
        with self.assertRaisesRegex(RuntimeError, 'restoration is incomplete'):
            self.run_mocked([self.before, self.active, self.active, self.active],
                            [None, RuntimeError('restore failed')])
        self.assertFalse(self.record()['restored'])
        self.assertIn('restore failed', self.record()['restore_error'])


if __name__ == '__main__':
    unittest.main()
