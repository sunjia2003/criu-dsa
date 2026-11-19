"""Verify the external oracle rejects wrong bytes and wrong generations."""
import importlib.util
import io
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('host_probe',ROOT/'scripts/host_scan_probe.py')
probe=importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class ExternalOracleTests(unittest.TestCase):
    def fixture(self, layout='dense'):
        args=SimpleNamespace(pages=9,dirty_run=1,clean_gap=1,checkpoints=3)
        state={'base':4096,'layout':layout,'excluded_page':4 if layout!='dense' else (1<<64)-1}
        image=bytearray(4096)
        mask=(1<<64)-1
        for page in range(args.pages):
            gen=2 if page%2==0 and page!=state['excluded_page'] else 0
            for offset in range(4096):
                value=((page+1)*0x9e3779b97f4a7c15+offset*0xd1b54a32d192ed03+gen*0x94d049bb133111eb)&mask
                value^=value>>33
                value=(value*0xff51afd7ed558ccd)&mask
                image.append((value>>32)&255)
        return args,state,image

    def test_scalar_reference_matches_all_bytes_and_mapping_exceptions(self):
        for layout in ('dense','protected','unmapped'):
            args,state,image=self.fixture(layout)
            with patch('builtins.open',return_value=io.BytesIO(image)):
                value=probe.verify_external(42,state,args)
            self.assertEqual(value['byte_errors'],0)
            self.assertEqual(value['checked_bytes'],(args.pages-(layout=='unmapped'))*4096)

    def test_corrupted_clean_page_is_rejected(self):
        args,state,image=self.fixture()
        image[4096+4096+17]^=1
        with patch('builtins.open',return_value=io.BytesIO(image)):
            with self.assertRaisesRegex(RuntimeError,'byte errors'):probe.verify_external(42,state,args)

    def test_wrong_generation_is_rejected(self):
        args,state,image=self.fixture();args.checkpoints=2
        with patch('builtins.open',return_value=io.BytesIO(image)):
            with self.assertRaisesRegex(RuntimeError,'byte errors'):probe.verify_external(42,state,args)


if __name__=='__main__':unittest.main()
