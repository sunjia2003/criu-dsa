"""Keep the common streaming-summary regression independent of range scanning."""
import ctypes
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


def function(source, signature):
    start = source.index(signature)
    body = source.index('{', start)
    depth = 1
    end = body + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


class StreamSummaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='dsa-stream-summary-')
        cls.addClassCleanup(cls.tmp.cleanup)
        directory = Path(cls.tmp.name)
        mem = (ROOT / 'criu/mem.c').read_text()
        summary = function(mem, 'static void dsa_desc_scan_emit_summary(')
        fixture = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint64_t u64;
typedef uint32_t u32;
static bool summary_enabled;
static char summary_text[1024];
#define pr_info(...) snprintf(summary_text, sizeof(summary_text), __VA_ARGS__)
static bool dsa_env_enabled(const char *name) {
    assert(!strcmp(name, "CRIU_DSA_STREAM_SUMMARY"));
    return summary_enabled;
}
struct dsa_desc_scan_ctx {
    u64 stream_bytes, stream_descs;
    u32 produced_slots;
    u64 producer_wait_slot_us, finish_wait_us;
    struct {
        u32 raw_faults, raw_fault_resubmits, batch_max_active_outer, batch_child_submits;
    } rpc_args;
};
__SUMMARY__
int check_summary(void) {
    struct dsa_desc_scan_ctx sc={.stream_bytes=1234,.stream_descs=19,.produced_slots=2,
      .producer_wait_slot_us=17,.finish_wait_us=23,.rpc_args={3,4,5,6}};
    summary_enabled=false;summary_text[0]=0;dsa_desc_scan_emit_summary(&sc);
    if(summary_text[0])return 0;
    summary_enabled=true;dsa_desc_scan_emit_summary(&sc);
    return strstr(summary_text,"payload_bytes=1234 descriptors=19 slots=2 producer_wait_slot_us=17 stream_finish_wait_us=23") &&
      strstr(summary_text,"raw_faults=3 raw_fault_resubmits=4 batch_max_active_outer=5 batch_child_submits=6");
}
'''
        source, library = directory / 'check.c', directory / 'check.so'
        source.write_text(fixture.replace('__SUMMARY__', summary))
        subprocess.run([
            'cc', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
            '-shared', '-fPIC', str(source), '-o', str(library),
        ], check=True)
        cls.lib = ctypes.CDLL(str(library))
        cls.lib.check_summary.restype = ctypes.c_int

    def test_optional_summary_uses_existing_counters_and_is_disabled_by_default(self):
        self.assertEqual(self.lib.check_summary(), 1)


if __name__ == '__main__':
    unittest.main()
