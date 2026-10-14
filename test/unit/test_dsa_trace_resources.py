"""Compile production declarations and IOV helper; synthetic data, not timings."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class TraceResourceTests(unittest.TestCase):
    def test_compact_defaults_keep_full_flow_and_override_headroom(self):
        header = (ROOT/'criu/include/parasite.h').read_text()
        declarations = header[header.index('#define DSA_PIPELINE_HEAD_COUNT'):
                              header.index('struct parasite_dsa_stream_hdr {')]
        with tempfile.TemporaryDirectory(prefix='dsa-trace-capacity-') as temporary:
            source = Path(temporary)/'capacity.c'
            source.write_text('''
#include <stdint.h>
#include <assert.h>
typedef uint32_t u32;
typedef uint64_t u64;
#include "dsa-flow.h"
'''+declarations+'''
int main(void) {
  assert(DSA_HOST_TRACE_BYTES_DEFAULT == 8U*1024U*1024U);
  assert(DSA_PIPELINE_TRACE_BYTES_DEFAULT == 32U*1024U*1024U);
  assert(DSA_FLOW_BYTES_DEFAULT == 32U*1024U*1024U);
  assert(DSA_PIPELINE_TRACE_BYTES_DEFAULT / sizeof(struct dsa_pipeline_event) == 1048576U);
  assert(DSA_HOST_TRACE_BYTES_DEFAULT / sizeof(struct dsa_pipeline_event) == 262144U);
  assert(DSA_HOST_TRACE_BYTES_DEFAULT < DSA_HOST_TRACE_BYTES_MAX);
  assert(DSA_PIPELINE_TRACE_BYTES_DEFAULT < DSA_PIPELINE_TRACE_BYTES_MAX);
  assert(dsa_flow_layout_valid(DSA_PIPELINE_TRACE_BYTES_DEFAULT+DSA_FLOW_BYTES_DEFAULT,
                              DSA_FLOW_BYTES_DEFAULT, DSA_PIPELINE_TRACE_BYTES_MAX,
                              sizeof(struct dsa_pipeline_event)));
  assert(dsa_flow_layout_valid(DSA_PIPELINE_TRACE_BYTES_DEFAULT, 0,
                              DSA_PIPELINE_TRACE_BYTES_MAX, sizeof(struct dsa_pipeline_event)));
  return 0;
}
''')
            binary = Path(temporary)/'capacity'
            subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                            '-I'+str(ROOT/'criu/include'), str(source), '-o', str(binary)], check=True)
            subprocess.run([str(binary)], check=True)

    def test_quiet_creation_logs_preserve_production_iov_operations(self):
        text = (ROOT/'criu/page-pipe.c').read_text()
        grow = text[text.index('static inline bool iov_grow_page('):
                    text.index('static int __ppb_resize_pipe(')]
        add = text[text.index('static inline int try_add_page_to_unbounded('):
                   text.index('static inline int try_add_page_unbounded(')]
        header = (ROOT/'criu/include/page-pipe.h').read_text()
        flags = header[header.index('#define PP_CHUNK_MODE'):
                       header.index('struct page_pipe *create_page_pipe(')]
        with tempfile.TemporaryDirectory(prefix='dsa-quiet-iov-') as temporary:
            source = Path(temporary)/'iov.c'
            source.write_text('''
#include <assert.h>
#include <stdbool.h>
#include <sys/uio.h>
#define PAGE_SIZE 4096
#define BUG_ON(condition) assert(!(condition))
static unsigned logs;
#define pr_debug(...) (logs++)
struct page_pipe { unsigned flags, free_iov, nr_iovs; };
struct page_pipe_buf { unsigned flags, nr_segs; unsigned long pages_in; struct iovec *iov; };
'''+flags+grow+add+'''
int main(void) {
  for (unsigned quiet=0; quiet<2; quiet++) {
    struct iovec iov[3] = {0};
    struct page_pipe p = {.flags=quiet ? PP_QUIET_IOV : 0, .nr_iovs=3};
    struct page_pipe_buf b = {.iov=iov};
    logs=0;
    assert(try_add_page_to_unbounded(&p, &b, 4096, 0) == 0);
    assert(try_add_page_to_unbounded(&p, &b, 8192, 0) == 0);
    assert(try_add_page_to_unbounded(&p, &b, 16384, 0) == 0);
    assert(try_add_page_to_unbounded(&p, &b, 20480, 1) == 1);
    assert(p.free_iov == 2 && b.nr_segs == 2 && b.pages_in == 3);
    assert(iov[0].iov_base == (void *)4096 && iov[0].iov_len == 8192);
    assert(iov[1].iov_base == (void *)16384 && iov[1].iov_len == 4096);
    assert(logs == (quiet ? 0 : 2));
  }
  return 0;
}
''')
            binary = Path(temporary)/'iov'
            subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                            str(source), '-o', str(binary)], check=True)
            subprocess.run([str(binary)], check=True)

    def test_compact_logs_are_opt_out_and_full_streaming_only(self):
        text = (ROOT/'criu/mem.c').read_text()
        self.assertIn('if (dsa_desc_scan_active && dsa_sc.scan_profile &&\n'
                      '\t    !dsa_env_enabled("CRIU_DSA_IOV_DEBUG"))\n'
                      '\t\tcpp_flags |= PP_QUIET_IOV;', text)
        self.assertIn('if (!dsa_scan_profile_enabled())\n\t\treturn 0;\n'
                      '\treturn dsa_pipeline_trace_alloc() ? 0 : -1;', text)


if __name__ == '__main__':
    unittest.main()
