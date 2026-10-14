"""Production vDSO bracket, validation and syscall fallback, not performance data."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ClockTests(unittest.TestCase):
    def test_production_default_and_explicit_syscall_escape(self):
        text=(ROOT/'criu/mem.c').read_text()
        helper=text[text.index('static bool dsa_env_enabled('):
                    text.index('static int dsa_dup_inherited_fd(')]
        code=r'''
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <assert.h>
__HELPER__
int main(void) {
  unsetenv("CRIU_DSA_TRACE_VDSO");
  assert(dsa_trace_vdso_enabled());
  const char *disabled[]={"0","off","false","", "invalid"};
  for (unsigned i=0;i<sizeof(disabled)/sizeof(disabled[0]);i++) {
    setenv("CRIU_DSA_TRACE_VDSO",disabled[i],1);
    assert(!dsa_trace_vdso_enabled());
  }
  const char *enabled[]={"1","true","YES","on"};
  for (unsigned i=0;i<sizeof(enabled)/sizeof(enabled[0]);i++) {
    setenv("CRIU_DSA_TRACE_VDSO",enabled[i],1);
    assert(dsa_trace_vdso_enabled());
  }
  return 0;
}
'''.replace('__HELPER__',helper)
        with tempfile.TemporaryDirectory(prefix='dsa-clock-default-') as temporary:
            source=Path(temporary)/'default.c';binary=Path(temporary)/'default'
            source.write_text(code)
            subprocess.run(['cc','-std=gnu11','-Wall','-Wextra','-Werror',str(source),'-o',str(binary)],check=True)
            subprocess.run([str(binary)],check=True)

    def test_production_brackets_and_runtime_fallback(self):
        code = r'''
#include <stdint.h>
#include <assert.h>
typedef uint64_t u64;
typedef uint32_t u32;
#include "dsa-clock.h"
static long tick = 100;
static int broken, slow_broken;
static int syscall_clock(clockid_t clock, struct timespec *ts) {
  assert(clock == CLOCK_MONOTONIC);
  if (slow_broken) return -1;
  ts->tv_sec=1; ts->tv_nsec=(tick+=10); return 0;
}
static int fast_clock(clockid_t clock, struct timespec *ts) {
  if (broken == 1) return -1;
  int ret=syscall_clock(clock, ts);
  if (broken == 2) ts->tv_nsec=1000000000L;
  if (broken == 3) ts->tv_sec=0;
  if (broken == 4) ts->tv_sec=-1;
  return ret;
}
int main(void) {
  struct timespec ts;
  struct dsa_trace_clock c={.fallback=syscall_clock};
  dsa_clock_try_vdso(&c, fast_clock);
  assert(!c.fast && !c.checks && !c.vdso_reads && !c.syscall_reads);
  c.requested=1;
  dsa_clock_try_vdso(&c, fast_clock);
  assert(c.fast && c.selected && c.checks == 16 && !c.errors);
  assert(c.syscall_reads == 32 && c.vdso_reads == 16 && c.max_bracket_ns == 20);
  assert(!dsa_clock_read(&c, &ts) && c.vdso_reads == 17 && c.syscall_reads == 32);
  for (int failure=1; failure<=4; failure++) {
    broken=0;
    c=(struct dsa_trace_clock){.fallback=syscall_clock,.requested=1};
    dsa_clock_try_vdso(&c, fast_clock);
    assert(c.selected);
    broken=failure;
    assert(!dsa_clock_read(&c, &ts) && !c.fast && !c.selected && c.errors == 1);
    assert(c.syscall_reads == 33 && c.vdso_reads == 17);
    assert(!dsa_clock_read(&c, &ts) && c.syscall_reads == 34);
    c=(struct dsa_trace_clock){.fallback=syscall_clock,.requested=1};
    dsa_clock_try_vdso(&c, fast_clock);
    assert(!c.fast && !c.selected && !c.checks && c.errors == 1);
  }
  broken=0;
  c=(struct dsa_trace_clock){.fallback=syscall_clock,.requested=1};
  dsa_clock_try_vdso(&c, NULL);
  assert(!c.fast && !c.checks && !c.errors);
  assert(!dsa_clock_read(&c, &ts) && c.syscall_reads == 1);
  slow_broken=1;
  assert(dsa_clock_read(&c, &ts) < 0);
  assert(c.failed && c.errors == 1);
  slow_broken=0;
  assert(dsa_clock_read(&c, &ts) < 0); /* A failed capture is never silently repaired. */
  slow_broken=1;
  c=(struct dsa_trace_clock){.fallback=syscall_clock,.requested=1};
  dsa_clock_try_vdso(&c, fast_clock);
  assert(!c.fast && !c.selected && !c.checks && c.errors == 1);
  slow_broken=0;
  c=(struct dsa_trace_clock){.fallback=syscall_clock,.last_ns=2000000000ULL};
  assert(dsa_clock_read(&c, &ts) < 0);
  assert(c.failed && c.errors == 1);
  return 0;
}
'''
        with tempfile.TemporaryDirectory(prefix='dsa-clock-') as temporary:
            source=Path(temporary)/'clock.c'; binary=Path(temporary)/'clock'
            source.write_text(code)
            subprocess.run(['cc','-std=gnu11','-O2','-Wall','-Wextra','-Werror',
                            '-iquote'+str(ROOT/'criu/include'), str(source), '-o', str(binary)], check=True)
            subprocess.run([str(binary)], check=True)

    def test_vdso_is_full_only_and_clock_results_are_not_rpc_scratch(self):
        host=(ROOT/'criu/mem.c').read_text()
        parasite=(ROOT/'criu/pie/parasite.c').read_text()
        self.assertIn('if (sc->scan_profile && dsa_trace_vdso_enabled() &&', host)
        self.assertIn('compel_mode_native(sc->ctl)', host)
        self.assertIn('a->trace_vdso_enabled && a->pipeline_trace_bytes && a->profile_enabled', parasite)
        self.assertIn('dsa_memzero(&dsa_trace_clock, sizeof(dsa_trace_clock));', parasite)
        self.assertIn('DSA_TRACE_CLOCK: version=1 pid=', parasite)
        self.assertIn('static struct dsa_trace_clock dsa_trace_clock;', parasite)
        self.assertNotIn('result_trace_clock', (ROOT/'criu/include/parasite.h').read_text())

    def test_full_microsecond_intervals_keep_clock_domain_on_fallback(self):
        text=(ROOT/'criu/pie/parasite.c').read_text()
        helper=text[text.index('static inline u64 dsa_now_us(void)'):
                    text.index('static u64 dsa_pipeline_mono_ns(void)')]
        code=r'''
#include <assert.h>
#include <stdint.h>
#include <sys/time.h>
typedef uint64_t u64;
typedef uint32_t u32;
#include "dsa-clock.h"
static struct dsa_trace_clock dsa_trace_clock;
static int wall_calls, broken;
static int mono_clock(clockid_t clock, struct timespec *ts) {
  assert(clock == CLOCK_MONOTONIC);
  ts->tv_sec=100; ts->tv_nsec=2345; return 0;
}
static int fast_clock(clockid_t clock, struct timespec *ts) {
  if (broken) return -1;
  return mono_clock(clock, ts);
}
static long sys_gettimeofday(struct timeval *tv, void *tz) {
  assert(tz == NULL);wall_calls++;tv->tv_sec=42;tv->tv_usec=123;return 0;
}
__HELPER__
int main(void) {
  assert(dsa_now_us() == 42000123 && wall_calls == 1);
  dsa_trace_clock=(struct dsa_trace_clock){.requested=1,.fast=fast_clock,.fallback=mono_clock};
  assert(dsa_now_us() == 100000002 && wall_calls == 1);
  broken=1;
  assert(dsa_now_us() == 100000002 && wall_calls == 1);
  assert(!dsa_trace_clock.fast && dsa_trace_clock.errors == 1);
  dsa_trace_clock.requested=0;
  assert(dsa_now_us() == 42000123 && wall_calls == 2);
  return 0;
}
'''.replace('__HELPER__',helper)
        with tempfile.TemporaryDirectory(prefix='dsa-us-clock-') as temporary:
            source=Path(temporary)/'clock.c';binary=Path(temporary)/'clock'
            source.write_text(code)
            subprocess.run(['cc','-std=gnu11','-O2','-Wall','-Wextra','-Werror',
                            '-iquote'+str(ROOT/'criu/include'),str(source),'-o',str(binary)],check=True)
            subprocess.run([str(binary)],check=True)


if __name__ == '__main__':
    unittest.main()
