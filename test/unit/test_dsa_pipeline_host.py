"""Exercise production Host accounting, not a reimplemented timer model.

The deterministic clock and tiny binary are synthetic correctness fixtures;
they never enter experimental figures or performance conclusions.
"""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class HostAccountingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        header = (ROOT/'criu/include/parasite.h').read_text()
        source = (ROOT/'criu/mem.c').read_text()
        wire = header[header.index('#define DSA_PIPELINE_HEAD_COUNT'):header.index('struct parasite_dsa_stream_hdr {')]
        declarations = source[source.index('enum dsa_scan_detail_phase {'):source.index('struct dsa_desc_scan_ctx {')]
        helpers = source[source.index('static u64 dsa_scan_detail_now('):source.index('static void dsa_scan_detail_emit(')]
        fixture = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
typedef uint32_t u32;
typedef uint64_t u64;
static u64 fake_ns;
static int clock_calls, clock_failed;
static int fake_clock_gettime(int id, struct timespec *ts) {
    assert(id == CLOCK_MONOTONIC); clock_calls++;
    if (clock_failed) return -1;
    ts->tv_sec = fake_ns / 1000000000ULL;
    ts->tv_nsec = fake_ns % 1000000000ULL;
    return 0;
}
#define clock_gettime fake_clock_gettime
__WIRE__
__DECLARATIONS__
struct dsa_pipeline_trace_ctx { void *host_buf; size_t host_size; };
struct dsa_dump_ctx { struct dsa_pipeline_trace_ctx *pipeline_trace; };
struct dsa_desc_scan_ctx { bool scan_profile; struct dsa_scan_detail detail; struct dsa_dump_ctx *dsa_ctx; };
__HELPERS__
int main(int argc, char **argv) {
    assert(argc == 2 && sizeof(dsa_scan_detail_names)/sizeof(*dsa_scan_detail_names) == 3);
    struct dsa_pipeline_event events[32] = {0};
    struct dsa_pipeline_trace_ctx trace = {events, sizeof(events)};
    struct dsa_dump_ctx ctx = {&trace};
    struct dsa_desc_scan_ctx sc = {.scan_profile=true, .dsa_ctx=&ctx};
    if (!strcmp(argv[1], "disabled")) {
        sc.scan_profile = false; sc.dsa_ctx = NULL;
        dsa_scan_detail_begin(&sc, 42);
        dsa_scan_detail_switch(&sc, DSA_SCAN_ORGANIZE);
        dsa_scan_detail_resume(&sc, dsa_scan_detail_save(&sc));
        dsa_scan_detail_end(&sc);
        assert(clock_calls == 0 && !sc.detail.recorded); return 0;
    }
    fake_ns = 100;
    dsa_scan_detail_begin(&sc, 42);
    if (!strcmp(argv[1], "invalid") || !strcmp(argv[1], "backwards")) {
        clock_failed = !strcmp(argv[1], "invalid"); fake_ns = 90;
        dsa_scan_detail_switch(&sc, DSA_SCAN_ORGANIZE);
        dsa_scan_detail_end(&sc);
        assert(!sc.detail.valid && sc.detail.count == 0); return 0;
    }
    if (!strcmp(argv[1], "zero")) {
        dsa_scan_detail_switch(&sc, DSA_SCAN_PACK_PUBLISH);
        dsa_scan_detail_end(&sc);
        assert(sc.detail.count == 2 && events[1].start_ns == events[1].end_ns);
        assert(sc.detail.total_ns == 0 && sc.detail.calls[DSA_SCAN_PACK_PUBLISH] == 1); return 0;
    }
    if (!strcmp(argv[1], "overflow")) sc.detail.capacity = 2;
    struct dsa_pipeline_scope scan = dsa_scan_detail_save(&sc);
    fake_ns = 110; dsa_scan_detail_switch(&sc, DSA_SCAN_PACK_PUBLISH);
    struct dsa_pipeline_scope pack = dsa_scan_detail_save(&sc);
    fake_ns = 130; dsa_scan_detail_switch(&sc, DSA_SCAN_SLOT_WAIT);
    fake_ns = 140; dsa_scan_detail_resume(&sc, pack);
    fake_ns = 150; dsa_scan_detail_resume(&sc, scan);
    fake_ns = 250; dsa_scan_detail_end(&sc);
    struct dsa_scan_detail *d = &sc.detail;
    assert(d->valid && d->recorded && !d->active && d->total_ns == 150);
    assert(d->phase_ns[DSA_SCAN_ORGANIZE] == 110);
    assert(d->phase_ns[DSA_SCAN_PACK_PUBLISH] == 30);
    assert(d->phase_ns[DSA_SCAN_SLOT_WAIT] == 10);
    assert(d->calls[DSA_SCAN_PACK_PUBLISH] == 1 && d->segments[DSA_SCAN_PACK_PUBLISH] == 2);
    u64 sum = 0, segments = 0;
    for (u32 i=0; i<DSA_SCAN_DETAIL_NR; i++) { sum += d->phase_ns[i]; segments += d->segments[i]; }
    assert(sum == 150 && segments == 5 && segments == d->count + d->dropped);
    if (!strcmp(argv[1], "overflow")) {
        assert(d->count == 2 && d->dropped == 3 && events[1].end_ns == 130); return 0;
    }
    assert(d->count == 5 && !d->dropped);
    assert(events[1].occurrence == events[3].occurrence && events[3].flags == DSA_PIPELINE_EVENT_RESUMED);
    u64 totals[DSA_SCAN_DETAIL_NR] = {0}, last = 100;
    for (u32 i=0; i<d->count; i++) {
        assert(events[i].start_ns == last); last = events[i].end_ns;
        totals[events[i].phase] += events[i].end_ns-events[i].start_ns;
    }
    for (u32 i=0; i<DSA_SCAN_DETAIL_NR; i++) assert(totals[i] == d->phase_ns[i]);
    assert(last == 250);
    if (!strcmp(argv[1], "export")) {
        struct dsa_host_trace_file h = {.magic=DSA_HOST_TRACE_MAGIC, .version=DSA_PIPELINE_TRACE_VERSION,
            .header_size=sizeof(h), .event_size=sizeof(*events), .scan_begin_ns=100,
            .scan_end_ns=250, .event_count=d->count, .pid=42, .clock_valid=1,
            .capacity=d->capacity, .flags=DSA_PIPELINE_TRACE_COMPLETE};
        memcpy(h.phase_ns, d->phase_ns, sizeof(h.phase_ns));
        memcpy(h.phase_calls, d->calls, sizeof(h.phase_calls));
        memcpy(h.phase_segments, d->segments, sizeof(h.phase_segments));
        FILE *file = fopen("host.bin", "wb"); assert(file);
        assert(fwrite(&h, sizeof(h), 1, file) == 1);
        assert(fwrite(events, sizeof(*events), d->count, file) == d->count);
        assert(fclose(file) == 0);
    }
    return 0;
}
'''
        fixture = fixture.replace('__WIRE__', wire).replace('__DECLARATIONS__', declarations).replace('__HELPERS__', helpers)
        cls.temporary = tempfile.TemporaryDirectory(prefix='dsa-host-accounting-')
        cls.addClassCleanup(cls.temporary.cleanup)
        directory = Path(cls.temporary.name)
        code, cls.binary = directory/'host.c', directory/'host'
        code.write_text(fixture)
        subprocess.run(['cc', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror', str(code), '-o', str(cls.binary)], check=True)
        spec = importlib.util.spec_from_file_location('host_trace_reader', ROOT/'scripts/dsa_pipeline_trace.py')
        cls.reader = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.reader)

    def run_case(self, mode):
        subprocess.run([str(self.binary), mode], cwd=self.temporary.name, check=True)

    def test_actual_wait_is_excluded_from_packaging_and_scan(self):
        self.run_case('exclusive')

    def test_off_does_not_read_clock_or_touch_trace_context(self):
        self.run_case('disabled')

    def test_zero_duration_phase_is_preserved_without_phantom_end_call(self):
        self.run_case('zero')

    def test_clock_failure_invalidates_capture(self):
        self.run_case('invalid')

    def test_backwards_clock_invalidates_capture(self):
        self.run_case('backwards')

    def test_overflow_preserves_prefix_and_continues_exclusive_totals(self):
        self.run_case('overflow')

    def test_production_c_binary_is_verified_by_python_reader_and_log(self):
        self.run_case('export')
        path = Path(self.temporary.name)/'host.bin'
        result = self.reader.validate(path)
        self.assertEqual((result['role'], result['scan_wall_ns'], result['records']), ('host', 150, 5))
        self.assertEqual(result['phases']['pack_publish'], dict(exclusive_ns=30, calls=1, fragments=2))
        log = ['DSA_HOST_TRACE_PROFILE: version=2 pid=42 clock_valid=1 scan_begin_ns=100 scan_end_ns=250']
        detail = 'DSA_SCAN_DETAIL_PROFILE: version=2 pid=42 clock_valid=1 total_ns=150 accounted_ns=150'
        for i, (name, value) in enumerate(result['phases'].items()):
            detail += f" {name}_ns={value['exclusive_ns']}"
            log.append(f"DSA_HOST_TRACE_PHASE_COUNTS: version=2 pid=42 phase={i} calls={value['calls']} segments={value['fragments']} exclusive_ns={value['exclusive_ns']}")
        log += [detail, 'DSA_HOST_TRACE_FILE: version=2 pid=42 records=5 dropped=0 complete=1']
        log_path = path.parent/'dump.log'
        log_path.write_text('\n'.join(log))
        self.assertTrue(self.reader.validate(path, log_path)['dump_log_verified'])
        log_path.write_text('\n'.join(log).replace('pack_publish_ns=30', 'pack_publish_ns=31'))
        with self.assertRaises(ValueError):
            self.reader.validate(path, log_path)

    def test_host_reader_rejects_truncation_and_incomplete_or_wrong_phase(self):
        self.run_case('export')
        path = Path(self.temporary.name)/'host.bin'
        original = path.read_bytes()
        path.write_bytes(original[:-1])
        with self.assertRaises(ValueError):
            self.reader.validate(path)
        fields = list(self.reader.HOST_HEADER_V2.unpack(original[:self.reader.HOST_HEADER_V2.size]))
        fields[7] = 1
        path.write_bytes(self.reader.HOST_HEADER_V2.pack(*fields)+original[self.reader.HOST_HEADER_V2.size:])
        with self.assertRaises(ValueError):
            self.reader.validate(path)
        invalid = bytearray(original)
        offset = self.reader.HOST_HEADER_V2.size
        invalid[offset:offset+self.reader.EVENT.size] = self.reader.EVENT.pack(100, 110, 1, 3, 0)
        path.write_bytes(invalid)
        with self.assertRaises(ValueError):
            self.reader.validate(path)


if __name__ == '__main__':
    unittest.main()
