#!/usr/bin/env python3
"""Validate full-only exclusive software intervals; never infer missing events.

This file is a chronology reader, not a benchmark runner or device-busy tracer.
Use iter_events() to plot observed (start_ns, end_ns, occurrence, phase, flags).
"""
import argparse
import json
from pathlib import Path
import re
import struct

MAGIC = 0x44535054
HEADER = struct.Struct('<4I22Q4I')
HOST_MAGIC = 0x44534854
HOST_HEADER = struct.Struct('<4I55Q4I')
HOST_HEADER_V2 = struct.Struct('<4I13Q4I')
EVENT = struct.Struct('<3Q2I')
PHASES = ('control', 'poll_scan', 'accept', 'prepare', 'submit', 'harvest')
PHASES_V2 = ('background_check', 'reserved_poll', 'accept_batch', 'prepare', 'submit', 'harvest')
HOST_PHASES_V2 = ('scan_organize', 'pack_publish', 'slot_wait')
HOST_PHASES = ('control', 'vma_prepare', 'pagemap_read', 'shmem_metadata', 'page_select',
               'lazy_stack', 'parent_coverage', 'hole_metadata', 'page_metadata',
               'raw_tracking', 'desc_append', 'slot_wait', 'desc_sum', 'desc_copy',
               'slot_publish', 'flush_control', 'scan_logging')
RESUMED = 1
COMPLETE = 1


def read_header(path):
    with Path(path).open('rb') as stream:
        prefix = stream.read(16)
        if len(prefix) != 16:
            raise ValueError('Truncated pipeline trace header')
        magic, version, _, _ = struct.unpack('<4I', prefix)
        if magic not in (MAGIC, HOST_MAGIC) or version not in (1, 2):
            raise ValueError('Unsupported pipeline trace magic/version')
        if magic == HOST_MAGIC:
            layout, phases, role = ((HOST_HEADER, HOST_PHASES, 'host') if version == 1
                                    else (HOST_HEADER_V2, HOST_PHASES_V2, 'host'))
        else:
            layout, phases, role = HEADER, PHASES if version == 1 else PHASES_V2, 'parasite'
        data = prefix + stream.read(layout.size-16)
    if len(data) != layout.size:
        raise ValueError('Truncated pipeline trace header')
    fields = layout.unpack(data)
    if fields[:4] != (magic, version, layout.size, EVENT.size):
        raise ValueError('Unsupported pipeline trace magic/version/layout/endianness')
    n = len(phases)
    return dict(begin_ns=fields[4], end_ns=fields[5], count=fields[6], dropped=fields[7],
                phase_ns=fields[8:8+n], calls=fields[8+n:8+2*n], segments=fields[8+2*n:8+3*n],
                pid=fields[8+3*n], clock_valid=fields[9+3*n], capacity=fields[10+3*n],
                flags=fields[11+3*n], role=role, phases=phases, header_bytes=layout.size,
                version=version)


def iter_events(path):
    """Stream fixed-size records without building millions of Python objects."""
    with Path(path).open('rb') as stream:
        stream.seek(read_header(path)['header_bytes'])
        while True:
            data = stream.read(EVENT.size*32768)
            if not data:
                return
            if len(data) % EVENT.size:
                raise ValueError('Truncated pipeline event')
            yield from EVENT.iter_unpack(data)


def validate(path, dump_log=None):
    path = Path(path)
    h = read_header(path)
    if not h['pid'] or h['clock_valid'] != 1 or h['flags'] != COMPLETE or h['dropped']:
        raise ValueError('Incomplete, dropped or invalid-clock trace; no full timeline can be claimed')
    if not h['begin_ns'] or h['end_ns'] < h['begin_ns'] or not 0 < h['count'] <= h['capacity']:
        raise ValueError('Invalid consumer window or record capacity')
    if path.stat().st_size != h['header_bytes'] + h['count']*EVENT.size:
        raise ValueError('File size does not match declared record count')
    names = h['phases']
    totals, calls, segments = [0]*len(names), [0]*len(names), [0]*len(names)
    # One byte per invocation is enough to verify resumed phase identity.
    # An occurrence first appears in increasing order; a resume reuses it.
    occurrence_phases = bytearray()
    last = h['begin_ns']
    seen = 0
    for start, end, occurrence, phase, flags in iter_events(path):
        if phase >= len(names) or flags not in (0, RESUMED) or not occurrence:
            raise ValueError('Invalid phase/flags/occurrence')
        if h['version'] == 2 and h['role'] == 'parasite' and phase == 1:
            raise ValueError('Reserved poll phase must not contain v2 events')
        if start != last or end < start or end > h['end_ns']:
            raise ValueError('Missing, overlapping, backwards or out-of-window interval')
        if occurrence == len(occurrence_phases)+1:
            if flags:
                raise ValueError('Resumed invocation was never observed')
            occurrence_phases.append(phase)
            calls[phase] += 1
        elif occurrence <= len(occurrence_phases):
            if occurrence_phases[occurrence-1] != phase or not flags:
                raise ValueError('Resumed invocation changed phase or lacks resume flag')
        else:
            raise ValueError('Missing invocation identifiers')
        totals[phase] += end-start
        segments[phase] += 1
        last = end
        seen += 1
    if seen != h['count'] or last != h['end_ns']:
        raise ValueError('Consumer chronology is incomplete')
    if tuple(totals) != h['phase_ns'] or sum(totals) != h['end_ns']-h['begin_ns']:
        raise ValueError('Trace durations do not reproduce exclusive counters')
    if tuple(calls) != h['calls'] or tuple(segments) != h['segments']:
        raise ValueError('Trace invocation/fragment counts do not match counters')
    result = dict(pid=h['pid'], complete=True, records=seen, role=h['role'], version=h['version'],
                  phases={name:dict(exclusive_ns=totals[i], calls=calls[i], fragments=segments[i])
                          for i, name in enumerate(names)})
    if h['version'] == 2 and h['role'] == 'parasite':
        result['phases']['reserved_poll']['collected'] = False
        result['phases']['reserved_poll']['merged_into'] = 'background_check'
    prefix = 'scan' if h['role'] == 'host' else 'consumer'
    result.update({prefix+'_begin_ns':h['begin_ns'], prefix+'_end_ns':h['end_ns'],
                   prefix+'_wall_ns':last-h['begin_ns']})
    if dump_log is not None:
        verify_log(result, Path(dump_log).read_text())
        result['dump_log_verified'] = True
    return result


def verify_log(result, text):
    def rows(marker):
        parsed = [dict((key, int(value)) for key, value in re.findall(r'(\w+)=(\d+)', line))
                  for line in text.splitlines() if marker+':' in line]
        return [row for row in parsed if row.get('pid') == result['pid']]
    if result['role'] == 'host':
        profiles = rows('DSA_HOST_TRACE_PROFILE')
        detail = rows('DSA_SCAN_DETAIL_PROFILE')
        if len(profiles) != 1 or len(detail) != 1:
            raise ValueError('Expected one Host trace and scan-detail profile for trace PID')
        p, d = profiles[0], detail[0]
        if p.get('version') != result['version'] or p.get('clock_valid') != 1 or any(
                p.get(key) != result[key] for key in ('scan_begin_ns', 'scan_end_ns')):
            raise ValueError('Host trace and log scan window/clock/version differ')
        if d.get('clock_valid') != 1 or d.get('total_ns') != result['scan_wall_ns'] or d.get('accounted_ns') != result['scan_wall_ns']:
            raise ValueError('Host scan-detail ledger does not close')
        counts = rows('DSA_HOST_TRACE_PHASE_COUNTS')
        names = tuple(result['phases'])
        if len(counts) != len(names) or {row.get('phase') for row in counts} != set(range(len(names))):
            raise ValueError('Missing or duplicate Host phase-count rows')
        for row in counts:
            name = names[row['phase']]
            phase = result['phases'][name]
            if d.get(name+'_ns') != phase['exclusive_ns'] or any(
                    row.get(source) != phase[target] for source, target in
                    (('calls', 'calls'), ('segments', 'fragments'), ('exclusive_ns', 'exclusive_ns'))):
                raise ValueError('Host trace and log per-phase counters differ')
        files = rows('DSA_HOST_TRACE_FILE')
        if len(files) != 1 or files[0].get('complete') != 1 or files[0].get('dropped') != 0 or files[0].get('records') != result['records']:
            raise ValueError('Missing or inconsistent Host trace-file record')
        return
    profiles = rows('DSA_PIPELINE_PROFILE')
    if len(profiles) != 1:
        raise ValueError('Expected one aggregate profile for trace PID')
    p = profiles[0]
    if p.get('version') != result['version']+1 or p.get('clock_valid') != 1 or any(
            p.get(key) != result[key] for key in ('consumer_begin_ns', 'consumer_end_ns')):
        raise ValueError('Trace and log lifecycle/clock/version differ')
    counts = rows('DSA_PIPELINE_PHASE_COUNTS')
    if len(counts) != 6 or {row.get('phase') for row in counts} != set(range(6)):
        raise ValueError('Missing or duplicate phase-count log rows')
    names = tuple(result['phases'])
    for row in counts:
        phase = result['phases'][names[row['phase']]]
        key = 'submit_call_ns' if row['phase'] == 4 else names[row['phase']]+'_ns'
        if p.get(key) != phase['exclusive_ns'] or any(
                row.get(source) != phase[target] for source, target in
                (('calls', 'calls'), ('segments', 'fragments'), ('exclusive_ns', 'exclusive_ns'))):
            raise ValueError('Trace and log per-phase counters differ')
    files = rows('DSA_PIPELINE_TRACE_FILE')
    if len(files) != 1 or files[0].get('complete') != 1 or files[0].get('dropped') != 0 or files[0].get('records') != result['records']:
        raise ValueError('Missing or inconsistent successful trace-file log record')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('trace', type=Path)
    parser.add_argument('--dump-log', type=Path, help='Also verify the matching PID, lifecycle, six counters and exported-file marker')
    args = parser.parse_args()
    try:
        result = validate(args.trace, args.dump_log)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
