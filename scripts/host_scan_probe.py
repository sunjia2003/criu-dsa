#!/usr/bin/env python3
"""Opt-in deterministic capture/restore probe; adapted from the archived memory probe."""
import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import signal
import struct
import subprocess
import time

LOCAL = Path(__file__).resolve().parent


def wait_state(path, kind, generation, timeout=30):
    deadline = time.monotonic()+timeout
    while time.monotonic() < deadline:
        try:
            value = json.loads(path.read_text())
            if value['kind'] == kind and value['generation'] == generation:
                return value
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        time.sleep(.01)
    raise TimeoutError(f'Expected {kind} generation={generation} in {path}')


def run_cli(args, argv, env, directory, kind):
    command = ['taskset', '-c', args.host_cpus, str(args.criu), *argv]
    begin = time.monotonic_ns()
    cpu_before = resource.getrusage(resource.RUSAGE_CHILDREN)
    with (args.output/f'{directory.name}-{kind}-console.log').open('w') as output:
        process = subprocess.run(command, env=env, stdout=output, stderr=subprocess.STDOUT, timeout=120)
    cpu_after = resource.getrusage(resource.RUSAGE_CHILDREN)
    return dict(argv=command, returncode=process.returncode, wall_ns=time.monotonic_ns()-begin,
                cli_family_user_cpu_s=cpu_after.ru_utime-cpu_before.ru_utime,
                cli_family_system_cpu_s=cpu_after.ru_stime-cpu_before.ru_stime)


def log_metrics(path):
    text = path.read_text()
    row = {}
    for marker in ('DSA_MEMDUMP_DETAIL', 'DSA_SCAN_HOST_PROFILE', 'DSA_GAP_PROFILE',
                   'DSA_COVERAGE_PROFILE', 'DSA_RANGE_PROFILE', 'DSA_STREAM_SUMMARY', 'DSA_HOST_SCAN', 'DSA_POST_THAW_PROFILE_TIME', 'DSA_POST_THAW_PROFILE_COUNT'):
        rows = [line for line in text.splitlines() if marker+':' in line]
        if len(rows) == 1:
            values = dict(re.findall(r'(\w+)=([^\s]+)', rows[0]))
            row[marker] = {key:int(value) if value.isdigit() else value for key, value in values.items()}
    for name, expression in (('frozen_us', r'Dumping finished successfully.*'),
                             ('freezing_us', r'Freezing time: (\d+) us')):
        match = re.search(expression, text)
        if match and match.lastindex:
            row[name] = int(match.group(1))
    timing = re.search(r'Dump timing: frozen=(\d+) us[^\n]*?memdump=(\d+) us[^\n]*?memwrite=(\d+) us', text)
    if timing:
        row.update(frozen_us=int(timing[1]), memdump_us=int(timing[2]), memwrite_us=int(timing[3]))
    return row


def probe_capture(directory, initial, checkpoint, args):
    """Read the actual fine sidecar, restricted to the deterministic probe VMA."""
    meta = struct.Struct('<QQIHH')
    base = initial['base']
    captured = set()
    for index in directory.glob('pages-fg-*.idx'):
        raw = index.read_bytes()
        if len(raw) % meta.size:
            raise ValueError('Truncated fine sidecar')
        for address, offset, count, patches, flags in meta.iter_unpack(raw):
            if base <= address < base + args.pages*4096:
                if address % 4096 or address in captured:
                    raise ValueError('Invalid/duplicate captured probe address')
                captured.add(address)
    required = set(range(args.pages)) if checkpoint == 1 else {
        page for page in range(args.pages) if args.dirty_run and
        page % (args.dirty_run+args.clean_gap) < args.dirty_run}
    if initial.get('layout') == 'unmapped':
        required.discard(initial['excluded_page'])
    if initial.get('layout') == 'protected':
        # Non-readable memory is captured without parent reuse on every dump.
        required.add(initial['excluded_page'])
    observed = {(address-base)//4096 for address in captured}
    if not required <= observed:
        raise ValueError('Capture omitted a deterministic dirty probe page')
    promoted = observed-required
    if checkpoint > 1:
        for page in promoted:
            if not args.gap_max or not args.dirty_run or args.clean_gap > args.gap_max:
                raise ValueError('Unexpected clean probe capture')
            left = page//(args.dirty_run+args.clean_gap)*(args.dirty_run+args.clean_gap)+args.dirty_run-1
            right = left+args.clean_gap+1
            if left not in required or right not in required:
                raise ValueError('Promoted page not between required captures')
    return dict(required_pages=len(required), captured_pages=len(observed), promoted_pages=len(promoted),
                captured_bytes=len(observed)*4096)


def run(args):
    if os.geteuid() != 0:
        raise ValueError('Run via sudo; credentials never stored in the study')
    args.output.mkdir(parents=True, exist_ok=False)
    hot = args.output/'hot'
    hot.mkdir()
    env = os.environ.copy()
    env.update(CRIU_DSA_DUMP='1', CRIU_DSA_DESC_SCAN='1', CRIU_DSA_FINE_GRAINED='1',
               CRIU_DSA_KEEP_FAILED_IMAGES='1',
               CRIU_DSA_HOT_APPLY='1', CRIU_DSA_HOT_MODE='memstore',
               CRIU_DSA_HOT_ROOT=str(hot), CRIU_DSA_HOT_MANIFEST=str(hot/'extents.log'),
               CRIU_DSA_HOT_MEMORY_MANIFEST=str(hot/'memory.json'),
               CRIU_DSA_HOT_MEMORY_NEXT=str(hot/'memory-next.json'),
               CRIU_DSA_OUTPUT_FORMAT='fine', CRIU_DSA_OUTPUT_IO='direct-sync',
               CRIU_DSA_FG_COMPARE_BACKEND=args.backend,
               CRIU_DSA_PROFILE='1' if args.diagnostics in ('profile', 'full') else '0',
               CRIU_DSA_DEBUG='1' if args.diagnostics == 'full' else '0',
               CRIU_DSA_SCAN_PROFILE='1' if args.diagnostics == 'full' else '0',
               CRIU_DSA_GAP_MAX_PAGES=str(args.gap_max), CRIU_DSA_COVERAGE_CURSOR=str(args.cursor),
               CRIU_DSA_RANGE_SCAN=str(getattr(args, 'range_scan', 0)),
               CRIU_DSA_STREAM_SUMMARY='1' if getattr(args,'summary',False) else '0')
    if getattr(args,'legacy_pagemap',False):env['CRIU_FAULT']='135'
    manifest = dict(parameters=vars(args), environment={key:value for key, value in env.items()
                    if key.startswith('CRIU_DSA_') or key=='CRIU_FAULT'}, criu_sha256=hashlib.sha256(args.criu.read_bytes()).hexdigest(),
                    probe_sha256=hashlib.sha256((LOCAL/'host_scan_fixture').read_bytes()).hexdigest(),
                    checkpoints=[], started=time.strftime('%Y-%m-%d %H:%M:%S'), state='RUNNING')
    manifest['parameters'] = {key:str(value) if isinstance(value, Path) else value for key, value in vars(args).items()}
    state_file = args.output/'probe-state.json'
    process = subprocess.Popen(['taskset', '-c', '1', str(LOCAL/'host_scan_fixture'), str(args.pages),
                                str(args.dirty_run), str(args.clean_gap), str(state_file),
                                getattr(args,'layout','dense')],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    restored_pid = None
    try:
        manifest['initial_state'] = wait_state(state_file, 'READY', 0)
        env['CRIU_DSA_PROFILE_IMG_ID'] = str(process.pid)
        env['CRIU_DSA_MEMORY_SERVICE_IMG_ID'] = str(process.pid)
        for checkpoint in range(1, args.checkpoints+1):
            if checkpoint > 1:
                process.send_signal(signal.SIGUSR1)
                wait_state(state_file, 'MUTATED', checkpoint-1)
            directory = args.output/f'cp-{checkpoint}'
            directory.mkdir()
            dump_log = args.output/f'cp-{checkpoint}.dump.log'
            argv = ['dump', '-t', str(process.pid), '-D', str(directory), '-o', str(dump_log),
                    '-v4' if args.diagnostics == 'full' else '-v3', '-R', '--track-mem', '--shell-job']
            if checkpoint > 1:
                argv.extend(['--prev-images-dir', '../cp-'+str(checkpoint-1)])
            run_record = run_cli(args, argv, env, directory, 'dump')
            run_record.update(checkpoint=checkpoint, generation=checkpoint-1, metrics=log_metrics(dump_log))
            if run_record['returncode'] == 0:
                for name in ('memdump_timeline', 'frozen_timeline'):
                    records = list(csv.DictReader((directory/f'{name}.csv').open()))
                    if len(records) != 1 or records[0]['ret'] != '0':
                        raise ValueError('Invalid successful checkpoint timeline: '+str(directory))
                    run_record['metrics'][name] = {key:int(value) if value.lstrip('-').isdigit() else value
                                                  for key, value in records[0].items()}
                run_record['probe_capture'] = probe_capture(directory, manifest['initial_state'], checkpoint, args)
            manifest['checkpoints'].append(run_record)
            (args.output/'manifest.json').write_text(json.dumps(manifest, indent=2))
            if run_record['returncode']:
                raise RuntimeError('Checkpoint failed: '+str(dump_log))
            os.replace(hot/'memory-next.json', hot/'memory.json')
        if args.restore:
            process.terminate()
            process.wait(timeout=10)
            directory = args.output/f'cp-{args.checkpoints}'
            pidfile = args.output/'restored.pid'
            restore_log = args.output/'restore.log'
            argv = ['restore', '-D', str(directory), '-o', str(restore_log), '-v3', '-d',
                    '--shell-job', '--pidfile', str(pidfile)]
            record = run_cli(args, argv, env, directory, 'restore')
            manifest['restore'] = record
            if record['returncode']:
                raise RuntimeError('Restore failed: '+str(restore_log))
            restored_pid = int(pidfile.read_text())
            os.kill(restored_pid, signal.SIGUSR2)
            manifest['restored_state'] = wait_state(state_file, 'VERIFIED', args.checkpoints-1)
            if manifest['restored_state']['errors'] != 0:
                raise RuntimeError('Restored bytes differ from deterministic reference')
            manifest['external_verification'] = verify_external(restored_pid, manifest['initial_state'], args)
        else:
            process.send_signal(signal.SIGUSR2)
            manifest['original_state'] = wait_state(state_file, 'VERIFIED', args.checkpoints-1)
            if manifest['original_state']['errors']:
                raise RuntimeError('Capture modified live target bytes')
        manifest['state'] = 'PASSED'
    except BaseException as error:
        manifest['state'] = 'FAILED'
        manifest['error'] = str(error)
        raise
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=10)
        if restored_pid is not None:
            try:
                os.kill(restored_pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        manifest['ended'] = time.strftime('%Y-%m-%d %H:%M:%S')
        (args.output/'manifest.json').write_text(json.dumps(manifest, indent=2))
        for directory, subdirs, files in os.walk(args.output):
            os.chmod(directory, 0o755)
            for name in files:
                path = Path(directory)/name
                os.chmod(path, 0o644)
                # Only this finished trial's large files, and only after all
                # checkpoints/restore: keep disk evidence without cache buildup.
                if path.is_file() and path.stat().st_size >= 1048576:
                    fd = os.open(path, os.O_RDONLY|os.O_CLOEXEC)
                    try:
                        os.fsync(fd)
                        os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
                    finally:
                        os.close(fd)


def verify_external(pid, initial, args):
    """Read restored bytes with an out-of-process oracle and requested generation."""
    import numpy as np
    errors = checked = 0
    excluded = initial.get('excluded_page', -1)
    with open(f'/proc/{pid}/mem', 'rb', buffering=0) as memory:
        for first in range(0, args.pages, 64):
            count = min(64, args.pages-first)
            pages = np.arange(first, first+count, dtype=np.uint64)
            dirty = (pages % (args.dirty_run+args.clean_gap) < args.dirty_run) & (pages != excluded)
            generation = dirty.astype(np.uint64) * np.uint64(args.checkpoints-1)
            with np.errstate(over='ignore'):
                values = ((pages[:, None]+np.uint64(1))*np.uint64(0x9e3779b97f4a7c15) +
                          np.arange(4096, dtype=np.uint64)[None, :]*np.uint64(0xd1b54a32d192ed03) +
                          generation[:, None]*np.uint64(0x94d049bb133111eb))
                values ^= values >> 33
                values *= np.uint64(0xff51afd7ed558ccd)
                wanted = (values >> 32).astype(np.uint8)
            for offset in range(count):
                page = first+offset
                if initial.get('layout') == 'unmapped' and page == excluded: continue
                memory.seek(initial['base']+page*4096)
                actual = memory.read(4096)
                if len(actual) != 4096: raise RuntimeError('Short restored-memory read')
                errors += int(np.count_nonzero(np.frombuffer(actual, dtype=np.uint8) != wanted[offset]))
                checked += 4096
    if errors: raise RuntimeError(f'External restore oracle found {errors} byte errors')
    return dict(checked_bytes=checked, byte_errors=errors, expected_generation=args.checkpoints-1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true')
    parser.add_argument('--host-cpus', default='18-20')
    parser.add_argument('--criu', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--pages', type=int, default=16384)
    parser.add_argument('--dirty-run', type=int, default=2)
    parser.add_argument('--clean-gap', type=int, default=1)
    parser.add_argument('--gap-max', type=int, default=0)
    parser.add_argument('--cursor', type=int, default=0)
    parser.add_argument('--range-scan', type=int, choices=(0,1), default=0)
    parser.add_argument('--layout', choices=('dense','unmapped','protected'), default='dense')
    parser.add_argument('--legacy-pagemap', action='store_true')
    parser.add_argument('--summary', action='store_true')
    parser.add_argument('--diagnostics', choices=('off', 'profile', 'full'), default='off')
    parser.add_argument('--backend', choices=('dsa', 'validate', 'memcmp'), default='dsa')
    parser.add_argument('--checkpoints', type=int, default=3)
    parser.add_argument('--restore', action='store_true')
    args = parser.parse_args()
    if not args.run: parser.error('--run is required')
    args.criu = args.criu.resolve()
    args.output = args.output.resolve()
    run(args)


if __name__ == '__main__':
    main()
