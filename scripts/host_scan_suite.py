#!/usr/bin/env python3
"""Run an explicit ABBA suite plan with a private DSA checkout mount."""
import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true')
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--record-dir', type=Path, required=True)
    args = parser.parse_args()
    if not args.run: parser.error('--run is required')
    if os.geteuid() == 0: parser.error('Run as the normal research user')
    plan = json.loads(args.plan.read_text())
    args.record_dir.mkdir(parents=True, exist_ok=False)
    cdp = Path('/home/lbr/workspace/cdp')
    record = {'plan': plan, 'plan_sha256': hashlib.sha256(args.plan.read_bytes()).hexdigest(),
              'started_at': datetime.now().astimezone().isoformat(), 'runs': []}
    body = 'set -e\nmount --make-rprivate /\nmount --bind "$1" "$2"\nshift 2\nexec sudo -u lbr taskset -c 18-20 env "$@"'
    host_only = plan.get('host_only_affinity', False)
    launcher = Path(__file__).with_name('host_scan_criu' if plan.get('native_launcher') else 'host_scan_criu.py')
    if host_only:
        body = 'set -e\nmount --make-rprivate /\nmount --bind "$1" "$2"\nmount --bind "$3" "$2/criu/criu"\nshift 3\nexec sudo -u lbr env "$@"'
    for case in plan['cases']:
        source = Path(case['source']).resolve()
        root = Path('/home/lbr/workspace/result-rawdata')/case['id']
        storage = Path(plan.get('storage_root', '/mnt/gen3/cdp-host-scan-20261015/result-rawdata'))/case['id']
        assignments = {'CDP_BENCHMARK_RUN_ID': case['id'],
                       'CDP_BENCHMARK_BACKUP_ROOT': str(storage/'checkpoints'),
                       'CDP_REDIS_CACHE_MODE': 'auto', 'CDP_HNSWLIB_CACHE_MODE': 'auto',
                       'CRIU_DSA_HOST_SCAN_THREADS': str(case['workers']),
                       'CRIU_DSA_HOST_SCAN_BLOCK_BYTES': str(case.get('block_bytes', 33554432)),
                       'CRIU_DSA_HOST_SCAN_SPIN': str(case.get('spin', 0)),
                       'CRIU_DSA_HOST_SCAN_TIMING': str(case.get('timing', 0)),
                       'CRIU_DSA_HOST_SCAN_CROSS_VMA': str(case.get('cross_vma', 0)),
                       'CRIU_DSA_HOST_SCAN_PREFETCH_DEPTH': str(case.get('prefetch_depth', 0)),
                       'CRIU_DSA_HOST_SCAN_MAIN_CPU': str(case.get('main_cpu', '')),
                       'CRIU_DSA_HOST_SCAN_WORKER_CPUS': str(case.get('worker_cpus', '')),
                       'CRIU_DSA_HOST_SCAN_PREFETCH_SPIN_LIMIT': str(case.get('spin_limit', 4096)),
                       'CRIU_DSA_HOST_SCAN_PERF': str(case.get('perf', 0)),
                       'CRIU_DSA_STREAM_SUMMARY': '1',
                       'SUDO_ASKPASS': '/tmp/cdp_sudo_askpass.sh'}
        executable = Path(case.get('executable', source/'criu/criu'))
        if host_only:
            assignments['CDP_HOST_SCAN_EXECUTABLE'] = str(executable)
        command = ['sudo', '-A', 'unshare', '--mount', '--fork', 'bash', '-c', body, 'host-scan-suite',
                   str(source), str(cdp/'thirdparty/criu-dsa'),
                   *([str(launcher)] if host_only else []),
                   *[f'{k}={v}' for k,v in assignments.items()], 'python3', str(cdp/'runtest.py'),
                   '--workloads', plan.get('workload', 'all'), '--interval', '1', '--max-backups', '10',
                   '--repeats', '1', '--diagnostics', 'off']
        entry = {'id': case['id'], 'argv': command, 'source': str(source),
                 'binary_sha256': hashlib.sha256(executable.read_bytes()).hexdigest(),
                 'actual_executable': str(executable), 'host_only_affinity': host_only,
                 'launcher_sha256': hashlib.sha256(launcher.read_bytes()).hexdigest() if host_only else None,
                 'started_at': datetime.now().astimezone().isoformat()}
        record['runs'].append(entry)
        (args.record_dir/'runs.json').write_text(json.dumps(record, indent=2))
        print('RUN '+case['id'], flush=True)
        with (args.record_dir/(case['id']+'.log')).open('w') as log:
            completed = subprocess.run(command, cwd=cdp, env=os.environ.copy(), stdout=log, stderr=subprocess.STDOUT)
        entry.update(returncode=completed.returncode, ended_at=datetime.now().astimezone().isoformat())
        (args.record_dir/'runs.json').write_text(json.dumps(record, indent=2))
        if completed.returncode: raise RuntimeError('Suite failed; retained logs: '+case['id'])
        # Transfer only this completed suite's hot data, outside measurements.
        hot = Path('/dev/shm')/('cdp-hot-lbr-'+case['id'])
        if hot.is_dir() and not hot.is_symlink():
            destination = storage/'hot-preserved'
            if destination.exists(): raise RuntimeError('Refusing to overwrite hot archive')
            subprocess.run(['sudo', '-A', 'mv', '--', str(hot), str(destination)], check=True)
            hot.symlink_to(destination, target_is_directory=True)
        entry['hot_archive'] = str(storage/'hot-preserved')
        (args.record_dir/'runs.json').write_text(json.dumps(record, indent=2))
        print('PASSED '+case['id'], flush=True)


if __name__ == '__main__': main()
