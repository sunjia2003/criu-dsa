#!/usr/bin/env python3
"""Execute an explicit, previously saved probe plan; no implicit experiments."""
import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
from types import SimpleNamespace

import host_scan_probe as probe


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true')
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not args.run: parser.error('--run is required')
    if os.geteuid() != 0: parser.error('Explicit privileged execution is required')
    args.output = args.output.resolve()
    plan = json.loads(args.plan.read_text())
    args.output.mkdir(parents=True, exist_ok=False)
    root = Path(__file__).resolve().parents[1]
    files = ['criu/mem.c', 'criu/include/dsa-host-scan.h', 'scripts/host_scan_fixture.c',
             'scripts/host_scan_fixture', 'scripts/host_scan_probe.py', 'scripts/host_scan_matrix.py']
    for header in ('dsa-host-prefetch.h', 'dsa-host-perf.h'):
        name = 'criu/include/'+header
        if (root/name).exists():
            files.append(name)
    provenance = {
        'base': subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip(),
        'status': subprocess.check_output(['git', '-C', str(root), 'status', '--porcelain'], text=True),
        'source_sha256': {f: hashlib.sha256((root/f).read_bytes()).hexdigest() for f in files},
        'plan_sha256': hashlib.sha256(args.plan.read_bytes()).hexdigest(),
        'allowed_host_cpus': plan.get('host_cpus', '18-20'),
        'started_at': datetime.now().astimezone().isoformat(), 'plan': plan, 'results': [],
    }
    provenance['build_sources'] = []
    for build in plan.get('build_sources', []):
        source = Path(build['root'])
        executable = Path(build['executable'])
        provenance['build_sources'].append({**build,
            'executable_sha256': hashlib.sha256(executable.read_bytes()).hexdigest(),
            'source_sha256': {name:hashlib.sha256((source/name).read_bytes()).hexdigest()
                              for name in build['files']}})
    output = args.output/'batch.json'
    output.write_text(json.dumps(provenance, indent=2))
    for case in plan['cases']:
        options = dict(run=True, pages=65536, dirty_run=1, clean_gap=1, gap_max=0, cursor=0,
                       range_scan=0, layout='dense', legacy_pagemap=False, diagnostics='off', backend='dsa',
                       checkpoints=3, summary=True, restore=True, host_cpus=plan.get('host_cpus', '18-20'))
        options.update(case.get('options', {}))
        options.update(criu=Path(case['criu']).resolve(), output=(args.output/case['name']).resolve())
        environment = {'CRIU_DSA_HOST_SCAN_THREADS': str(case['workers']), **case.get('environment', {})}
        before = {key: os.environ.get(key) for key in environment}
        os.environ.update(environment)
        start = time.monotonic()
        print('RUN '+case['name'], flush=True)
        try:
            probe.run(SimpleNamespace(**options))
            manifest = json.loads((options['output']/'manifest.json').read_text())
            provenance['results'].append({'case': case['name'], 'state': 'PASSED',
                'seconds': time.monotonic()-start,
                'restored_byte_errors': manifest.get('restored_state', {}).get('errors'),
                'external_byte_errors': manifest.get('external_verification', {}).get('byte_errors'),
                'external_checked_bytes': manifest.get('external_verification', {}).get('checked_bytes')})
        except BaseException as error:
            provenance['results'].append({'case': case['name'], 'state': 'FAILED', 'error': str(error)})
            raise
        finally:
            for key, value in before.items():
                if value is None: os.environ.pop(key, None)
                else: os.environ[key] = value
            output.write_text(json.dumps(provenance, indent=2))
    provenance['ended_at'] = datetime.now().astimezone().isoformat()
    output.write_text(json.dumps(provenance, indent=2))


if __name__ == '__main__': main()
