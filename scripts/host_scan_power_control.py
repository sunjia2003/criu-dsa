#!/usr/bin/env python3
"""Temporarily control the three authorized CPU policies and restore their state."""
import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys

CPUS = (18, 19, 20)
FIELDS = ('scaling_driver', 'scaling_governor', 'energy_performance_preference',
          'scaling_min_freq', 'scaling_max_freq', 'related_cpus')


def now():
    return datetime.now().astimezone().isoformat()


def snapshot():
    return {str(cpu): {field: (Path(f'/sys/devices/system/cpu/cpu{cpu}/cpufreq')/field)
                             .read_text().strip() for field in FIELDS} for cpu in CPUS}


def write_record(path, value):
    path.write_text(json.dumps(value, indent=2)+'\n')


def root_action(action, state_path):
    if os.geteuid() != 0:
        raise RuntimeError('CPU policy changes require the privileged helper')
    original = json.loads(state_path.read_text())
    if set(original) != {str(cpu) for cpu in CPUS}:
        raise ValueError('Only CPU18, CPU19 and CPU20 are authorized')
    errors = []
    for cpu in CPUS:
        directory = Path(f'/sys/devices/system/cpu/cpu{cpu}/cpufreq')
        try:
            governor = 'performance' if action == 'performance' else original[str(cpu)]['scaling_governor']
            available = (directory/'scaling_available_governors').read_text().split()
            if governor not in available:
                raise ValueError('Unavailable governor: '+governor)
            (directory/'scaling_governor').write_text(governor)
            if action == 'restore':
                preference = original[str(cpu)]['energy_performance_preference']
                available = (directory/'energy_performance_available_preferences').read_text().split()
                if preference not in available:
                    raise ValueError('Unavailable energy preference: '+preference)
                current = (directory/'energy_performance_preference').read_text().strip()
                if current != preference:
                    (directory/'energy_performance_preference').write_text(preference)
        except Exception as error:
            errors.append(f'CPU{cpu}: {error}')
    if errors:
        raise RuntimeError('; '.join(errors))


def privileged(action, state_path):
    subprocess.run(['sudo', '-A', sys.executable, str(Path(__file__).resolve()),
                    '--root-action', action, '--state', str(state_path)],
                   check=True, timeout=30)


def terminate_child(child):
    if child is None or child.poll() is not None:
        return
    # The task-specific process group contains root namespace helpers, too.
    subprocess.run(['sudo', '-A', 'kill', '-TERM', '--', '-'+str(child.pid)],
                   check=False, timeout=10)
    try:
        child.wait(timeout=20)
    except subprocess.TimeoutExpired:
        subprocess.run(['sudo', '-A', 'kill', '-KILL', '--', '-'+str(child.pid)],
                       check=False, timeout=10)
        child.wait(timeout=10)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true')
    parser.add_argument('--smoke-test', action='store_true')
    parser.add_argument('--plan', type=Path)
    parser.add_argument('--record-dir', type=Path)
    parser.add_argument('--root-action', choices=('performance', 'restore'))
    parser.add_argument('--state', type=Path)
    args = parser.parse_args()
    if args.root_action:
        if not args.state:
            parser.error('--state is required')
        root_action(args.root_action, args.state)
        return
    if not args.run or args.record_dir is None:
        parser.error('--run and --record-dir are required')
    if os.geteuid() == 0:
        parser.error('Run the controller as the normal research user')
    if not args.smoke_test and args.plan is None:
        parser.error('--plan is required unless --smoke-test')
    if args.plan:
        args.plan = args.plan.resolve(strict=True)
    args.record_dir = args.record_dir.resolve()
    args.record_dir.mkdir(parents=True, exist_ok=False)
    state_path = args.record_dir/'before.json'
    before = snapshot()
    write_record(state_path, before)
    record = {'started_at':now(), 'authorized_cpus':list(CPUS), 'before':before,
              'smoke_test':args.smoke_test,
              'plan':str(args.plan) if args.plan else None,
              'plan_sha256':hashlib.sha256(args.plan.read_bytes()).hexdigest() if args.plan else None,
              'controller_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'restored':False}
    record_path = args.record_dir/'power-control.json'
    write_record(record_path, record)
    child = None
    failure = None

    def interrupted(signum, frame):
        raise KeyboardInterrupt(f'Received signal {signum}')

    previous = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        privileged('performance', state_path)
        record['active'] = snapshot()
        record['activated_at'] = now()
        for cpu in CPUS:
            state = record['active'][str(cpu)]
            if state['scaling_governor'] != 'performance':
                raise RuntimeError(f'CPU{cpu} governor did not switch')
            for field in ('scaling_min_freq', 'scaling_max_freq', 'scaling_driver', 'related_cpus'):
                if state[field] != before[str(cpu)][field]:
                    raise RuntimeError(f'CPU{cpu}: unexpected change to {field}')
        write_record(record_path, record)
        print('PERFORMANCE active on CPU18-20', flush=True)
        if not args.smoke_test:
            command = [sys.executable, str(Path(__file__).with_name('host_scan_suite.py')),
                       '--run', '--plan', str(args.plan), '--record-dir', str(args.record_dir/'suites')]
            record['suite_argv'] = command
            write_record(record_path, record)
            child = subprocess.Popen(command, start_new_session=True)
            record['suite_returncode'] = child.wait()
            if record['suite_returncode']:
                raise RuntimeError('Suite runner failed')
        record['before_restore'] = snapshot()
        if record['before_restore'] != record['active']:
            raise RuntimeError('CPU policies changed during controlled experiment')
    except BaseException as error:
        failure = error
        record['error'] = str(error)
    finally:
        # Do not allow a repeated interrupt to skip the restoration attempt.
        for sig in previous:
            signal.signal(sig, signal.SIG_IGN)
        try:
            terminate_child(child)
        except Exception as error:
            record['child_cleanup_error'] = str(error)
        try:
            privileged('restore', state_path)
        except Exception as error:
            record['restore_error'] = str(error)
        try:
            record['after'] = snapshot()
            record['restored'] = record['after'] == before
        except Exception as error:
            record['restore_verification_error'] = str(error)
        record['ended_at'] = now()
        write_record(record_path, record)
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        print('RESTORED '+str(record['restored'])+'; '+str(record_path), flush=True)
    if not record['restored']:
        raise RuntimeError('CPU policy restoration is incomplete; inspect '+str(record_path))
    if failure:
        raise failure


if __name__ == '__main__':
    main()
