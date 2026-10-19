#!/usr/bin/python3
"""Private-namespace launcher: constrain CRIU, never its protected application."""
import os
from pathlib import Path
import sys

executable = Path(os.environ['CDP_HOST_SCAN_EXECUTABLE']).resolve()
allowed = Path('/home/lbr/workspace/result-processed/20261015-host-scan-builds').resolve()
if executable.parent != allowed or executable.name not in ('baseline.criu', 'candidate-v3.criu'):
    raise SystemExit('Refusing an unregistered experimental CRIU executable')
os.sched_setaffinity(0, {18, 19, 20})
os.execv(str(executable), [str(executable), *sys.argv[1:]])
