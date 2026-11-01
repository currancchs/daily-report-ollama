#!/usr/bin/env python3
"""Run one installed component with non-secret config loaded without shell evaluation."""
import os
from pathlib import Path
import re
import subprocess
import sys

source = Path(__file__).resolve().parent
if (source.parent/'src').is_dir(): source = source.parent/'src'
if len(sys.argv) < 2 or sys.argv[1] not in {p.stem for p in source.glob('*.py')}:
    raise SystemExit('Usage: run.py COMPONENT [arguments]; component must be in src/')
environment = os.environ.copy()
config = Path(environment.get('AI_MONITOR_ENV_FILE', '/etc/ai-monitor/monitor.env'))
if config.exists():
    for number, line in enumerate(config.read_text(encoding='utf-8').splitlines(), 1):
        line = line.strip()
        if not line or line.startswith('#'): continue
        key, sep, value = line.partition('=')
        if not sep or not re.fullmatch(r'AI_MONITOR_[A-Z_]+', key):
            raise SystemExit(f'Invalid setting at line {number}')
        environment[key] = value.strip()
raise SystemExit(subprocess.call([sys.executable, '-I', str(source/(sys.argv[1]+'.py')), *sys.argv[2:]], env=environment))
