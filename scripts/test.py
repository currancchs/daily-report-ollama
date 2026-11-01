#!/usr/bin/env python3
"""Run offline regression programs, failing on the first error. No real AI/email."""
from pathlib import Path
import os
import subprocess
import sys
root=Path(__file__).resolve().parent.parent
(root/'work').mkdir(exist_ok=True)
env={k:v for k,v in os.environ.items() if not k.startswith('AI_MONITOR_')}
env.update(PYTHONUTF8='1', AI_MONITOR_WAKE_MAC='02:00:00:00:00:01', AI_MONITOR_WAKE_BROADCAST='192.0.2.255')
files=sorted((root/'tests').glob('test_*.py'))
files.sort(key=lambda p:(p.name!='test_html_upgrade.py',p.name))
for path in files:
    result=subprocess.run([sys.executable,str(path)],cwd=root,env=env)
    if result.returncode: raise SystemExit(result.returncode)
print(f'PASS: {len(files)} offline regression programs')
