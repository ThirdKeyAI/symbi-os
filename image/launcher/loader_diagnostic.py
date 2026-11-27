#!/usr/bin/env python3
"""Capture normal startup from a disposable container supervised by the host."""
import json
import subprocess
from bounded_process import run_bounded


def capture_startup(command, output, record, timeout=5):
    """Capture a direct child, preserving the report before any execution."""
    record.update(command=command, timeout_seconds=timeout, timed_out=False)
    report = output/'loader-result.json'
    report.write_text(json.dumps(record, indent=2)+'\n')
    try:
        try:
            result = run_bounded(command, output/'loader-stdout.log', output/'loader-stderr.log', timeout=timeout)
            record['exit_code'] = result.returncode
        except subprocess.TimeoutExpired:
            # This service normally remains alive. run_bounded kills and reaps
            # the direct child; the hosted parent still removes the container.
            record.update(timed_out=True, exit_code=None)
        record['diagnostic_completed'] = True
    except Exception as error:
        record['execution_failure'] = type(error).__name__+': '+str(error)
        raise
    finally:
        report.write_text(json.dumps(record, indent=2)+'\n')
