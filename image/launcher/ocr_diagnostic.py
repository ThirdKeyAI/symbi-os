#!/usr/bin/env python3
"""Expose the suppressed OCR error on the original base; never qualify the suite."""
import json
import os
from pathlib import Path
import shutil
from bounded_process import run_bounded


def main():
    if (os.geteuid() != 10001 or os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'):
        raise SystemExit('OCR diagnostics require the isolated hosted probe user')
    evidence = Path('/output')
    cgroup = Path('/sys/fs/cgroup') / Path(Path('/proc/self/cgroup').read_text().strip().split('::', 1)[1]).relative_to('/')
    limits = {name: (cgroup/name).read_text().strip()
              for name in ('memory.max', 'memory.swap.max', 'cpu.max', 'pids.max')}
    if limits != {'memory.max': '268435456', 'memory.swap.max': '0',
                  'cpu.max': '100000 100000', 'pids.max': '64'}:
        raise ValueError('Unexpected OCR diagnostic resource limits')
    record = {'scope': 'Diagnostic of upstream TestRunOCR prerequisites on the original signed base',
              'os_qualified': False, 'upstream_tests_passed': False, 'limits': limits,
              'executables': {name: shutil.which(name) for name in ('convert', 'tesseract')},
              'commands': [], 'diagnostic_completed': False}

    def run(name, command):
        result = run_bounded(command, evidence/(name+'-stdout.log'), evidence/(name+'-stderr.log'))
        record['commands'].append({'name': name, 'command': command, 'exit_code': result.returncode})
        return result

    try:
        # These are the exact image-generation arguments and OCR invocation in
        # the pinned upstream test/helper. No success is inferred from RPM names.
        if record['executables']['tesseract']:
            run('tesseract-version', ['tesseract', '--version'])
            run('tesseract-languages', ['tesseract', '--list-langs'])
        if record['executables']['convert']:
            created = run('create-test-image', ['convert', '-size', '300x50', 'xc:white',
                          '-pointsize', '20', '-fill', 'black', '-draw',
                          "text 10,30 'hello elephant'", '/output/ocr_test.png'])
            if created.returncode == 0 and record['executables']['tesseract']:
                result = run('ocr', ['tesseract', '/output/ocr_test.png', 'stdout'])
                record['expected_word_observed'] = result.returncode == 0 and 'elephant' in result.stdout.lower()
        record['missing_executables'] = [name for name, path in record['executables'].items() if path is None]
        record['diagnostic_completed'] = True
    except Exception as error:
        record['failure'] = type(error).__name__ + ': ' + str(error)
        raise
    finally:
        record['cgroup_final'] = {name: (cgroup/name).read_text().strip()
                                  for name in (*limits, 'memory.peak', 'memory.events', 'cpu.stat')}
        (evidence/'result.json').write_text(json.dumps(record, indent=2)+'\n')


if __name__ == '__main__':
    main()
