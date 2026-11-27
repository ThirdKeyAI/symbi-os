#!/usr/bin/env python3
"""Check shipped Lua defaults with the actual bounded Fedora compositor parser."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hyprland', type=Path, required=True)
    parser.add_argument('--defaults', type=Path, required=True)
    parser.add_argument('--work-dir', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() == 0 or not Path('/run/.containerenv').exists():
        raise SystemExit('Use the disposable unprivileged Fedora probe container')
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from guest_inventory import require_fedora_family
    require_fedora_family(platform.freedesktop_os_release())
    group = Path('/sys/fs/cgroup') / Path(Path('/proc/self/cgroup').read_text().strip().split('::', 1)[1]).relative_to('/')
    limits = {name: (group / name).read_text().strip() for name in ('memory.max', 'memory.swap.max', 'cpu.max')}
    quota, period = limits['cpu.max'].split()
    if limits['memory.max'] == 'max' or int(limits['memory.max']) > 2 * 1024**3:
        raise SystemExit('At most 2 GiB memory is required')
    if limits['memory.swap.max'] != '0' or quota == 'max' or int(quota) > int(period):
        raise SystemExit('At most one CPU and no swap are required')
    binary = args.hyprland.resolve(strict=True)
    source = args.defaults.resolve(strict=True)
    work = args.work_dir.absolute()
    if work.exists() or work.is_symlink() or work.parent.resolve() != work.parent:
        raise SystemExit('Use a fresh work directory without symlinked parents')
    report = args.report.absolute()
    if report.exists() or report.is_symlink():
        raise SystemExit('Preserve previous evidence')
    files = {}
    for path in source.rglob('*'):
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise SystemExit('Defaults may contain only regular files and directories')
        if path.is_file():
            files[str(path.relative_to(source))] = digest(path)
    assert {'hyprland.lua', 'input.lua', 'appearance.lua'} <= files.keys()
    work.mkdir(mode=0o700)
    for name in ('home', 'runtime', 'config'):
        (work / name).mkdir(mode=0o700)
    config = work / 'config/hypr'
    shutil.copytree(source, config)
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(work / 'home'), 'XDG_RUNTIME_DIR': str(work / 'runtime'),
           'XDG_CONFIG_HOME': str(work / 'config'), 'LANG': 'C.UTF-8',
           'LIBGL_ALWAYS_SOFTWARE': '1', 'LP_NUM_THREADS': '1', 'OMP_NUM_THREADS': '1'}
    result = {'passed': False, 'os_qualified': False, 'hyprland_sha256': digest(binary),
              'defaults_sha256': files, 'limits': limits, 'checks': [],
              'scope': 'Real compositor configuration parsing, not a boot or desktop interaction test'}

    def save():
        report.write_text(json.dumps(result, indent=2) + '\n')

    def check(name, path, expected_success):
        completed = subprocess.run([str(binary), '--verify-config', '--config', str(path)],
                                   cwd=work, env=env, capture_output=True, text=True, timeout=30)
        passed = (completed.returncode == 0) if expected_success else completed.returncode == 1
        result['checks'].append({'name': name, 'passed': passed, 'exit_code': completed.returncode,
                                 'stdout': completed.stdout, 'stderr': completed.stderr})
        save()
        if not passed:
            raise RuntimeError(name + ' failed')

    save()
    try:
        check('shipped-session-defaults', config / 'hyprland.lua', True)
        invalid = config / 'invalid-control.lua'
        invalid.write_text('this is not valid Lua syntax !!!\n')
        check('invalid-lua-control-rejected', invalid, False)
        check('shipped-session-defaults-repeat', config / 'hyprland.lua', True)
        assert digest(binary) == result['hyprland_sha256']
        assert all(digest(source / name) == value for name, value in files.items())
        result['passed'] = True
    finally:
        save()


if __name__ == '__main__':
    main()
