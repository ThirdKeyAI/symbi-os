"""Run native before/after consent regressions; rebuild only portal and picker."""
import json
import os
from pathlib import Path
import shutil
import time

PREFIX = Path('/usr/lib/symbi/portal')
COMPOSITOR = Path('/usr/lib/symbi/hyprland')


def main():
    if os.getuid() != 10001 or not Path('/run/.containerenv').exists():
        raise SystemExit('Consent compilation requires the unprivileged disposable Fedora build account')
    from bounded_process import run_bounded
    from build_inputs import require_source_tree, require_test_report
    from consent_inputs import prefix_inventory, require_portal_only_install, require_tree
    from reuse import digest, unique_json
    inputs, output = Path('/inputs'), Path('/output')
    evidence = output/'evidence'
    pins = unique_json((inputs/'source-inputs.json').read_bytes())
    bundle = unique_json((inputs/'consent-inputs.json').read_bytes())
    parent = unique_json((inputs/'parent-prefix.json').read_bytes())
    component = next(row for row in pins['components'] if row['name'] == 'xdg-desktop-portal-hyprland')
    source = output/'sources'/component['name']
    shutil.copytree(inputs/'sources'/component['name'], source, symlinks=True)
    shutil.copytree(Path('/retained-portal'), PREFIX, symlinks=True, dirs_exist_ok=True)
    if prefix_inventory(PREFIX) != parent['files']: raise ValueError('Retained native prefix changed during copying')
    record = {'passed': False, 'os_qualified': False, 'consent_qualified': False,
              'checks': [], 'test_suites': {}, 'negative_controls': {},
              'source_revision': component['revision'], 'consent_inputs_sha256': digest(inputs/'consent-inputs.json'),
              'compositor_recompiled': False, 'toolkit_recompiled': False,
              'scope': 'Actual formatter regression and CLI refusals, portal/picker build and loaders; complete D-Bus/GUI consent acceptance remains pending'}

    def save(): (evidence/'compile.json').write_text(json.dumps(record, indent=2)+'\n')

    def run(name, command, timeout=300, check=True):
        record['active_check'] = {'name': name, 'command': command}; save()
        started = time.monotonic()
        result = run_bounded(command, evidence/(name+'-stdout.log'), evidence/(name+'-stderr.log'),
                             timeout=timeout, max_bytes=1024**2)
        record['checks'].append({'name': name, 'command': command, 'exit_code': result.returncode,
                                 'elapsed_seconds': time.monotonic()-started})
        del record['active_check']; save()
        if check: result.check_returncode()
        return result

    def apply_patch(patch):
        path = inputs/'patches'/Path(patch['path']).name
        if (path.is_symlink() or not path.is_file() or path.stat().st_size != patch['bytes']
                or digest(path) != patch['sha256']):
            raise ValueError('Consent patch bytes changed')
        git = ['git', '-c', 'core.hooksPath=/dev/null', '-C', str(source), 'apply']
        stats = run(patch['role']+'-scope', git+['--numstat', '--', str(path)]).stdout.splitlines()
        rows = [line.split('\t') for line in stats]
        if (any(len(row) != 3 or not row[0].isdigit() or not row[1].isdigit() for row in rows)
                or sorted(row[2] for row in rows) != sorted(patch['files'])):
            raise ValueError('Actual patch targets differ from the reviewed scope')
        run(patch['role']+'-dry-run', git+['--check', '--whitespace=nowarn', '--', str(path)])
        run(patch['role']+'-apply', git+['--whitespace=nowarn', '--', str(path)])
        require_tree(source, bundle, patch['role'])

    try:
        require_source_tree(source, component, component['revision'])
        require_tree(source, bundle, 'upstream')
        apply_patch(bundle['patches'][0])
        # Compile and run the real upstream formatter with the new regression
        # expectations BEFORE changing its implementation. No toolkit rebuild.
        baseline = output/'before-no-restore'
        picker = source/'hyprland-share-picker'
        run('before-test-build', ['/usr/bin/g++', '-std=c++23', '-O0', '-g0', '-I'+str(picker),
            str(picker/'PickerDataTest.cpp'), str(picker/'PickerData.cpp'), '-o', str(baseline)])
        baseline_result = run('before-native-test', [str(baseline)], timeout=30, check=False)
        if (baseline_result.returncode != 1
                or 'Symbi OS: persistent choice emitted or fresh selection changed' not in baseline_result.stderr):
            raise ValueError('Native regression did not expose the original persistence behavior')
        record['negative_controls']['original_native_test_failed'] = True
        apply_patch(bundle['patches'][1])
        run('required-providers', ['pkg-config', '--exists', 'hyprtoolkit >= 0.6.0', 'sdbus-c++ >= 2.0.0',
            'hyprland-protocols >= 0.8.0', 'libpipewire-0.3 >= 1.1.82', 'libspa-0.2'])
        build = output/'build/portal'
        run('portal-configure', ['cmake', '-S', str(source), '-B', str(build), '-G', 'Ninja',
            '-DCMAKE_INSTALL_PREFIX='+str(PREFIX), '-DCMAKE_INSTALL_LIBDIR=lib', '-DCMAKE_INSTALL_LIBEXECDIR=libexec',
            '-DCMAKE_INSTALL_DATAROOTDIR=share', '-DCMAKE_INSTALL_RPATH='+str(PREFIX/'lib')+';'+str(COMPOSITOR/'lib'),
            '-DCMAKE_BUILD_WITH_INSTALL_RPATH=ON', '-DCMAKE_PREFIX_PATH='+str(PREFIX)+';'+str(COMPOSITOR),
            '-DFETCHCONTENT_FULLY_DISCONNECTED=ON', '-DFETCHCONTENT_UPDATES_DISCONNECTED=ON',
            '-DCMAKE_C_FLAGS_RELEASE=-O3 -DNDEBUG -g0', '-DCMAKE_CXX_FLAGS_RELEASE=-O3 -DNDEBUG -g0',
            '-DCMAKE_BUILD_TYPE=Release', '-DBUILD_TESTING=ON', '-DSYSTEMD_SERVICES=ON'])
        run('portal-build', ['cmake', '--build', str(build), '--parallel', '1'], 1800)
        report = evidence/'portal-tests.xml'
        run('portal-tests', ['ctest', '--test-dir', str(build), '--parallel', '1', '--no-tests=error',
                             '--output-on-failure', '--output-junit', str(report)], 180)
        if report.is_symlink() or report.stat().st_size > 1024**2: raise ValueError('Unexpected native test report')
        cases = require_test_report(report.read_bytes(), expected_cases=['hyprland-share-picker-data.hyprland-share-picker-data'])
        record['test_suites']['portal-tests'] = {'cases': cases, 'sha256': digest(report)}
        run('portal-install', ['cmake', '--install', str(build)])
        license = bundle['patch_license']
        license_source = inputs/'LICENSE.symbi-os'
        if (license_source.is_symlink() or license_source.stat().st_size != license['bytes']
                or digest(license_source) != license['sha256']):
            raise ValueError('Downstream patch license changed')
        license_target = PREFIX/'share/licenses/symbi-os-portal-patch/LICENSE'
        license_target.parent.mkdir(parents=True)
        shutil.copyfile(license_source, license_target); license_target.chmod(0o644)
        record['unchanged_retained_files'] = require_portal_only_install(parent, prefix_inventory(PREFIX), license)
        for index, relative in enumerate(('lib/libhyprtoolkit.so.0.6.0', 'bin/hyprland-share-picker',
                                           'libexec/xdg-desktop-portal-hyprland')):
            path = PREFIX/relative
            checked = run('loader-'+str(index), ['ldd', str(path)], 30)
            if 'not found' in checked.stdout+checked.stderr: raise ValueError('Unresolved compiled portal dependency')
            run('needed-'+str(index), ['readelf', '--dynamic', str(path)], 30)
        for name, argument in (('allow-token', '--allow-token'), ('unknown-option', '--symbi-unrecognized')):
            result = run('picker-'+name, [str(PREFIX/'bin/hyprland-share-picker'), argument], timeout=30, check=False)
            if (result.returncode != 2 or result.stdout.strip()
                    or result.stderr.strip() != '[XDPH_PICKER_ERROR] This picker accepts no command-line options'):
                raise ValueError('Installed picker did not refuse unsupported options before opening a display')
            record['negative_controls'][name+'_rejected'] = True
        version = run('portal-version', [str(PREFIX/'libexec/xdg-desktop-portal-hyprland'), '--version'], 30)
        if version.stdout.strip() != 'xdg-desktop-portal-hyprland v'+component['version']:
            raise ValueError('Portal version differs from the reviewed upstream version')
        require_tree(source, bundle, 'implementation')
        record['passed'] = True
    except Exception as error:
        record['failure'] = type(error).__name__+': '+str(error)
        raise
    finally: save()


if __name__ == '__main__': main()
