"""Build the pinned toolkit and portal offline as the disposable build user."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import time

PREFIX = Path('/usr/lib/symbi/portal')
COMPOSITOR = Path('/usr/lib/symbi/hyprland')


def main():
    if os.getuid() != 10001 or not Path('/run/.containerenv').exists():
        raise SystemExit('Portal compilation requires the unprivileged disposable Fedora build account')
    from bounded_process import run_bounded
    from build_inputs import require_source_tree, require_test_report
    inputs, output = Path('/inputs'), Path('/output')
    evidence = output/'evidence'
    pins = json.loads((inputs/'source-inputs.json').read_text())
    sources = output/'sources'
    shutil.copytree(inputs/'sources', sources, symlinks=True)
    record = {'passed': False, 'os_qualified': False, 'checks': [], 'test_suites': {},
              'scope': 'Offline development build; Debug toolkit tests, Release portal tests and build-container loader checks only',
              'source_revisions': pins['components'], 'prefix': str(PREFIX),
              'compositor_recompiled': False, 'test_and_release_toolkit_are_distinct_builds': True}

    def save():
        (evidence/'compile.json').write_text(json.dumps(record, indent=2)+'\n')

    def run(name, command, timeout=300):
        record['active_check'] = {'name': name, 'command': command}
        save()
        started = time.monotonic()
        result = run_bounded(command, evidence/(name+'-stdout.log'), evidence/(name+'-stderr.log'),
                             timeout=timeout, max_bytes=1024**2)
        record['checks'].append({'name': name, 'command': command, 'exit_code': result.returncode,
                                 'elapsed_seconds': time.monotonic()-started})
        del record['active_check']
        save()
        result.check_returncode()
        return result

    def tests(name, command, *, expected_cases=None):
        report = evidence/(name+'.xml')
        run(name, command, 180)
        if report.is_symlink() or report.stat().st_size > 1024**2:
            raise ValueError('Unexpected native test report file')
        raw = report.read_bytes()
        record['test_suites'][name] = {'cases': require_test_report(raw, expected_cases=expected_cases),
                                     'sha256': hashlib.sha256(raw).hexdigest()}
        save()

    common = ['-G', 'Ninja', '-DCMAKE_INSTALL_PREFIX='+str(PREFIX), '-DCMAKE_INSTALL_LIBDIR=lib',
              '-DCMAKE_INSTALL_LIBEXECDIR=libexec', '-DCMAKE_INSTALL_DATAROOTDIR=share',
              '-DCMAKE_INSTALL_RPATH='+str(PREFIX/'lib')+';'+str(COMPOSITOR/'lib'),
              '-DCMAKE_BUILD_WITH_INSTALL_RPATH=ON', '-DCMAKE_PREFIX_PATH='+str(PREFIX)+';'+str(COMPOSITOR),
              '-DFETCHCONTENT_FULLY_DISCONNECTED=ON', '-DFETCHCONTENT_UPDATES_DISCONNECTED=ON',
              '-DCMAKE_C_FLAGS_DEBUG=-O0 -g0', '-DCMAKE_CXX_FLAGS_DEBUG=-O0 -g0',
              '-DCMAKE_C_FLAGS_RELEASE=-O3 -DNDEBUG -g0', '-DCMAKE_CXX_FLAGS_RELEASE=-O3 -DNDEBUG -g0']
    try:
        for component in pins['components']:
            require_source_tree(sources/component['name'], component, component['revision'])
        # Required providers must exist before CMake can choose a subproject fallback.
        run('required-providers', ['pkg-config', '--exists', 'sdbus-c++ >= 2.0.0', 'hyprland-protocols >= 0.8.0',
                                  'libpipewire-0.3 >= 1.1.82', 'libspa-0.2', 'iniparser', 'absl_flat_hash_map'])
        protocol = COMPOSITOR/'share/hyprland-protocols/protocols/hyprland-workspace-image-capture-source-v1.xml'
        if not protocol.is_file():raise ValueError('Retained compositor prefix lacks workspace capture protocol')
        toolkit = sources/'hyprtoolkit'
        debug = output/'build/toolkit-debug'
        run('toolkit-debug-configure', ['cmake', '-S', str(toolkit), '-B', str(debug), *common,
            '-DCMAKE_BUILD_TYPE=Debug', '-DCMAKE_BUILD_WITH_INSTALL_RPATH=OFF',
            '-DCMAKE_BUILD_RPATH='+str(debug)+';'+str(COMPOSITOR/'lib')])
        run('toolkit-debug-build', ['cmake', '--build', str(debug), '--parallel', '1', '--target',
                                    'hyprtoolkit_tests', 'embeddedRendererTest'], 1800)
        tests('toolkit-unit', [str(debug/'hyprtoolkit_tests'), '--gtest_output=xml:'+str(evidence/'toolkit-unit.xml')])
        tests('toolkit-renderer', [str(debug/'embeddedRendererTest'), '--gtest_output=xml:'+str(evidence/'toolkit-renderer.xml')])
        release = output/'build/toolkit-release'
        run('toolkit-release-configure', ['cmake', '-S', str(toolkit), '-B', str(release), *common, '-DCMAKE_BUILD_TYPE=Release'])
        run('toolkit-release-build', ['cmake', '--build', str(release), '--parallel', '1'], 1800)
        run('toolkit-release-install', ['cmake', '--install', str(release)])
        run('installed-toolkit-provider', ['pkg-config', '--atleast-version=0.6.0', 'hyprtoolkit'])
        portal = output/'build/portal'
        run('portal-configure', ['cmake', '-S', str(sources/'xdg-desktop-portal-hyprland'), '-B', str(portal),
                                *common, '-DCMAKE_BUILD_TYPE=Release', '-DBUILD_TESTING=ON', '-DSYSTEMD_SERVICES=ON'])
        run('portal-build', ['cmake', '--build', str(portal), '--parallel', '1'], 1800)
        tests('portal-tests', ['ctest', '--test-dir', str(portal), '--parallel', '1', '--no-tests=error',
                              '--output-on-failure', '--output-junit', str(evidence/'portal-tests.xml')],
              expected_cases=['hyprland-share-picker-data.hyprland-share-picker-data'])
        run('portal-install', ['cmake', '--install', str(portal)])
        for component in pins['components']:
            target = PREFIX/'share/licenses'/component['name']/'LICENSE'
            target.parent.mkdir(parents=True)
            shutil.copyfile(sources/component['name']/'LICENSE', target)
        for index, relative in enumerate(('lib/libhyprtoolkit.so.0.6.0', 'bin/hyprland-share-picker', 'libexec/xdg-desktop-portal-hyprland')):
            path = PREFIX/relative
            if path.is_symlink() or not path.is_file():raise ValueError('Missing regular installed native payload')
            checked = run('loader-'+str(index), ['ldd', str(path)], 30)
            if 'not found' in checked.stdout+checked.stderr:raise ValueError('Unresolved native build-container dependency')
            run('needed-'+str(index), ['readelf', '--dynamic', str(path)], 30)
        version = run('portal-version', [str(PREFIX/'libexec/xdg-desktop-portal-hyprland'), '--version'], 30)
        if version.stdout.strip() != 'xdg-desktop-portal-hyprland v1.5.0':raise ValueError('Portal version differs')
        record['passed'] = True
    except Exception as error:
        record['failure'] = type(error).__name__+': '+str(error)
        raise
    finally:
        save()


if __name__ == '__main__':
    main()
