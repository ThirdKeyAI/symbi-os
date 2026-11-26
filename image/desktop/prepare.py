"""Prepare the actual BlueBuild desktop context from retained, checked artifacts."""
import json
import os
from pathlib import Path
import shutil
import subprocess

from image.assembly.inputs import unpack_runtime
from image.assembly.runtime_install import require_runtime_rpms
from image.desktop.files import copy_regular, inventory, release_file_cache
from image.desktop.inputs import select_prefix_files
from image.desktop.portal import select_consent_files
from image.desktop.recipe import render_desktop, review_containerfile
from image.desktop.trust import prepare_trust
from image.fonts.install import prepare_font_payload
from image.hyprland.build_inputs import require_current_requirements, unpack_rpms
from image.hyprland.prefix_input import unpack_prefix
from image.launcher.binary_inputs import require_bindings, unpack_binaries
from image.launcher.walker_binary_inputs import unpack_walker
from image.portal.consent_prefix import load_consent_prefix, unpack_consent_portal
from image.portal.runtime_inputs import select_runtime_package
from image.toolchain.reuse import digest, unique_json, unpack_tool


def main():
    if (os.geteuid() == 0 or os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'):
        raise SystemExit('Use the unprivileged hosted desktop preparation unit')
    root = Path.cwd()
    group = Path('/sys/fs/cgroup')/Path(Path('/proc/self/cgroup').read_text().strip().split('::', 1)[1]).relative_to('/')
    limits = {n: (group/n).read_text().strip() for n in ('memory.max', 'memory.swap.max', 'cpu.max', 'pids.max')}
    if not group.name.startswith('symbi-desktop-prep-') or limits != {
            'memory.max': '1073741824', 'memory.swap.max': '0', 'cpu.max': '100000 100000', 'pids.max': '64'}:
        raise ValueError('Unexpected desktop preparation limits')
    variant = os.environ['SYMBI_IMAGE_VARIANT']
    evidence = root/'.cache/desktop-image-evidence'
    evidence.mkdir(parents=True, exist_ok=True)
    storage = root/'.cache/desktop-image-inputs'
    storage.mkdir(mode=0o700)
    context = storage/'context'
    context.mkdir()
    payload = context/'payload'
    payload.mkdir()
    record = {'passed': False, 'os_qualified': False, 'source_commit': os.environ['GITHUB_SHA'],
              'variant': variant, 'limits': limits, 'artifacts': {}, 'checkpoints': []}

    def checkpoint(phase):
        record['phase'] = phase
        record['checkpoints'].append({'phase': phase, 'memory.current': (group/'memory.current').read_text().strip(),
            'memory.peak': (group/'memory.peak').read_text().strip(), 'memory.events': (group/'memory.events').read_text().strip(),
            'memory.stat': (group/'memory.stat').read_text(),
            'process_memory': [line for line in Path('/proc/self/status').read_text().splitlines() if line.startswith(('VmRSS:', 'VmHWM:'))]})
        temporary = evidence/'preparation.json.tmp'
        with temporary.open('w') as output:
            output.write(json.dumps(record, indent=2)+'\n')
            output.flush()
            os.fsync(output.fileno())
        temporary.replace(evidence/'preparation.json')
        print('Desktop preparation: '+phase, flush=True)

    def load(relative):
        return unique_json((root/relative).read_bytes())

    def artifact(name, relative):
        lock = load(relative)
        record['artifacts'][name] = {'lock': relative, 'lock_sha256': digest(root/relative), **lock['artifact']}
        return lock

    try:
        checkpoint('validate-target-and-builder')
        pins = load('image/base-images.json')
        recipe = render_desktop(pins, variant, root)
        build_base = pins['variants']['generic']['image']
        record['base'] = pins['variants'][variant]['image']
        record['component_compilation_base'] = build_base
        tool_lock = artifact('bluebuild', 'image/development-builder.lock.json')
        tool = unpack_tool(root/'.cache/bluebuild-development-tool.zip', tool_lock,
                           root/'image/toolchain/bluebuild.json', storage/'tool')
        release_file_cache(storage/'tool')
        for row in tool['patches']:
            if digest(root/row['path']) != row['sha256']:
                raise ValueError('Current builder patch changed')
        checkpoint('extract-compositor')
        hypr_lock = artifact('hyprland', 'image/hyprland/development-prefix.lock.json')
        record['prefix_link_rewrites'] = []
        hypr = unpack_prefix(root/'.cache/hyprland-development-prefix.zip', hypr_lock,
                             storage/'prefix', record['prefix_link_rewrites'])
        release_file_cache(storage/'prefix')
        checkpoint('select-compositor-runtime')
        sources = load('image/hyprland/candidate-inputs.json')
        expected = {row['name']: row['rev'] for row in sources['libraries']}
        expected.update(Hyprland=sources['hyprland_revision'], glaze=sources['glaze']['revision'])
        expected['Hyprland/subprojects/udis86'] = next(row['revision'] for row in sources['submodules'] if row['path'] == 'subprojects/udis86')
        if (hypr['base'] != build_base or hypr['source_commit'] != hypr_lock['tested_merge']
                or hypr['rpm_lock_sha256'] != digest(root/'image/hyprland/build-rpms.lock.json')
                or hypr['native_patch_sha256'] != digest(root/'image/hyprland/patches/0001-disable-native-loading.patch')
                or len(hypr['source_revisions']) != len(expected)
                or {row['name']: row['rev'] for row in hypr['source_revisions']} != expected):
            raise ValueError('Current compositor source/build/patch bindings changed')
        for relative, path in select_prefix_files(storage/'prefix/hyprland').items():
            target = payload/'usr/lib/symbi/hyprland'/relative
            if path.is_symlink():
                target.parent.mkdir(parents=True, exist_ok=True)
                target.symlink_to(os.readlink(path))
            else:
                copy_regular(path, target, bool(path.stat().st_mode & 0o111))
        for name in ('Hyprland', 'hyprctl'):
            target = payload/'usr/bin'/name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.symlink_to('../lib/symbi/hyprland/bin/'+name)
        checkpoint('extract-patched-portal')
        portal_args, portal_bindings, portal_packages = load_consent_prefix(root, build_base)
        portal_lock = artifact('portal', 'image/portal/consent-prefix.lock.json')
        if portal_lock != portal_args[0]: raise ValueError('Portal artifact lock changed during preparation')
        portal = unpack_consent_portal(root/'.cache/portal-consent-prefix.zip', *portal_args, storage/'portal')
        release_file_cache(storage/'portal')
        for relative, path in select_consent_files(storage/'portal/portal', portal).items():
            target = payload/relative
            if path.is_symlink():
                target.parent.mkdir(parents=True, exist_ok=True)
                target.symlink_to(os.readlink(path))
            else:
                copy_regular(path, target, bool(path.stat().st_mode & 0o111))
        record['portal'] = {'manifest_sha256': portal_lock['manifest_sha256'], 'bindings': portal_bindings,
                            'parent_manifest_sha256': portal['parent_prefix_manifest_sha256'],
                            'unchanged_retained_files': portal['unchanged_retained_files'],
                            'native_negative_controls': portal['native_negative_controls'],
                            'consent_qualified': False,
                            'version': next(row['version'] for row in portal['source_inputs']['components']
                                            if row['name'] == 'xdg-desktop-portal-hyprland')}
        checkpoint('extract-elephant')
        elephant_lock = artifact('elephant', 'image/launcher/development-binaries.lock.json')
        if (elephant_lock.get('upstream_tests_passed') is not True
                or elephant_lock.get('source_build_provider_controls_passed') is not True):
            raise ValueError('Elephant source/provider acceptance is required')
        elephant_source = load('image/launcher/elephant-source.json')
        patch_hash = digest(root/'image/launcher/patches/0001-packaged-application-provider-only.patch')
        patch = load('image/launcher/provider-patch.json')
        if patch['patch_sha256'] != patch_hash or patch['upstream_revision'] != elephant_source['revision']:
            raise ValueError('Elephant patch metadata changed')
        require_bindings(elephant_lock['manifest'], elephant_lock, build_base, elephant_source,
                         digest(root/'image/launcher/build-rpms.lock.json'), patch_hash,
                         digest(root/'image/launcher/probes/native_marker.go'))
        unpack_binaries(root/'.cache/elephant-development-binaries.zip', elephant_lock, storage/'elephant')
        release_file_cache(storage/'elephant')
        copy_regular(storage/'elephant/patched', payload/'usr/bin/elephant', True)
        copy_regular(storage/'elephant/desktopapplications', payload/'usr/lib/symbi/elephant/providers/desktopapplications.so')
        checkpoint('extract-walker')
        walker_lock = artifact('walker', 'image/launcher/walker-development-binary.lock.json')
        unpack_walker(root/'.cache/walker-development-binary.zip', walker_lock, root, build_base, storage/'walker')
        release_file_cache(storage/'walker')
        copy_regular(storage/'walker/walker', payload/'usr/bin/walker', True)
        checkpoint('extract-symbiont')
        runtime_lock = artifact('symbiont', 'image/assembly/runtime-development.lock.json')
        unpack_runtime(root/'.cache/symbiont-runtime.zip', runtime_lock, root/'upstream/symbiont.toml',
                       root/'image/assembly/runtime-build-result.json', storage/'runtime')
        release_file_cache(storage/'runtime')
        checkpoint('copy-symbiont')
        for name in ('symbi', 'symbi-sandbox-supervisor'):
            copy_regular(storage/'runtime'/name, payload/'usr/bin'/name, True)
        checkpoint('prepare-nerd-fonts')
        intake = unique_json((root/'.cache/font-intake-evidence/result.json').read_bytes())
        if (intake.get('passed') is not True or intake.get('source_commit') != record['source_commit']
                or intake.get('private_downloads_removed') is not True
                or intake.get('archive_extracted') is not False or intake.get('font_parser_executed') is not False):
            raise ValueError('Current hosted font intake has not passed')
        record['fonts'] = prepare_font_payload(root/'.cache/font-candidate', root/'image/fonts/inputs.json',
                                               root, payload, os.environ['GITHUB_SHA'])
        if intake.get('inventories') != record['fonts']['archives']:
            raise ValueError('Hosted font intake inventory changed')
        shutil.copytree(root/'.cache/font-intake-evidence', evidence/'font-intake')
        checkpoint('prepare-signed-rpms-and-licenses')
        install = context/'install-inputs'
        install.mkdir()
        packages = []
        trust = load('image/hyprland/fedora-package-trust.json')
        profiles = [('hyprland', 'image/hyprland/runtime-rpms.lock.json', 'image/hyprland/runtime-requirements.json', 'hyprland-runtime-rpms.zip'),
                    ('walker', 'image/launcher/runtime-rpms.lock.json', 'image/launcher/runtime-requirements.json', 'launcher-runtime-rpms.zip'),
                    ('symbiont', 'image/assembly/runtime-rpms.lock.json', 'image/runtime_packages/requirements.json', 'symbiont-runtime-rpms.zip')]
        for name, lock_path, requirements_path, archive in profiles:
            lock = artifact(name+'-rpms', lock_path)
            require_current_requirements(lock, load(requirements_path))
            if lock['base'] != build_base or lock['key'] != trust['key'] or lock.get('qualified') is not False:
                raise ValueError('Runtime RPM provenance changed')
            if name == 'symbiont':
                require_runtime_rpms(lock, build_base, load(requirements_path), trust)
            unpack_rpms(root/'.cache'/archive, lock, storage/(name+'-rpms'))
            for row in lock['packages']:
                copy_regular(storage/(name+'-rpms')/'rpms'/row['filename'], install/'rpms'/row['filename'])
                packages.append(row)
        checkpoint('select-signed-portal-runtime')
        portal_rpms = artifact('portal-rpms', 'image/portal/build-rpms.lock.json')
        if portal_rpms != portal_packages: raise ValueError('Portal RPM lock changed during preparation')
        unpack_rpms(root/'.cache/portal-build-rpms.zip', portal_rpms, storage/'portal-rpms')
        release_file_cache(storage/'portal-rpms')
        package = select_runtime_package(portal_rpms)
        copy_regular(storage/'portal-rpms/rpms'/package['filename'], install/'rpms'/package['filename'])
        packages.append(package)
        record['portal']['runtime_package'] = package
        if len(packages) != 6 or len({row['filename'] for row in packages}) != 6:
            raise ValueError('Expected six distinct reviewed runtime libraries')
        combined = {'schema': 1, 'qualified': False, 'target_base': record['base'],
                    'resolution_base': build_base, 'key': trust['key'], 'packages': packages}
        (install/'combined-lock.json').write_text(json.dumps(combined, indent=2)+'\n')
        files = {'install.py': 'image/desktop/install.py', 'inputs.py': 'image/desktop/inputs.py',
                 'runtime_install.py': 'image/assembly/runtime_install.py', 'package_identity.py': 'image/walker/inputs.py',
                 'guest_inventory.py': 'image/hyprland/guest_inventory.py', 'resolve_packages.py': 'image/hyprland/resolve_packages.py',
                 'bounded_process.py': 'image/launcher/probes/bounded_process.py', 'fedora-45-primary.asc': trust['key']['path']}
        for name, source in files.items(): copy_regular(root/source, install/name)
        for source, name in [('image/launcher/licenses/walker.LICENSE', 'Walker-GPL-3.0'),
                             ('image/launcher/licenses/elephant.LICENSE', 'Elephant-GPL-3.0'),
                             ('image/desktop/licenses/Symbiont.LICENSE', 'Symbiont-Apache-2.0'),
                             ('image/hyprland/licenses/hyprwire.LICENSE', 'hyprwire.LICENSE')]:
            copy_regular(root/source, payload/'usr/share/licenses/symbiont-os'/name)
        provenance = load('image/desktop/licenses/sources.json')
        for row in provenance['files']:
            source = root/row['retained_path']
            if digest(source) != row['sha256'] or source.stat().st_size != row['bytes']:
                raise ValueError('Original component license changed')
            if row['name'] != 'Symbiont':
                copy_regular(source, payload/'usr/share/licenses/symbiont-os'/source.name)
        checkpoint('prepare-image-trust')
        record['image_trust'] = prepare_trust(root, payload)
        sources_doc = payload/'usr/share/doc/symbiont-os'
        sources_doc.mkdir(parents=True)
        (sources_doc/'development-inputs.json').write_text(json.dumps(record, indent=2)+'\n')
        for relative in ('image/hyprland/patches/0001-disable-native-loading.patch',
                         'image/launcher/patches/0001-packaged-application-provider-only.patch',
                         'image/portal/patches/0001-no-restore-tests.patch',
                         'image/portal/patches/0002-require-fresh-screen-sharing-consent.patch'):
            copy_regular(root/relative, sources_doc/'patches'/Path(relative).name)
        for path in ('image/overlay', 'image/desktop/session'):
            if any(p.is_symlink() or not (p.is_file() or p.is_dir()) for p in (root/path).rglob('*')):
                raise ValueError('Desktop overlay contains linked or special inputs')
            shutil.copytree(root/path, context/path, symlinks=False)
        (context/'image/desktop/session/usr/libexec/symbi-launch-desktop-services').chmod(0o755)
        for relative in ('LICENSE', 'image/harden-image.sh', 'image/vendor/ombuntu/LICENSE',
                         'image/vendor/omarchy/LICENSE', pins['variants'][variant]['public_key']):
            copy_regular(root/relative, context/relative)
        for path in context.rglob('*'):
            if path.is_dir() and not path.is_symlink(): path.chmod(0o755)
        checkpoint('validate-and-generate-containerfile')
        recipe_path = context/'recipe.json'
        recipe_path.write_text(json.dumps(recipe, indent=2)+'\n')
        env = dict(os.environ, BLUEBUILD_REVISION=tool['upstream_revision'], RAYON_NUM_THREADS='1',
                   TOKIO_WORKER_THREADS='1', NO_COLOR='1', DOCKER_HOST='unix:///dev/null', CONTAINER_HOST='unix:///dev/null')
        if any(name.startswith('BB_') for name in env): raise ValueError('Ambient builder configuration is forbidden')
        binary = str(storage/'tool/bluebuild')
        commands = [('validate', [binary, 'validate', '--all-errors', str(recipe_path)]),
                    ('generate', [binary, 'generate', str(recipe_path), '--output', str(context/'Containerfile'),
                                  '--registry', 'ghcr.io', '--registry-namespace', 'thirdkeyai', '--inspect-driver', 'oci-client',
                                  '--build-driver', 'docker', '--run-driver', 'docker', '--platform', 'linux/amd64'])]
        for name, command in commands:
            with (evidence/(name+'.log')).open('xb') as log:
                subprocess.run(command, cwd=context, env=env, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=180)
        review_containerfile((context/'Containerfile').read_text(), recipe, record['base'])
        for name in ('recipe.json', 'Containerfile'):
            shutil.copyfile(context/name, evidence/name)
        record['payload'] = inventory(payload)
        record['overlay'] = {**inventory(context/'image/overlay'), **inventory(context/'image/desktop/session')}
        for name in ('usr/libexec/symbi-seed-config', 'usr/libexec/symbi-desktop-session',
                     'usr/libexec/symbi-launch-desktop-services'):
            record['overlay'][name]['mode'] = 0o755
        record['context'] = inventory(context)
        record['required_packages'] = packages
        record['passed'] = True
        checkpoint('complete')
    except Exception as error:
        record['failure'] = type(error).__name__+': '+str(error)
        raise
    finally:
        record['cgroup_final'] = {n: (group/n).read_text().strip() for n in (*limits, 'memory.peak', 'memory.events', 'cpu.stat')}
        (evidence/'preparation.json').write_text(json.dumps(record, indent=2)+'\n')


if __name__ == '__main__':
    main()
