"""Exercise the exact retained BlueBuild CLI without a source checkout/build."""
import json
import os
from pathlib import Path
import shutil
import subprocess

from image.toolchain.reuse import unpack_tool, unique_json


def main():
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted' or os.geteuid() == 0):
        raise SystemExit('Use the unprivileged hosted builder-reuse unit')
    root = Path.cwd()
    group = Path('/sys/fs/cgroup')/Path(Path('/proc/self/cgroup').read_text().strip().split('::', 1)[1]).relative_to('/')
    limits = {name: (group/name).read_text().strip()
              for name in ('memory.max', 'memory.swap.max', 'cpu.max', 'pids.max')}
    if (not group.name.startswith('symbi-builder-reuse-') or limits != {
            'memory.max': '536870912', 'memory.swap.max': '0', 'cpu.max': '100000 100000', 'pids.max': '64'}):
        raise ValueError('Unexpected builder-reuse resource limits')
    evidence = root/'.cache/assembly-input-evidence/builder'
    evidence.mkdir(parents=True)
    storage = root/'.cache/assembly-builder-reuse'
    storage.mkdir(mode=0o700)
    record = {'passed': False, 'source_commit': os.environ['GITHUB_SHA'], 'limits': limits,
              'os_qualified': False, 'scope': 'Actual cross-job CLI reuse; no native compilation or image build'}
    try:
        lock = unique_json((root/'image/development-builder.lock.json').read_bytes())
        manifest = unpack_tool(root/'.cache/bluebuild-development-tool.zip', lock,
                               root/'image/toolchain/bluebuild.json', storage/'tool')
        record['artifact'] = lock['artifact']
        record['compiled_manifest'] = manifest
        # Generation extracts embedded scripts and edits .gitignore. Keep those
        # effects in a fresh context, separate from the checked-out source.
        context = storage/'context'
        (context/'image/keys').mkdir(parents=True)
        for relative in ('image/recipe.py', 'image/base-images.json',
                         'image/keys/secureblue-2026.pub'):
            shutil.copyfile(root/relative, context/relative)
        env = dict(os.environ, BLUEBUILD_REVISION=manifest['upstream_revision'],
                   RAYON_NUM_THREADS='1', TOKIO_WORKER_THREADS='1', NO_COLOR='1')
        command = ['/usr/bin/python3', str(root/'image/toolchain/qualify.py'),
                   '--binary', str(storage/'tool/bluebuild'), '--root', str(context),
                   '--evidence', str(evidence/'cli')]
        with (evidence/'cli-run.log').open('xb') as log:
            subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=900)
        result = unique_json((evidence/'cli/result.json').read_bytes())
        if (result.get('recipe_validation_passed') is not True
                or result.get('containerfiles_generated') is not True or result.get('os_qualified') is not False
                or result.get('binary_sha256') != manifest['binary']['sha256']
                or len(result.get('checks', [])) != 17 or any(row.get('passed') is not True for row in result['checks'])):
            raise ValueError('Retained builder did not pass its complete CLI acceptance')
        record['cli_cases'] = len(result['checks'])
        record['passed'] = True
    except Exception as error:
        record['failure'] = type(error).__name__+': '+str(error)
        raise
    finally:
        record['cgroup_final'] = {name: (group/name).read_text().strip()
                                  for name in (*limits, 'memory.peak', 'memory.events', 'cpu.stat')}
        (evidence/'result.json').write_text(json.dumps(record, indent=2)+'\n')


if __name__ == '__main__':
    main()
