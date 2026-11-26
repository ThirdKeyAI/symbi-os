"""Retain source-bound compiled builder bytes without claiming qualification."""
import hashlib
import json
import re
import shutil


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def retain_compiled_tool(binary, source_license, config_path, record, tested_commit, destination):
    if destination.exists() or destination.is_symlink():
        raise ValueError('Compiled-tool destination must be fresh')
    for path, maximum in ((binary, 128*1024**2), (source_license, 256*1024), (config_path, 65536)):
        if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= maximum:
            raise ValueError('Expected bounded regular tool, license and config inputs')
    if not isinstance(tested_commit, str) or not re.fullmatch(r'[0-9a-f]{40}', tested_commit):
        raise ValueError('The tested OS commit must be exact')
    config = json.loads(config_path.read_text())
    if (config.get('schema') != 1 or config.get('repository') != 'https://github.com/blue-build/cli'
            or config.get('profile') != 'dev' or config.get('qualified') is not False
            or record.get('source_clean_before_build') is not True or record.get('build_passed') is not True
            or record.get('source_revision') != config.get('revision')
            or any(record.get(key) != config.get(key) for key in ('rust', 'features', 'profile', 'patches'))):
        raise ValueError('Compiled source identity differs from the reviewed tool configuration')
    for key in ('cargo_lock_sha256', 'applied_diff_sha256', 'license_sha256'):
        if not isinstance(record.get(key), str) or not re.fullmatch(r'[0-9a-f]{64}', record[key]):
            raise ValueError('Missing exact build input hash: '+key)
    if (not re.fullmatch(r'[0-9a-f]{40}', record['source_revision'])
            or not isinstance(record.get('rustc'), str)
            or not record['rustc'].startswith('rustc '+config['rust']+' ')
            or digest(source_license) != record['license_sha256']):
        raise ValueError('Compiler or original source license changed')
    manifest = {'schema': 1, 'compiled': True, 'os_qualified': False, 'cli_acceptance_qualified': False,
                'scope': 'Compiled development builder only; inspect separately retained CLI and upstream tests before reuse',
                'source_commit': tested_commit, 'upstream_revision': record['source_revision'],
                'tool_config_sha256': digest(config_path), 'cargo_lock_sha256': record['cargo_lock_sha256'],
                'applied_diff_sha256': record['applied_diff_sha256'], 'patches': record['patches'],
                'rust': record['rust'], 'rustc': record['rustc'], 'features': record['features'], 'profile': record['profile'],
                'binary': {'name': 'bluebuild', 'bytes': binary.stat().st_size, 'sha256': digest(binary)},
                'license': {'name': 'LICENSE', 'bytes': source_license.stat().st_size, 'sha256': digest(source_license)}}
    destination.mkdir(mode=0o755)
    try:
        shutil.copyfile(binary, destination/'bluebuild')
        (destination/'bluebuild').chmod(0o755)
        shutil.copyfile(source_license, destination/'LICENSE')
        (destination/'LICENSE').chmod(0o644)
        (destination/'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
        (destination/'manifest.json').chmod(0o644)
    except Exception:
        shutil.rmtree(destination)
        raise
    return manifest
