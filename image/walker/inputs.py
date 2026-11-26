"""Validate pinned Walker sources, signed tool identities and additive installs."""
import hashlib
import re
import tomllib


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def require_source(source, pins):
    for name in ('Cargo.toml', 'Cargo.lock', 'build.rs'):
        path = source/name
        if (path.is_symlink() or not path.is_file()
                or digest(path) != pins[name.lower().replace('.', '_')+'_sha256']):
            raise ValueError('Pinned source changed: '+name)
    if (source/'.cargo').exists() or (source/'.cargo').is_symlink():
        raise ValueError('Source-supplied Cargo configuration is not permitted')
    manifest = tomllib.loads((source/'Cargo.toml').read_text())
    if (manifest['package']['name'] != 'walker' or manifest['package']['version'] != pins['version']
            or 'patch' in manifest or 'replace' in manifest):
        raise ValueError('Unexpected package identity or dependency replacement')
    lock = tomllib.loads((source/'Cargo.lock').read_text())
    rows = lock.get('package', [])
    if lock.get('version') != 4 or not rows:
        raise ValueError('Expected the reviewed v4 Cargo lock')
    seen, roots = set(), 0
    for row in rows:
        identity = (row.get('name'), row.get('version'), row.get('source'))
        if identity in seen:
            raise ValueError('Duplicate locked package identity')
        seen.add(identity)
        if 'source' not in row:
            if row.get('name') != 'walker' or row.get('version') != pins['version']:
                raise ValueError('Unexpected unchecksummed local dependency')
            roots += 1
        elif (row['source'] != 'registry+https://github.com/rust-lang/crates.io-index'
              or not re.fullmatch(r'[0-9a-f]{64}', row.get('checksum', ''))):
            raise ValueError('Only the checksummed upstream registry graph is permitted')
    if roots != 1:
        raise ValueError('Expected exactly the pinned Walker root package')
    return {'packages': len(rows), 'registry_dependencies': len(rows)-1}


def require_rust_identity(text, executable):
    if executable not in ('rustc', 'cargo') or not text.startswith(executable+' 1.100.0 '):
        raise ValueError('Unexpected signed Fedora compiler version')
    fields = {}
    for line in text.splitlines()[1:]:
        if ': ' in line:
            key, value = line.split(': ', 1)
            if key in fields:
                raise ValueError('Duplicate compiler identity field')
            fields[key] = value
    if fields.get('release') != '1.100.0' or fields.get('host') != 'x86_64-unknown-linux-gnu':
        raise ValueError('Expected stable Rust/Cargo 1.100.0 for x86_64 GNU Linux')
    return fields


def require_additive(before, after, expected):
    if not before or not expected or any(len(rows) != len(set(rows)) for rows in (before, after, expected)):
        raise ValueError('Missing or ambiguous package transaction')
    if any(len(row.split('\t')) != 5 for row in [*before, *after, *expected]):
        raise ValueError('Malformed package identity')
    if {row.split('\t')[0] for row in before} & {row.split('\t')[0] for row in expected}:
        raise ValueError('A candidate would replace an existing base package')
    if not set(before).issubset(after) or set(after)-set(before) != set(expected):
        raise ValueError('The transaction must preserve the base and add only reviewed packages')
