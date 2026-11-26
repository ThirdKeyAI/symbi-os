"""Put the reviewed enforcing release policy into the actual image payload."""
from pathlib import Path

from image.signing import render, write_bundle
from image.toolchain.reuse import digest, unique_json


def prepare_trust(root, payload):
    root, payload = Path(root), Path(payload)
    if (payload.is_symlink() or not payload.is_dir() or payload.resolve() != payload
            or (payload/'etc').is_symlink()
            or ((payload/'etc').exists() and not (payload/'etc').is_dir())):
        raise ValueError('Policy payload requires a real, unlinked directory')
    release_path, base_path = root/'image/release-trust.json', root/'image/base-images.json'
    release, bases = unique_json(release_path.read_bytes()), unique_json(base_path.read_bytes())
    bundle = render(release, bases, root)
    output = payload/'etc/containers'
    # This fresh output namespace rejects overlapping or linked destinations.
    # Keys are embedded public bytes already hash-checked by the trust renderer.
    write_bundle(bundle, output)
    files = {}
    for path in (output/'policy.json', output/'registries.d/symbiont.yaml'):
        path.chmod(0o644)
        files[path.relative_to(payload).as_posix()] = {'sha256': digest(path), 'bytes': path.stat().st_size}
    return {'release_trust_sha256': digest(release_path), 'base_pins_sha256': digest(base_path),
            'release_repositories': release['repositories'], 'files': files,
            'signature_qualified': False,
            'scope': 'Installed enforcing policy preparation; actual signature/update/rollback controls remain required'}
