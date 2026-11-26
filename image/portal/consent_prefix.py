"""Consume the patched portal without relabelling its parent's native tests."""
from image.portal.consent_inputs import load_consent, require_portal_only_install
from image.portal.prefix_input import require_portal_manifest, unpack_verified_portal_archive
from image.toolchain.reuse import exact_hash, unique_json


def require_consent_manifest(manifest, lock, pins, consent, parent_lock, base, rpm_hash, compositor_hash):
    try:
        parent = require_portal_manifest(parent_lock['manifest'], parent_lock, pins, base, rpm_hash, compositor_hash)
        if (type(lock['schema']) is not int or lock['schema'] != 1
                or any(lock[name] is not False for name in ('qualified', 'product_installation', 'consent_qualified'))
                or type(lock['run_id']) is not int or lock['run_id'] <= 0
                or not exact_hash(lock['tested_commit'], 40) or not exact_hash(lock['manifest_sha256'])
                or manifest != lock['manifest'] or type(manifest['schema']) is not int or manifest['schema'] != 1
                or manifest['compiled'] is not True
                or any(manifest[name] is not False for name in ('os_qualified', 'selected_base_qualified', 'consent_qualified'))
                or manifest['source_commit'] != lock['tested_commit'] or manifest['base'] != base
                or manifest['source_inputs'] != pins or manifest['consent_inputs'] != consent
                or manifest['rpm_lock_sha256'] != rpm_hash
                or manifest['reused_compositor_manifest_sha256'] != compositor_hash
                or manifest['parent_prefix_manifest_sha256'] != parent_lock['manifest_sha256']
                or not exact_hash(manifest['compile_report_sha256']) or not exact_hash(manifest['payload_sha256'])
                or type(manifest['payload_bytes']) is not int or not 0 < manifest['payload_bytes'] <= 64*1024**2):
            raise ValueError('Patched portal source, parent, build or qualification binding changed')
        artifact = lock['artifact']
        if (type(artifact['id']) is not int or artifact['id'] <= 0
                or artifact['name'] != 'portal-consent-prefix' or not exact_hash(artifact['sha256'])
                or type(artifact['bytes']) is not int or not 0 < artifact['bytes'] <= 65*1024**2):
            raise ValueError('Invalid patched portal artifact identity')
        suites = manifest['test_suites']
        if (set(suites) != {'portal-tests'}
                or suites['portal-tests']['cases'] != ['hyprland-share-picker-data.hyprland-share-picker-data']
                or not exact_hash(suites['portal-tests']['sha256'])):
            raise ValueError('Patched portal native test accounting changed')
        controls = manifest['native_negative_controls']
        if (set(controls) != {'original_native_test_failed', 'allow-token_rejected', 'unknown-option_rejected'}
                or any(value is not True for value in controls.values())):
            raise ValueError('Patched portal native negative controls are incomplete')
        retained = require_portal_only_install(parent, manifest['files'], consent['patch_license'])
        if (manifest['unchanged_retained_files'] != retained
                or sum(row.get('bytes', 0) for row in manifest['files'].values()) > 64*1024**2):
            raise ValueError('Retained portal accounting or expanded payload limit changed')
    except (KeyError, TypeError, AttributeError) as error:
        raise ValueError('Malformed patched portal prefix binding') from error
    return manifest


def unpack_consent_portal(archive, lock, pins, consent, parent_lock, base, rpm_hash, compositor_hash, destination):
    manifest = require_consent_manifest(lock['manifest'], lock, pins, consent, parent_lock, base, rpm_hash, compositor_hash)
    return unpack_verified_portal_archive(archive, lock, manifest, destination)


def load_consent_prefix(root, base):
    """Return validated consumer arguments, source bindings and the RPM build lock."""
    import hashlib
    from image.portal.build_inputs import require_rpm_bindings
    from image.portal.inputs import load_inputs, regular_bytes

    pins, requirements, bindings = load_inputs(root)
    consent, consent_bindings = load_consent(root, pins)
    bindings.update(consent_bindings)

    def load(relative):
        raw = regular_bytes(root, relative, 2*1024**2)
        bindings[relative] = hashlib.sha256(raw).hexdigest()
        return unique_json(raw)

    packages = load('image/portal/build-rpms.lock.json')
    trust = load('image/hyprland/fedora-package-trust.json')
    require_rpm_bindings(packages, requirements, base, trust)
    parent = load('image/portal/development-prefix.lock.json')
    compositor = load('image/hyprland/development-prefix.lock.json')
    lock = load('image/portal/consent-prefix.lock.json')
    args = (lock, pins, consent, parent, base, bindings['image/portal/build-rpms.lock.json'], compositor['manifest_sha256'])
    require_consent_manifest(lock['manifest'], *args)
    return args, bindings, packages
