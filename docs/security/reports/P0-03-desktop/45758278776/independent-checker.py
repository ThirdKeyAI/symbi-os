"""Independently reconcile the small successful assembly evidence."""
from pathlib import Path
import hashlib
import json
import sys

sys.dont_write_bytecode = True
repo = Path('/vmstore/repos2/symbi-os/.cache/p0-image-followup')
sys.path.insert(0, str(repo))
from image.desktop.inputs import require_transaction
from image.hyprland.inventory import require_subject
from image.hyprland.resolve_packages import require_keyring, require_verified_rpm
from image.toolchain.reuse import unique_json
from image.walker.inputs import require_package_identity

root = Path(__file__).resolve().parent
evidence = root/'.cache/desktop-evidence-45758278776'
load = lambda p: unique_json(p.read_bytes())
build, prep = load(evidence/'build.json'), load(evidence/'preparation.json')
head = '1e171d1820b473141df4c300dd657056a171b98a'
assert build['source_commit'] == prep['source_commit'] == head
assert build['passed'] is True and build['image_built'] is True and build['os_qualified'] is False
assert prep['passed'] is True and prep['variant'] == build['variant'] == 'generic'
base = load(repo/'image/base-images.json')['variants']['generic']['image']
assert prep['base'] == build['base'] == base
require_subject(load(evidence/'base-signature-stdout.log'), base)
commands = {row['name']: row['exit_code'] for row in build['commands']}
assert len(commands) == len(build['commands'])
assert all(code == (1 if name.startswith('absent-') or name == 'base-check-absent' else 0)
           for name, code in commands.items())
required = []
for name in ('image/hyprland/runtime-rpms.lock.json', 'image/launcher/runtime-rpms.lock.json',
             'image/assembly/runtime-rpms.lock.json'):
    required.extend(load(repo/name)['packages'])
assert prep['required_packages'] == required and len(required) == 5
trust = load(repo/'image/hyprland/fedora-package-trust.json')
fingerprint = trust['key']['fingerprint']
require_keyring((evidence/'install/keyring-stdout.log').read_text(), fingerprint)
identities = []
for index, package in enumerate(required):
    require_verified_rpm(0, (evidence/f'install/rpm-{index}-signature-stdout.log').read_text(), fingerprint)
    rows = (evidence/f'install/rpm-{index}-identity-stdout.log').read_text().splitlines()
    assert len(rows) == 1
    require_package_identity(rows[0], package['nevra'])
    identities.extend(rows)
before = (evidence/'install/installed-before-stdout.log').read_text().splitlines()
after = (evidence/'install/installed-after-stdout.log').read_text().splitlines()
require_transaction(before, after, identities)
assert len(before) == 2178 and len(after) == 2183
old_config, new_config = load(evidence/'install/crypto-before.json'), load(evidence/'install/crypto-after.json')
assert all(new_config.get(name) == value for name, value in old_config.items())
install = load(evidence/'install/result.json')
assert install == build['installation'] and install['passed'] is True
assert hashlib.sha256((evidence/'install/openssl3.cnf').read_bytes()).hexdigest() == install['compatibility_configuration_sha256']
installed = load(evidence/'installed-files-stdout.log')
assert installed == build['installed_files'] and installed['passed'] is True
assert installed['installed_files_checked'] == len({**prep['payload'], **prep['overlay']}) == 88
assert installed['installed_package_count'] == 2183 and installed['uid'] == 10001
for name in ('Hyprland', 'hyprctl', 'elephant', 'walker', 'symbi', 'symbi-sandbox-supervisor'):
    assert 'not found' not in (evidence/f'ldd-{name}-stdout.log').read_text() + (evidence/f'ldd-{name}-stderr.log').read_text()
for name, expected in [('symbi-version', 'symbi 3.0.0'), ('walker-version', '2.17.2'),
                       ('elephant-provider', 'desktopapplications')]:
    assert (evidence/f'{name}-stdout.log').read_text().strip() == expected
session = load(evidence/'session-result.json')
assert session['passed'] is True and [row['exit_code'] for row in session['checks']] == [0, 1, 0]
assert all(row['passed'] for row in session['checks'])
assert session['hyprland_sha256'] == prep['payload']['usr/lib/symbi/hyprland/bin/Hyprland']['sha256']
for name, digest in session['defaults_sha256'].items():
    assert digest == prep['overlay']['usr/share/symbiont/defaults/hypr/'+name]['sha256']
assert len(build['checks']) == 11 and all(row['passed'] for row in build['checks'])
assert build['all_containers_absent'] is True and len(build['containers']) == 13
assert all(row == {'removed': True, 'absent': True} for row in build['containers'].values())
assert not (evidence/'all-containers-absent-stdout.log').read_text().strip()
assert build['image_build_limits_verified'] == {'memory.max':'2147483648','memory.swap.max':'0','cpu.max':'100000 100000','pids.max':'128'}
for label, counters in [('preparation', prep['cgroup_final']), ('build_tree', build['image_build_cgroup_final']),
                        ('installer', install['cgroup_final']), ('parent', build['cgroup_final'])]:
    events = dict(line.split() for line in counters['memory.events'].splitlines())
    assert events['oom'] == events['oom_kill'] == '0', label
assert build['image_archive']['image_id'] == build['image_id']

# Independently render the approved public trust inputs and bind the installed
# file hashes to them. This does not claim signature/update enforcement tests.
import tempfile
from image.signing import render, write_bundle
release_path, bases_path = repo/'image/release-trust.json', repo/'image/base-images.json'
trust_record = prep['image_trust']
assert trust_record['release_trust_sha256'] == hashlib.sha256(release_path.read_bytes()).hexdigest()
assert trust_record['base_pins_sha256'] == hashlib.sha256(bases_path.read_bytes()).hexdigest()
assert trust_record['signature_qualified'] is False
assert trust_record['release_repositories'] == load(release_path)['repositories']
with tempfile.TemporaryDirectory(dir=root/'.cache') as temporary:
    directory = Path(temporary)/'containers'
    bundle = render(load(release_path), load(bases_path), repo)
    write_bundle(bundle, directory)
    for suffix in ('policy.json', 'registries.d/symbiont.yaml'):
        key = 'etc/containers/'+suffix
        data = (directory/suffix).read_bytes()
        sha = hashlib.sha256(data).hexdigest()
        assert trust_record['files'][key] == {'sha256': sha, 'bytes': len(data)}
        assert prep['payload'][key] == {'sha256': sha, 'bytes': len(data), 'mode': 0o644}
    policy = load(directory/'policy.json')
    assert policy['default'] == [{'type':'reject'}]
    assert len(policy['transports']['docker']) == 4
manifest = load(evidence/'image-manifest.json')
assert manifest == {'schema':1, 'built':True, 'os_qualified':False, 'source_commit':head,
                    'base':base, 'variant':'generic', 'archive':build['image_archive'],
                    'preparation_sha256':hashlib.sha256((evidence/'preparation.json').read_bytes()).hexdigest()}
assert manifest['archive'] == {
    'name':'symbiont-os-generic.oci.tar.gz', 'bytes':4034269486,
    'sha256':'7c1f6a7896c22ff70bc9fca7a1822d1144ad755c18bc032583081c6e71ce8156',
    'image_id':'sha256:68a9d7bcdbf15413a897821de45c2c20a76a9197bea1fdbcf2aeec56edcb483c'}

result = {'schema': 1, 'independent_evidence_recheck_passed': True, 'source_commit': head,
          'base_signature_subject_verified': True, 'rpm_signatures_and_identities_rechecked': 5,
          'base_packages_preserved': len(before), 'installed_packages': len(after),
          'original_crypto_slots_preserved': len(old_config), 'installed_files_checked': 88,
          'dynamic_loaders_checked': 6, 'cli_provider_controls': 3, 'lua_controls': 3,
          'bootc_lint': (evidence/'bootc-lint-stdout.log').read_text(),
          'temporary_containers_removed_and_absent': 13, 'oom_or_kill': False,
          'image_archive': build['image_archive'], 'os_qualified': False,
          'installed_approved_trust_files': trust_record['files'],
          'image_manifest_sha256': hashlib.sha256((evidence/'image-manifest.json').read_bytes()).hexdigest(),
          'signature_qualified': False,
          'limitations': 'Evidence reconciliation only; large OCI archive stays hosted. No VM boot, desktop interaction, TLS-policy equivalence, Fedora sandbox/escape, OS signature/update or rollback qualification.'}
(root/'.cache/desktop-45758278776-independent-check.json').write_text(json.dumps(result, indent=2)+'\n')
print(json.dumps(result, indent=2))
