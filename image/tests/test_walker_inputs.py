"""Reject source drift, alternative registries and replacement base packages."""
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('walker_inputs', Path(__file__).parents[1]/'walker/inputs.py')
inputs = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inputs)


class WalkerInputs(unittest.TestCase):
    def fixture(self, source, registry='registry+https://github.com/rust-lang/crates.io-index', checksum='a'*64):
        files = {
            'Cargo.toml': '[package]\nname="walker"\nversion="2.17.2"\n',
            'Cargo.lock': ('version=4\n[[package]]\nname="walker"\nversion="2.17.2"\n'
                           '[[package]]\nname="example"\nversion="1.0.0"\n'
                           f'source="{registry}"\nchecksum="{checksum}"\n'),
            'build.rs': 'fn main() {}\n',
        }
        pins = {'version': '2.17.2'}
        for name, content in files.items():
            (source/name).write_text(content)
            pins[name.lower().replace('.', '_')+'_sha256'] = hashlib.sha256(content.encode()).hexdigest()
        return pins

    def test_exact_source_and_checksummed_registry_graph_are_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            pins = self.fixture(source)
            self.assertEqual(inputs.require_source(source, pins), {'packages': 2, 'registry_dependencies': 1})

    def test_manifest_lock_build_script_and_source_config_drift_are_refused(self):
        for name in ('Cargo.toml', 'Cargo.lock', 'build.rs', '.cargo/config.toml'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                source = Path(directory)
                pins = self.fixture(source)
                path = source/name
                path.parent.mkdir(exist_ok=True)
                path.write_text(path.read_text()+'\n#changed\n' if path.exists() else '[net]\noffline=false\n')
                with self.assertRaises(ValueError):inputs.require_source(source, pins)

    def test_git_alternative_registry_and_missing_checksum_are_refused(self):
        for registry, checksum in (('git+https://example.test/repository', 'a'*64),
                                   ('registry+https://example.test/index', 'a'*64),
                                   ('registry+https://github.com/rust-lang/crates.io-index', '')):
            with self.subTest(registry=registry, checksum=checksum), tempfile.TemporaryDirectory() as directory:
                source = Path(directory)
                pins = self.fixture(source, registry, checksum)
                with self.assertRaises(ValueError):inputs.require_source(source, pins)

    def test_registry_replacement_and_duplicate_package_entries_are_refused(self):
        for suffix in ('[[patch.crates-io.example]]\npath="/tmp/override"\n', ''):
            with self.subTest(suffix=suffix), tempfile.TemporaryDirectory() as directory:
                source = Path(directory)
                pins = self.fixture(source)
                if suffix:
                    path = source/'Cargo.toml'
                    path.write_text(path.read_text()+suffix)
                    pins['cargo_toml_sha256'] = inputs.digest(path)
                else:
                    path = source/'Cargo.lock'
                    path.write_text(path.read_text()+'[[package]]\nname="walker"\nversion="2.17.2"\n')
                    pins['cargo_lock_sha256'] = inputs.digest(path)
                with self.assertRaises(ValueError):inputs.require_source(source, pins)

    def test_signed_toolchain_requires_exact_stable_release_and_host(self):
        valid = 'rustc 1.100.0 (abcdef 2026-01-01)\nbinary: rustc\nrelease: 1.100.0\nhost: x86_64-unknown-linux-gnu\n'
        inputs.require_rust_identity(valid, 'rustc')
        for changed in (valid.replace('1.100.0', '1.101.0'), valid.replace('release: 1.100.0', 'release: 1.100.0-nightly'),
                        valid.replace('x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-gnu'), valid+'release: 1.100.0\n'):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                inputs.require_rust_identity(changed, 'rustc')
        cargo = 'cargo 1.100.0 (abcdef 2026-01-01)\nrelease: 1.100.0\nhost: x86_64-unknown-linux-gnu\n'
        inputs.require_rust_identity(cargo, 'cargo')

    def test_only_additions_to_the_original_base_are_accepted(self):
        before = ['base\t0\t1\t1.fc45\tx86_64']
        added = ['new\t0\t1\t1.fc45\tx86_64']
        inputs.require_additive(before, before+added, added)
        for after, expected in ((added, added), (before+added+['unexpected'], added),
                                (before+before+added, added), (before, []),
                                (before+['base\t0\t2\t1.fc45\tx86_64'], ['base\t0\t2\t1.fc45\tx86_64'])):
            with self.subTest(after=after), self.assertRaises(ValueError):inputs.require_additive(before, after, expected)


    def test_reviewed_rpm_epochs_are_part_of_exact_identity(self):
        observed = [('gpgmepp-devel\t1\t2.0.0\t2.fc45\tx86_64', 'gpgmepp-devel-1:2.0.0-2.fc45.x86_64'),
                    ('libpng-devel\t2\t1.6.59\t1.fc45\tx86_64', 'libpng-devel-2:1.6.59-1.fc45.x86_64'),
                    ('openssl-devel\t1\t4.0.3\t1.fc45\tx86_64', 'openssl-devel-1:4.0.3-1.fc45.x86_64'),
                    ('xz-devel\t1\t5.8.3\t2.fc45\tx86_64', 'xz-devel-1:5.8.3-2.fc45.x86_64'),
                    ('cargo\t0\t1.100.0\t1.fc45\tx86_64', 'cargo-1.100.0-1.fc45.x86_64')]
        for identity, pinned in observed:
            with self.subTest(identity=identity):
                inputs.require_package_identity(identity, pinned)
                fields = identity.split('\t')
                for index in range(5):
                    changed = fields.copy()
                    changed[index] = '3' if index == 1 else 'changed'
                    with self.subTest(field=index), self.assertRaises(ValueError):
                        inputs.require_package_identity('\t'.join(changed), pinned)

    def test_missing_noncanonical_or_unpinned_epoch_is_refused(self):
        pinned = 'gpgmepp-devel-1:2.0.0-2.fc45.x86_64'
        for epoch in ('', '(none)', '01', '-1', '0', '2'):
            with self.subTest(epoch=epoch), self.assertRaises(ValueError):
                inputs.require_package_identity('gpgmepp-devel\t'+epoch+'\t2.0.0\t2.fc45\tx86_64', pinned)
        with self.assertRaises(ValueError):
            inputs.require_package_identity('gpgmepp-devel\t1\t2.0.0\t2.fc45\tx86_64', pinned.replace('1:', ''))


if __name__ == '__main__':
    unittest.main()
