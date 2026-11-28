"""Fail closed before executing reused runtime binaries or signed inputs."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import warnings
import zipfile


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    'fixture_inputs', ROOT / 'image/container/hosted/inputs.py')
inputs = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inputs)


class RuntimeArchive(unittest.TestCase):
    def fixture_output(self, root):
        work = root / 'work'
        output = work / 'fixture-output'
        output.mkdir(parents=True)
        fixture_source = {
            'revision': '1' * 40,
            'tree': '2' * 40,
            'runtime_source_revision': '3' * 40,
            'drivers': {
                driver: hashlib.sha256(driver.encode()).hexdigest()
                for driver in inputs.FIXTURE_CASES
            },
        }
        setup = {
            'runsc': '/usr/bin/runsc',
            'source_revision': '3' * 40,
            'fixture_commit': '1' * 40,
            'patch_sha256': '4' * 64,
            'fixture_source': fixture_source,
            'fixture_source_lock_sha256': '5' * 64,
            'binary_sha256': '6' * 64,
            'image_id': 'sha256:' + '7' * 64,
        }
        runs = []
        for backend in ('docker', 'gvisor'):
            for driver, case_names in inputs.FIXTURE_CASES.items():
                stem = backend + '-' + Path(driver).stem
                runtime = 'runsc' if backend == 'gvisor' else 'runc'
                report = {field: 'fixture'
                          for field in inputs.FIXTURE_REPORT_FIELDS[driver]}
                report.update({
                    'passed': True,
                    'fixture': '/tmp/fixture',
                    'backend': backend,
                    'binary_sha256': setup['binary_sha256'],
                    'image': setup['image_id'],
                    'driver_sha256': fixture_source['drivers'][driver],
                    'provider_errors': [],
                    'remaining_workers': [],
                    'remaining_leases': [],
                })
                if backend == 'gvisor':
                    report['runsc'] = {'path': setup['runsc']}
                cases = []
                for name in case_names:
                    fields = (
                        inputs.FIXTURE_CASE_FIELDS[driver]
                        | inputs.FIXTURE_CASE_FIELDS_BY_NAME[driver][name])
                    case = {field: 'fixture' for field in fields}
                    case.update({
                        'name': name, 'passed': True, 'exit_code': 0,
                        'workers': [{'id': name, 'runtime': runtime}],
                    })
                    cases.append(case)
                report['cases'] = cases
                report_path = output / (stem + '.json')
                report_path.write_text(json.dumps(report) + '\n')
                log_path = output / (stem + '.log')
                log_path.write_text(stem + ' passed\n')
                command = [
                    'python3', '-B', 'scripts/' + driver, '--binary',
                    str(work / 'bin/symbi'), '--image', setup['image_id'],
                    '--report', str(report_path),
                ]
                if backend == 'gvisor':
                    command += [
                        '--gvisor', '--runsc-binary', setup['runsc']]
                runs.append({
                    'backend': backend, 'driver': driver,
                    'command': command, 'passed': True, 'exit_code': 0,
                    'elapsed_seconds': 1.0,
                    'log_sha256': inputs.digest(log_path),
                    'remaining_containers': [],
                    'report_sha256': inputs.digest(report_path),
                    'observed_runtimes': [runtime],
                })
        result = {
            'passed': True, 'qualified': False, 'runs': runs,
            'source_revision': setup['source_revision'],
            'fixture_commit': setup['fixture_commit'],
            'patch_sha256': setup['patch_sha256'],
            'fixture_source': fixture_source,
            'fixture_source_lock_sha256':
                setup['fixture_source_lock_sha256'],
            'binary_sha256': setup['binary_sha256'],
            'image_id': setup['image_id'], 'scope': inputs.FIXTURE_SCOPE,
        }
        (output / 'result.json').write_text(json.dumps(result) + '\n')
        return output, setup, result

    def test_root_rebinds_every_fixture_report_and_log_after_quiescence(self):
        with tempfile.TemporaryDirectory() as temp:
            output, setup, result = self.fixture_output(Path(temp))
            self.assertEqual(
                inputs.validate_fixture_output(output, setup), result)
            first = output / 'docker-test-filesystem-grants.log'
            first.write_text('rewritten after its test\n')
            with self.assertRaisesRegex(ValueError, 'receipt changed'):
                inputs.validate_fixture_output(output, setup)

    def test_root_rejects_coherently_rewritten_fixture_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            output, setup, result = self.fixture_output(Path(temp))
            report_path = output / 'docker-test-filesystem-grants.json'
            report = json.loads(report_path.read_text())
            report['passed'] = False
            report_path.write_text(json.dumps(report) + '\n')
            result['runs'][0]['report_sha256'] = inputs.digest(report_path)
            (output / 'result.json').write_text(json.dumps(result) + '\n')
            with self.assertRaisesRegex(ValueError, 'report changed'):
                inputs.validate_fixture_output(output, setup)

    def test_root_rejects_extra_report_and_case_authority_fields(self):
        for target in ('report', 'case'):
            with self.subTest(target=target), \
                    tempfile.TemporaryDirectory() as temp:
                output, setup, result = self.fixture_output(Path(temp))
                report_path = output / 'docker-test-filesystem-grants.json'
                report = json.loads(report_path.read_text())
                if target == 'report':
                    report['qualified'] = False
                else:
                    report['cases'][0]['authority'] = 'invented'
                report_path.write_text(json.dumps(report) + '\n')
                result['runs'][0]['report_sha256'] = inputs.digest(report_path)
                (output / 'result.json').write_text(json.dumps(result) + '\n')
                with self.assertRaisesRegex(ValueError, 'report changed'):
                    inputs.validate_fixture_output(output, setup)

    def test_hosted_source_exactly_matches_native_lock(self):
        hosted = json.loads((
            ROOT / 'image/container/hosted/inputs.lock.json').read_text())
        native = json.loads((
            ROOT / 'image/container/native-fixture.lock.json').read_text())
        selected = inputs.validate_fixture_source_lock(hosted, native)
        self.assertEqual(selected['revision'], native['revision'])
        self.assertEqual(selected['tree'], native['tree'])
        self.assertEqual(selected['drivers'], native['drivers'])
        self.assertEqual(hosted['fixture_execution'], {
            'state': 'passed',
            'event': 'pull_request',
            'pull_request': 6,
            'conclusion': 'success',
            'run_id': 45995824985,
            'run_attempt': 1,
            'head': 'cdd8e7d931ddf90f1fe8afb22d12df9c539320b4',
            'checked_merge': '2189acad039387cd48116c11934da383bea8e653',
            'job_id': 140494839919,
            'source_revision': native['revision'],
            'source_tree': native['tree'],
            'artifact': {
                'id': 15196575712,
                'name': 'container-fixture-evidence',
                'bytes': 293698,
                'sha256': '8b9d8f59f66348ff42625cb313bffc21cead77bb0b152563c6b236313aa99ad0',
            },
            'passed': True,
            'qualified': False,
        })
        hosted_root = ROOT / 'image/container/hosted'
        for relative, expected in hosted['input_sha256'].items():
            with self.subTest(input=relative):
                self.assertEqual(
                    inputs.digest(hosted_root / relative), expected)

        pending = copy.deepcopy(hosted)
        pending['fixture_execution'] = {
            'state': 'pending',
            'run_id': None,
            'head': None,
            'source_revision': native['revision'],
            'source_tree': native['tree'],
        }
        inputs.validate_fixture_source_lock(pending, native)

        variants = []
        for field in ('fixture_commit', 'fixture_tree', 'source_revision'):
            changed = copy.deepcopy(hosted)
            changed[field] = '0' * 40
            variants.append((changed, native))
        changed = copy.deepcopy(hosted)
        changed['fixture_drivers']['test-git-source.py'] = '0' * 64
        variants.append((changed, native))
        changed_native = copy.deepcopy(native)
        changed_native['qualified'] = True
        variants.append((hosted, changed_native))
        changed_native = copy.deepcopy(native)
        changed_native['drivers']['extra.py'] = '0' * 64
        variants.append((hosted, changed_native))
        changed = copy.deepcopy(hosted)
        changed['runtime_artifact_validation']['run_id'] = 0
        variants.append((changed, native))

        execution_mutations = (
            (('state',), 'pending'),
            (('event',), 'push'),
            (('pull_request',), 7),
            (('conclusion',), 'failure'),
            (('run_id',), 45995824986),
            (('run_attempt',), 2),
            (('head',), '0' * 40),
            (('checked_merge',), '0' * 40),
            (('job_id',), 140494839920),
            (('source_revision',), '0' * 40),
            (('source_tree',), '0' * 40),
            (('artifact', 'id'), 15196575713),
            (('artifact', 'name'), 'other-evidence'),
            (('artifact', 'bytes'), 293699),
            (('artifact', 'sha256'), '0' * 64),
            (('passed',), False),
            (('passed',), 1),
            (('qualified',), True),
            (('qualified',), 0),
        )
        for path, value in execution_mutations:
            changed = copy.deepcopy(hosted)
            target = changed['fixture_execution']
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            variants.append((changed, native))

        changed = copy.deepcopy(pending)
        changed['fixture_execution']['unexpected'] = None
        variants.append((changed, native))
        changed = copy.deepcopy(hosted)
        changed['fixture_execution']['unexpected'] = None
        variants.append((changed, native))
        for changed_hosted, changed_native in variants:
            with self.subTest(hosted=changed_hosted, native=changed_native), \
                    self.assertRaises(ValueError):
                inputs.validate_fixture_source_lock(
                    changed_hosted, changed_native)

    def fixture(self, directory, extra=None):
        payload = b'fixture bytes; not an executable'
        archive = directory / 'binaries.zip'
        with zipfile.ZipFile(archive, 'w') as stream:
            stream.writestr('symbi', payload)
            if extra:
                with warnings.catch_warnings():
                    warnings.filterwarnings('ignore', 'Duplicate name:', UserWarning)
                    stream.writestr(extra, payload)
        lock = {'artifact': {'bytes': archive.stat().st_size, 'sha256': inputs.digest(archive)},
                'binaries': {'symbi': {'bytes': len(payload), 'sha256': hashlib.sha256(payload).hexdigest()}}}
        return archive, lock

    def test_verified_bytes_become_executable(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive, lock = self.fixture(root)
            inputs.unpack_runtime(archive, lock, root / 'bin')
            self.assertEqual((root / 'bin/symbi').stat().st_mode & 0o777, 0o755)

    def test_modified_or_unexpected_archive_members_are_refused(self):
        for extra in ('../escape', 'another-binary', 'symbi'):
            with self.subTest(extra=extra), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                archive, lock = self.fixture(root, extra)
                with self.assertRaises(ValueError):
                    inputs.unpack_runtime(archive, lock, root / 'bin')
                self.assertFalse((root / 'bin').exists())

    def test_binary_hash_mismatch_never_creates_executable(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive, lock = self.fixture(root)
            lock['binaries']['symbi']['sha256'] = '0' * 64
            with self.assertRaises(ValueError):
                inputs.unpack_runtime(archive, lock, root / 'bin')
            self.assertFalse((root / 'bin/symbi').stat().st_mode & 0o111)

    def test_archive_digest_mismatch_prevents_extraction(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive, lock = self.fixture(root)
            lock['artifact']['sha256'] = '0' * 64
            with self.assertRaises(ValueError):
                inputs.unpack_runtime(archive, lock, root / 'bin')
            self.assertFalse((root / 'bin').exists())

    def test_signature_status_requires_exact_valid_signer(self):
        fingerprint = '1' * 40
        inputs.require_signature(0, '[GNUPG:] VALIDSIG ' + fingerprint + ' 2026-11-25 rest\n', fingerprint)
        for status, text in [(1, '[GNUPG:] VALIDSIG ' + fingerprint),
                             (0, '[GNUPG:] GOODSIG short-id example'),
                             (0, '[GNUPG:] VALIDSIG ' + '2' * 40),
                             (0, '[GNUPG:] VALIDSIG ' + fingerprint + '\n[GNUPG:] BADSIG x y')]:
            with self.subTest(status=status, text=text), self.assertRaises(ValueError):
                inputs.require_signature(status, text, fingerprint)

    def test_public_evidence_refuses_links_to_private_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / 'public'
            source.mkdir()
            (root / 'private-key').write_text('synthetic private fixture')
            (source / 'report.log').symlink_to(root / 'private-key')
            with self.assertRaises(ValueError):
                inputs.collect_public(source, root / 'retained')
            self.assertFalse((root / 'retained').exists())

    def test_public_evidence_refuses_private_pem_but_copies_public_report(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / 'public'
            source.mkdir()
            report = source / 'result.json'
            report.write_text(json.dumps({'qualified': False, 'passed': False}) + '\n')
            (source / 'diagnostic.log').write_text('-----BEGIN PRIVATE KEY-----\nfixture\n')
            with self.assertRaises(ValueError):
                inputs.collect_public(source, root / 'retained')
            self.assertFalse((root / 'retained').exists())
            (source / 'diagnostic.log').unlink()
            inputs.collect_public(source, root / 'retained')
            self.assertEqual((root / 'retained/result.json').read_bytes(), report.read_bytes())
            self.assertEqual(
                (root / 'retained').stat().st_mode & 0o777, 0o755)
            self.assertEqual(
                (root / 'retained/result.json').stat().st_mode & 0o777,
                0o644)

    def test_outer_public_evidence_rejects_misleading_generic_file(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / 'public'
            source.mkdir()
            (source / 'result.json').write_text(
                json.dumps({'passed': False, 'qualified': False}) + '\n')
            (source / 'qualified.txt').write_text('synthetic claim\n')
            destination = root / 'retained'
            with self.assertRaisesRegex(ValueError, 'exact plan'):
                inputs.collect_public(
                    source, destination,
                    expected_paths={'result.json'})
            self.assertFalse(destination.exists())

    def test_public_evidence_publish_is_atomic_and_cleans_failed_staging(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / 'public'
            source.mkdir()
            (source / 'result.json').write_text(
                json.dumps({'passed': False, 'qualified': False}) + '\n')
            destination = root / 'retained'
            with mock.patch.object(
                    inputs.os, 'rename', side_effect=OSError('synthetic stop')):
                with self.assertRaises(OSError):
                    inputs.collect_public(source, destination)
            self.assertFalse(destination.exists())
            self.assertEqual(
                [path.name for path in root.iterdir()], ['public'])

    def public_package_fixture(self, root):
        source = root / 'public'
        nested = source / 'fixture-packages' / 'metadata'
        nested.mkdir(parents=True)
        releases = {
            'noble_InRelease': b'noble signed release\n',
            'noble-updates_InRelease': b'noble updates signed release\n',
            'noble-security_InRelease': b'noble security signed release\n',
        }
        indexes = {
            name: (name + '\n').encode()
            for name in inputs.SELECTED_PACKAGE_INDEXES
        }
        manifest = b'{"selected":false,"qualified":false}\n'
        for name, content in {**releases, **indexes}.items():
            (nested / name).write_bytes(content)
        (source / 'fixture-packages' / 'package-manifest.json').write_bytes(
            manifest)
        (source / 'fixture-packages' / 'packages.tsv').write_text(
            'python3\t3.12.3-0ubuntu2\n')

        def bound(name, raw):
            return {
                'filename': name, 'bytes': len(raw),
                'sha256': hashlib.sha256(raw).hexdigest(),
            }

        lock = {
            'state': 'selected',
            'selected': True,
            'candidate': {
                'manifest': {
                    'path': 'manifest.json', 'bytes': len(manifest),
                    'sha256': hashlib.sha256(manifest).hexdigest(),
                },
                'release_metadata': [
                    {'inrelease': bound(name, releases[name])}
                    for name in sorted(releases)
                ],
                'package_indexes': [
                    bound(name, indexes[name]) for name in sorted(indexes)
                ],
                'packages': [{
                    'package': 'python3', 'version': '3.12.3-0ubuntu2',
                    'architecture': 'amd64',
                }],
            },
        }
        lock_path = (
            root / 'image/container/ubuntu-fixture-packages.lock.json')
        lock_path.parent.mkdir(parents=True)
        lock_path.write_text(json.dumps(lock) + '\n')
        bindings = inputs.selected_public_bindings(lock_path)
        return source, bindings, {**releases, **indexes}, manifest

    def test_public_evidence_copies_complete_nested_selected_metadata(self):
        selected_indexes = {
            'noble_main_binary-amd64_Packages.xz',
            'noble-updates_main_binary-amd64_Packages.xz',
            'noble-security_main_binary-amd64_Packages.xz',
        }
        self.assertEqual(inputs.SELECTED_PACKAGE_INDEXES, selected_indexes)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, bindings, metadata, manifest = self.public_package_fixture(
                root)

            retained = root / 'retained'
            inputs.collect_public(source, retained, bindings)

            copied = retained / 'fixture-packages' / 'metadata'
            self.assertEqual(
                {path.name: path.read_bytes() for path in copied.iterdir()},
                metadata,
            )
            self.assertEqual(
                (retained / 'fixture-packages/package-manifest.json').read_bytes(),
                manifest,
            )
            self.assertEqual(
                (retained / 'fixture-packages/packages.tsv').read_text(),
                'python3\t3.12.3-0ubuntu2\n',
            )
            self.assertEqual(
                (retained / 'fixture-packages/metadata').stat().st_mode
                & 0o777, 0o755)
            self.assertTrue(all(
                path.stat().st_mode & 0o777 == 0o644
                for path in retained.rglob('*') if path.is_file()))

    def test_public_evidence_binds_selected_paths_hashes_and_completeness(self):
        mutations = ('wrong-path', 'wrong-hash', 'missing', 'extra', 'packages')
        for mutation in mutations:
            with self.subTest(mutation=mutation), \
                    tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                source, bindings, _, _ = self.public_package_fixture(root)
                selected = (
                    source / 'fixture-packages/metadata/noble_InRelease')
                if mutation == 'wrong-path':
                    selected.rename(source / 'noble_InRelease')
                elif mutation == 'wrong-hash':
                    selected.write_bytes(b'changed selected release\n')
                elif mutation == 'missing':
                    selected.unlink()
                elif mutation == 'extra':
                    (source / 'fixture-packages/qualified.json').write_text(
                        '{"qualified":true}\n')
                else:
                    (source / 'fixture-packages/packages.tsv').write_text(
                        'other\t1\n')
                with self.assertRaises(ValueError):
                    inputs.collect_public(
                        source, root / 'retained', bindings)
                self.assertFalse((root / 'retained').exists())

    def test_public_evidence_rejects_every_unselected_xz_basename(self):
        rejected = (
            'Packages.xz',
            'noble_main_binary-arm64_Packages.xz',
            'noble-updates_universe_binary-amd64_Packages.xz',
            'noble-security_main_binary-amd64_Sources.xz',
        )
        for name in rejected:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                source = root / 'public'
                source.mkdir()
                (source / name).write_bytes(b'unselected compressed index')
                with self.assertRaisesRegex(
                        ValueError, 'Selected package evidence path or bytes changed'):
                    inputs.collect_public(source, root / 'retained')
                self.assertFalse((root / 'retained').exists())

    def test_fixture_image_normalizes_only_evidence_modes_after_writes(self):
        dockerfile = (
            ROOT / 'image/container/hosted/fixture/Dockerfile').read_text()
        evidence = '/usr/share/symbi-fixture-evidence'
        directory_modes = (
            f'find {evidence} -xdev -type d -exec chmod 0755 {{}} +')
        file_modes = (
            f'find {evidence} -xdev -type f -exec chmod 0644 {{}} +')

        self.assertEqual(dockerfile.count(directory_modes), 1)
        self.assertEqual(dockerfile.count(file_modes), 1)
        self.assertEqual(dockerfile.count('chmod '), 2)
        self.assertLess(
            dockerfile.index("dpkg-query -W -f"),
            dockerfile.index(directory_modes),
        )
        self.assertLess(
            dockerfile.index(directory_modes), dockerfile.index(file_modes))
        self.assertNotIn('chmod -R', dockerfile)


if __name__ == '__main__':
    unittest.main()
