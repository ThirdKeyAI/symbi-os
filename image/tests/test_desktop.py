"""Assembly must preserve the base and admit only reviewed runtime inputs."""
import copy
from pathlib import Path
import tempfile
import unittest

from image.desktop.prepare import copy_regular
from image.desktop.inputs import required_package_delta, require_transaction, select_prefix_files
from image.desktop.recipe import render_desktop, review_containerfile


class DesktopAssembly(unittest.TestCase):
    def test_payload_copy_preserves_bytes_and_mode_and_rejects_links_or_overwrites(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = root/'source'; source.write_bytes(b'non-executable fixture' * 100)
            target = root/'payload/binary'
            copy_regular(source, target, executable=True)
            self.assertEqual(source.read_bytes(), target.read_bytes())
            self.assertEqual(target.stat().st_mode & 0o777, 0o755)
            with self.assertRaises(ValueError): copy_regular(source, target)
            (root/'linked').symlink_to(source)
            with self.assertRaises(ValueError): copy_regular(root/'linked', root/'other')

    def test_only_missing_exact_packages_are_added(self):
        before = ['base\t0\t1\t1.fc45\tx86_64', 'library\t1\t3\t1.fc45\tx86_64']
        required = ['library\t1\t3\t1.fc45\tx86_64', 'new\t0\t2\t1.fc45\tx86_64']
        self.assertEqual(required_package_delta(before, required), [required[1]])
        require_transaction(before, before + [required[1]], required)
        require_transaction(before, before, [required[0]])

    def test_replacement_removal_extra_or_ambiguous_packages_are_refused(self):
        before = ['base\t0\t1\t1.fc45\tx86_64']
        required = ['new\t0\t2\t1.fc45\tx86_64']
        for bad in (['base\t0\t2\t1.fc45\tx86_64'], required * 2, ['malformed'],
                    required + ['new\t0\t3\t1.fc45\tx86_64']):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                required_package_delta(before, bad)
        for after in (required, before, before + required + ['extra\t0\t1\t1.fc45\tx86_64']):
            with self.subTest(after=after), self.assertRaises(ValueError):
                require_transaction(before, after, required)

    def prefix(self, root):
        for name in ('bin/Hyprland', 'bin/hyprctl', 'bin/hyprwayland-scanner', 'bin/hyprpm',
                     'include/header.h', 'lib/libtest.so.1', 'lib/libtest.a',
                     'lib/pkgconfig/test.pc', 'share/hyprland/background.png'):
            path = root/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'non-executable fixture')
        (root/'lib/libtest.so').symlink_to('libtest.so.1')

    def test_runtime_prefix_excludes_compiler_and_package_manager_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); self.prefix(root)
            selected = select_prefix_files(root)
            self.assertEqual(set(selected), {'bin/Hyprland', 'bin/hyprctl', 'lib/libtest.so.1',
                                             'lib/libtest.so', 'share/hyprland/background.png'})

    def test_runtime_prefix_refuses_escaping_or_linked_parents(self):
        for parent in (False, True):
            with self.subTest(parent=parent), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); self.prefix(root)
                if parent:
                    (root/'share/hyprland/background.png').unlink()
                    (root/'share/hyprland').rmdir()
                    (root/'share/hyprland').symlink_to('/tmp', target_is_directory=True)
                else:
                    (root/'lib/libtest.so').unlink()
                    (root/'lib/libtest.so').symlink_to('/etc/passwd')
                with self.assertRaises(ValueError): select_prefix_files(root)

    def recipe_fixture(self, root):
        import hashlib
        key = root/'image/keys/base.pub'; key.parent.mkdir(parents=True); key.write_bytes(b'public fixture')
        pin = {'image': 'ghcr.io/example/base@sha256:'+'1'*64,
               'public_key': 'image/keys/base.pub', 'public_key_sha256': hashlib.sha256(key.read_bytes()).hexdigest()}
        pins = {'schema': 1, 'variants': {'generic': pin, 'nvidia': copy.deepcopy(pin)}}
        recipe = render_desktop(pins, 'generic', root)
        snippets = recipe['modules'][0]['snippets']
        text = '\n'.join(['ARG BASE_IMAGE="'+pin['image']+'"', 'FROM "${BASE_IMAGE}" AS symbiont-os',
                         'FROM scratch AS stage-files', 'WORKDIR /files', 'FROM scratch AS stage-keys',
                         'FROM symbiont-os', 'ARG TARGETARCH',
                         'RUN --mount=type=bind,src=.bluebuild-scripts_a654ee88,dst=/scripts/,ro /scripts/pre_build.sh',
                         *snippets,
                         'RUN --mount=type=bind,src=.bluebuild-scripts_a654ee88,dst=/scripts/,ro /scripts/post_build.sh'])+'\n'
        return pins, recipe, text

    def test_desktop_recipe_installs_before_hardening_and_preserves_base_pin(self):
        with tempfile.TemporaryDirectory() as directory:
            pins, recipe, text = self.recipe_fixture(Path(directory))
            review_containerfile(text, recipe, pins['variants']['generic']['image'])
            snippets = recipe['modules'][0]['snippets']
            self.assertLess(next(i for i, s in enumerate(snippets) if 'install.py' in s),
                            next(i for i, s in enumerate(snippets) if 'RUN bash' in s))
            self.assertTrue(any('COPY --chown=0:0 payload/' in s for s in snippets))

    def test_generated_file_rejects_extra_images_commands_and_missing_hardening(self):
        with tempfile.TemporaryDirectory() as directory:
            pins, recipe, text = self.recipe_fixture(Path(directory))
            for changed in (text+'FROM example.invalid/new:latest\n', text+'RUN curl example.invalid\n',
                            text.replace('1'*64, '2'*64), text.replace('RUN bash', 'RUN true # bash'),
                            text+'ENV OPENSSL_CONF=/untrusted\n',
                            text.replace('FROM "${BASE_IMAGE}"', 'ARG BASE_IMAGE="ghcr.io/example/base"\nFROM "${BASE_IMAGE}"')):
                with self.subTest(changed=changed[-100:]), self.assertRaises(ValueError):
                    review_containerfile(changed, recipe, pins['variants']['generic']['image'])
