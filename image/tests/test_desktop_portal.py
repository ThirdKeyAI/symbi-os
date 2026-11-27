"""Install only the retained runtime and activate the patched absolute executable."""
import hashlib
from pathlib import Path
import tempfile
import unittest

from image.desktop.portal import select_consent_files, verify_activation


SYSTEMD = '''[Unit]
Description=Portal service (Hyprland implementation)
PartOf=graphical-session.target
After=graphical-session.target
ConditionEnvironment=WAYLAND_DISPLAY

[Service]
Type=dbus
BusName=org.freedesktop.impl.portal.desktop.hyprland
ExecStart=/usr/lib/symbi/portal/libexec/xdg-desktop-portal-hyprland
Restart=on-failure
Slice=session.slice
'''
DBUS = '''[D-BUS Service]
Name=org.freedesktop.impl.portal.desktop.hyprland
Exec=/usr/lib/symbi/portal/libexec/xdg-desktop-portal-hyprland
SystemdService=xdg-desktop-portal-hyprland.service
'''
DESCRIPTOR = '''[portal]
DBusName=org.freedesktop.impl.portal.desktop.hyprland
Interfaces=org.freedesktop.impl.portal.Screenshot;org.freedesktop.impl.portal.ScreenCast;org.freedesktop.impl.portal.GlobalShortcuts;org.freedesktop.impl.portal.InputCapture;
UseIn=wlroots;Hyprland;sway;Wayfire;river;
'''
PREFERENCE = '''[preferred]
default=gtk
org.freedesktop.impl.portal.ScreenCast=hyprland
org.freedesktop.impl.portal.Screenshot=hyprland
'''


class DesktopPortal(unittest.TestCase):
    def fixture(self, root):
        files = {}
        for name in ('bin/hyprland-share-picker', 'libexec/xdg-desktop-portal-hyprland',
                     'lib/libhyprtoolkit.so.0.6.0', 'share/licenses/hyprtoolkit/LICENSE',
                     'share/licenses/xdg-desktop-portal-hyprland/LICENSE',
                     'share/licenses/symbi-os-portal-patch/LICENSE', 'include/development.h', 'lib/pkgconfig/development.pc'):
            path = root/name; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'non-executable test fixture'); path.chmod(0o755 if name.startswith(('bin/', 'libexec/', 'lib/lib')) else 0o644)
        for name, target in [('lib/libhyprtoolkit.so', 'libhyprtoolkit.so.6'), ('lib/libhyprtoolkit.so.6', 'libhyprtoolkit.so.0.6.0')]:
            (root/name).symlink_to(target)
        for name, content in [('lib/systemd/user/xdg-desktop-portal-hyprland.service', SYSTEMD),
                              ('share/dbus-1/services/org.freedesktop.impl.portal.desktop.hyprland.service', DBUS),
                              ('share/xdg-desktop-portal/portals/hyprland.portal', DESCRIPTOR)]:
            path = root/name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text(content); path.chmod(0o644)
        for path in root.rglob('*'):
            name = path.relative_to(root).as_posix()
            if path.is_symlink(): files[name] = {'link': path.readlink().as_posix()}
            elif path.is_file(): files[name] = {'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'bytes': path.stat().st_size, 'mode': path.stat().st_mode & 0o7777}
        return {'files': files}

    def test_runtime_selection_preserves_links_and_licenses_and_excludes_development_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); manifest = self.fixture(root)
            selected = select_consent_files(root, manifest)
            self.assertEqual(len(selected), 11)
            self.assertEqual(sum(name.startswith('usr/lib/symbi/portal/') for name in selected), 8)
            self.assertIn('usr/share/dbus-1/services/org.freedesktop.impl.portal.desktop.hyprland.service', selected)
            self.assertIn('usr/lib/systemd/user/xdg-desktop-portal-hyprland.service', selected)
            self.assertTrue(selected['usr/lib/symbi/portal/lib/libhyprtoolkit.so'].is_symlink())
            self.assertFalse(any('include/' in name or 'pkgconfig/' in name for name in selected))

    def test_changed_missing_extra_linked_or_unsafe_files_are_refused(self):
        for kind in ('bytes', 'missing', 'extra', 'link', 'mode'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve(); manifest = self.fixture(root)
                path = root/'bin/hyprland-share-picker'
                if kind == 'bytes': path.write_bytes(b'changed')
                elif kind == 'missing': path.unlink()
                elif kind == 'extra': (root/'bin/unreviewed').write_bytes(b'extra')
                elif kind == 'mode': path.chmod(0o4755)
                else: path.unlink(); path.symlink_to('/etc/passwd')
                with self.assertRaises(ValueError): select_consent_files(root, manifest)

    def test_changed_activation_command_or_scope_is_refused_even_with_updated_inventory(self):
        for original, replacement in (('/usr/lib/symbi/portal/libexec/xdg-desktop-portal-hyprland', '/bin/sh -c override'),
                                      ('Type=dbus', 'Type=simple'), ('Restart=on-failure', 'Restart=on-failure\nExecStartPre=/bin/true')):
            with self.subTest(replacement=replacement), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve(); manifest = self.fixture(root)
                name = 'lib/systemd/user/xdg-desktop-portal-hyprland.service'; path = root/name
                path.write_text(path.read_text().replace(original, replacement))
                manifest['files'][name].update(sha256=hashlib.sha256(path.read_bytes()).hexdigest(), bytes=path.stat().st_size)
                with self.assertRaises(ValueError): select_consent_files(root, manifest)

    def test_installed_vendor_selection_has_explicit_backend_and_no_wlr_fallback(self):
        for kind in ('valid', 'fallback', 'path', 'missing', 'linked'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve(); prefix = root/'source'; prefix.mkdir(); manifest = self.fixture(prefix)
                for name, source in select_consent_files(prefix, manifest).items():
                    target = root/name; target.parent.mkdir(parents=True, exist_ok=True)
                    if source.is_symlink(): target.symlink_to(source.readlink())
                    else: target.write_bytes(source.read_bytes())
                preference = root/'usr/share/xdg-desktop-portal/hyprland-portals.conf'; preference.write_text(PREFERENCE)
                if kind == 'valid':
                    result = verify_activation(root)
                    self.assertTrue(result['passed']); self.assertFalse(result['interactive_session_qualified'])
                    continue
                if kind == 'fallback': preference.write_text(PREFERENCE.replace('ScreenCast=hyprland', 'ScreenCast=hyprland;wlr'))
                elif kind == 'missing': preference.unlink()
                elif kind == 'linked': preference.unlink(); preference.symlink_to('/etc/passwd')
                else:
                    path = root/'usr/share/dbus-1/services/org.freedesktop.impl.portal.desktop.hyprland.service'
                    path.write_text(DBUS.replace('/usr/lib/symbi/portal/libexec/', '/usr/bin/'))
                with self.assertRaises(ValueError): verify_activation(root)


if __name__ == '__main__': unittest.main()
