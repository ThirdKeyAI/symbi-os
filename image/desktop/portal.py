"""Select the patched portal runtime and check its installed activation defaults."""
import configparser
import json
import os
from pathlib import Path


PRIVATE_FILES = {
    'bin/hyprland-share-picker', 'libexec/xdg-desktop-portal-hyprland',
    'lib/libhyprtoolkit.so.0.6.0', 'lib/libhyprtoolkit.so.6', 'lib/libhyprtoolkit.so',
    'share/licenses/hyprtoolkit/LICENSE', 'share/licenses/xdg-desktop-portal-hyprland/LICENSE',
    'share/licenses/symbi-os-portal-patch/LICENSE',
}
ACTIVATION = {
    'lib/systemd/user/xdg-desktop-portal-hyprland.service': {
        'Unit': {'Description': 'Portal service (Hyprland implementation)',
                 'PartOf': 'graphical-session.target', 'After': 'graphical-session.target',
                 'ConditionEnvironment': 'WAYLAND_DISPLAY'},
        'Service': {'Type': 'dbus', 'BusName': 'org.freedesktop.impl.portal.desktop.hyprland',
                    'ExecStart': '/usr/lib/symbi/portal/libexec/xdg-desktop-portal-hyprland',
                    'Restart': 'on-failure', 'Slice': 'session.slice'},
    },
    'share/dbus-1/services/org.freedesktop.impl.portal.desktop.hyprland.service': {
        'D-BUS Service': {'Name': 'org.freedesktop.impl.portal.desktop.hyprland',
                         'Exec': '/usr/lib/symbi/portal/libexec/xdg-desktop-portal-hyprland',
                         'SystemdService': 'xdg-desktop-portal-hyprland.service'},
    },
    'share/xdg-desktop-portal/portals/hyprland.portal': {
        'portal': {'DBusName': 'org.freedesktop.impl.portal.desktop.hyprland',
                   'Interfaces': 'org.freedesktop.impl.portal.Screenshot;org.freedesktop.impl.portal.ScreenCast;'
                                 'org.freedesktop.impl.portal.GlobalShortcuts;org.freedesktop.impl.portal.InputCapture;',
                   'UseIn': 'wlroots;Hyprland;sway;Wayfire;river;'},
    },
}
PREFERENCE = {'preferred': {'default': 'gtk', 'org.freedesktop.impl.portal.ScreenCast': 'hyprland',
                            'org.freedesktop.impl.portal.Screenshot': 'hyprland'}}


def require_config(path, expected):
    if (path.is_symlink() or not path.is_file() or path.resolve() != path
            or not 0 < path.stat().st_size <= 4096):
        raise ValueError('Expected a bounded regular portal activation file: '+str(path))
    parser = configparser.ConfigParser(interpolation=None, delimiters=('=',), strict=True)
    parser.optionxform = str
    try:
        parser.read_string(path.read_text())
    except (configparser.Error, UnicodeError) as error:
        raise ValueError('Malformed portal activation file') from error
    if parser.defaults() or {section: dict(parser[section]) for section in parser.sections()} != expected:
        raise ValueError('Portal activation command or backend selection changed: '+str(path))


def select_consent_files(prefix, manifest):
    from image.portal.consent_inputs import prefix_inventory
    inventory = prefix_inventory(prefix)
    if inventory != manifest['files'] or not (PRIVATE_FILES | set(ACTIVATION)).issubset(inventory):
        raise ValueError('Prepared portal prefix differs from its validated manifest')
    for name, expected in ACTIVATION.items():
        if inventory[name].get('mode') != 0o644: raise ValueError('Unsafe portal activation mode')
        require_config(prefix/name, expected)
    for name in PRIVATE_FILES:
        row = inventory[name]
        if name in ('lib/libhyprtoolkit.so', 'lib/libhyprtoolkit.so.6'):
            expected = 'libhyprtoolkit.so.6' if name.endswith('.so') else 'libhyprtoolkit.so.0.6.0'
            if row != {'link': expected}: raise ValueError('Portal runtime library link changed')
        elif row.get('mode') != (0o644 if name.startswith('share/') else 0o755):
            raise ValueError('Unsafe portal runtime mode or type')
    selected = {'usr/lib/symbi/portal/'+name: prefix/name for name in sorted(PRIVATE_FILES)}
    selected.update({'usr/'+name: prefix/name for name in sorted(ACTIVATION)})
    return selected


def verify_activation(root):
    for name, expected in ACTIVATION.items(): require_config(root/'usr'/name, expected)
    require_config(root/'usr/share/xdg-desktop-portal/hyprland-portals.conf', PREFERENCE)
    return {'passed': True, 'interactive_session_qualified': False,
            'scope': 'Installed vendor defaults and absolute activation paths; users can override portal preferences'}


if __name__ == '__main__':
    if os.geteuid() != 10001 or not Path('/run/.containerenv').exists():
        raise SystemExit('Use the unprivileged installed-image probe container')
    print(json.dumps(verify_activation(Path('/'))))
