"""Inspect installed payload bytes from an unprivileged read-only image container."""
import hashlib
import json
import os
from pathlib import Path
import subprocess


LEGACY_FONTLESS_SOURCE = "23a6c721092ad77c3af33c11cab230ecaaa54cff"


def verify_font_payload(source):
    """Check fonts, except for the exact retained image that predates them."""
    if "fonts" not in source:
        if source.get("source_commit") != LEGACY_FONTLESS_SOURCE:
            raise ValueError("Only the exact retained pre-font image may omit font evidence")
        return {"checked": False, "legacy_source_commit": LEGACY_FONTLESS_SOURCE,
                "scope": "Exact retained image predates the development font payload"}
    from font_verify import verify_installed_fonts
    return {"checked": True, **verify_installed_fonts(source["fonts"])}


def main():
    if os.geteuid() != 10001 or not Path('/run/.containerenv').exists():
        raise SystemExit('Use the unprivileged installed-image inspection container')
    source = json.loads(Path('/qualification/preparation.json').read_text())
    group = Path('/sys/fs/cgroup')/Path(Path('/proc/self/cgroup').read_text().strip().split('::', 1)[1]).relative_to('/')
    limits = {n: (group/n).read_text().strip() for n in ('memory.max', 'memory.swap.max', 'cpu.max', 'pids.max')}
    status = dict(row.split(':', 1) for row in Path('/proc/self/status').read_text().splitlines() if ':' in row)
    if (limits != {'memory.max':'536870912', 'memory.swap.max':'0', 'cpu.max':'100000 100000', 'pids.max':'64'}
            or status['CapEff'].strip() != '0000000000000000' or status['NoNewPrivs'].strip() != '1'
            or not os.statvfs('/').f_flag & os.ST_RDONLY
            or sorted(p.name for p in Path('/sys/class/net').iterdir()) != ['lo']):
        raise ValueError('Installed-image inspection isolation changed')
    count = 0
    for relative, expected in {**source['payload'], **source['overlay']}.items():
        if not relative.startswith(('usr/', 'etc/')) or '..' in Path(relative).parts:
            raise ValueError('Unexpected installed payload path')
        path = Path('/')/relative
        info = path.lstat()
        if info.st_uid != 0 or (not path.is_symlink() and info.st_mode & 0o022):
            raise ValueError('Installed payload must be root-owned and not writable by others: '+relative)
        if 'link' in expected:
            if not path.is_symlink() or os.readlink(path) != expected['link'] or not path.resolve(strict=True).is_file():
                raise ValueError('Installed link changed: '+relative)
        else:
            if path.is_symlink() or not path.is_file() or path.stat().st_size != expected['bytes']:
                raise ValueError('Installed file shape changed: '+relative)
            with path.open('rb') as stream: actual = hashlib.file_digest(stream, 'sha256').hexdigest()
            if actual != expected['sha256'] or info.st_mode & 0o777 != expected['mode']:
                raise ValueError('Installed content/mode changed: '+relative)
        count += 1
    for name in ('/usr/bin/hyprpm', '/usr/lib/symbi/hyprland/bin/hyprpm'):
        if os.path.lexists(name): raise ValueError('Hyprland package manager remains installed')
    for name in ('symbi-desktop-session', 'symbi-seed-config', 'symbi-launch-desktop-services',
                 'symbi-qualification-source-diagnostic.py'):
        if not os.access('/usr/libexec/'+name, os.X_OK): raise ValueError('Desktop helper is not executable')
    fmt = '%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n'
    inventory = subprocess.check_output(['rpm', '-qa', '--qf', fmt], text=True, timeout=30).splitlines()
    expected = Path('/qualification/installed-after-stdout.log').read_text().splitlines()
    if len(set(inventory)) != len(inventory) or set(inventory) != set(expected):
        raise ValueError('Final image package inventory changed after installation')
    fonts = verify_font_payload(source)
    scope = ('Installed bytes and native font parsing only; no boot or containment qualification'
             if fonts['checked'] else
             'Installed bytes for exact retained pre-font image; no boot, font or containment qualification')
    print(json.dumps({'passed':True, 'os_qualified':False, 'installed_files_checked':count,
                      'installed_package_count':len(inventory), 'all_package_identities_preserved_after_build':True,
                      'fonts':fonts, 'uid':os.geteuid(), 'limits':limits, 'scope':scope}))


if __name__ == '__main__': main()
