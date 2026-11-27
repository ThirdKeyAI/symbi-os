"""Fail-closed inputs for disposable desktop RPM discovery, never runtime trust."""
import configparser
import re


FEDORA = '4F50A6114CD5C6976A7F1179655A4B02F577861E'
FUSION = 'E9A491A3DE247814E7E067EAE06F8ECDD651FF2E'


def require_keyring(output, fingerprints):
    actual = [line.split()[0].upper() for line in output.splitlines() if line.strip()]
    if (not fingerprints or len(set(fingerprints)) != len(fingerprints)
            or any(not re.fullmatch(r'[0-9A-F]{40}', key) for key in fingerprints)
            or len(actual) != len(fingerprints) or set(actual) != set(fingerprints)):
        raise ValueError('Discovery keyring must contain exactly the reviewed public keys')


def verified_signer(status, output, fingerprints):
    if status != 0:
        raise ValueError('RPM verification command failed')
    elements = [line.strip() for line in output.splitlines() if line.startswith((' ', '\t'))]
    if not elements or any(not line.endswith(': OK') for line in elements):
        raise ValueError('RPM contains failed or unrecognized verification elements')
    signatures = [line for line in elements if ' signature,' in line.lower()]
    if not signatures or not any(line.startswith('Payload ') and ' digest: OK' in line for line in elements):
        raise ValueError('RPM needs both a verified signature and payload digest')
    signers = set()
    for line in signatures:
        match = re.search(r'key fingerprint: ([0-9a-fA-F]{40}): OK$', line)
        if not match or match[1].upper() not in fingerprints:
            raise ValueError('Unreviewed RPM signing key')
        signers.add(match[1].upper())
    if len(signers) != 1:
        raise ValueError('Ambiguous package signing identity')
    return signers.pop()


def require_repositories(text):
    expected = {
        'fedora': ('https://mirrors.fedoraproject.org/metalink?protocol=https&repo=fedora-45&arch=x86_64', 'fedora-45-primary.asc'),
        'updates': ('https://mirrors.fedoraproject.org/metalink?protocol=https&repo=updates-released-f45&arch=x86_64', 'fedora-45-primary.asc'),
        'rpmfusion-free': ('https://mirrors.rpmfusion.org/metalink?repo=free-fedora-45&arch=x86_64&protocol=https', 'rpmfusion-free-2020.asc'),
        'rpmfusion-free-updates': ('https://mirrors.rpmfusion.org/metalink?repo=free-fedora-updates-released-45&arch=x86_64&protocol=https', 'rpmfusion-free-2020.asc'),
    }
    config = configparser.ConfigParser(interpolation=None)
    config.read_string(text)
    if config.defaults() or set(config.sections()) != set(expected):
        raise ValueError('Unexpected discovery repositories or inherited options')
    allowed = {'name', 'metalink', 'enabled', 'countme', 'metadata_expire', 'repo_gpgcheck',
               'type', 'gpgcheck', 'gpgkey', 'skip_if_unavailable', 'sslverify'}
    for name, (url, key) in expected.items():
        section = config[name]
        if (set(section) - allowed or section.get('metalink') != url
                or section.get('gpgkey') != 'file:///inputs/' + key
                or any(section.getboolean(option, fallback=None) is not True
                       for option in ('enabled', 'gpgcheck', 'sslverify'))
                or section.getboolean('skip_if_unavailable', fallback=None) is not False
                or section.getboolean('repo_gpgcheck', fallback=None) is not False
                or section.getboolean('countme', fallback=False) is not False):
            raise ValueError('Discovery repository policy changed: ' + name)


def require_requirements(value):
    packages = value.get('packages')
    review = value.get('security_review', {}).get('kitty', {})
    if (value.get('schema') != 1 or value.get('packages_selected') is not False
            or not isinstance(packages, list) or not 3 <= len(packages) <= 64
            or any(not isinstance(name, str) or not re.fullmatch(r'[a-z][a-z0-9+_.-]*', name) for name in packages)
            or len(set(packages)) != len(packages) or not {'kitty', 'mplayer', 'mpv'}.issubset(packages)
            or review.get('minimum_upstream_version') != '0.51.0'
            or review.get('cves') != ['CVE-2026-134823', 'CVE-2026-95835']
            or review.get('fixed_package_verified') is not False):
        raise ValueError('Unexpected desktop candidate requirements or premature security clearance')
