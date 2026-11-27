"""Choose the one missing runtime provider from authenticated build inputs."""
import re


GUEST_LIMITS = {'memory.max': '2147483648', 'memory.swap.max': '0',
                'cpu.max': '100000 100000', 'pids.max': '128'}
LOADER_PROBES = ['lib/libhyprtoolkit.so.0.6.0', 'bin/hyprland-share-picker',
                 'libexec/xdg-desktop-portal-hyprland']


def select_runtime_package(build_lock):
    try:
        matches = [row for row in build_lock['packages']
                   if re.fullmatch(r'iniparser-[0-9][A-Za-z0-9.+~_-]*\.fc45\.x86_64',row.get('nevra',''))]
        if len(matches) != 1:
            raise ValueError('Expected exactly one Fedora45 iniparser runtime package')
        row = matches[0]
        if (row['filename'] != row['nevra']+'.rpm' or row['signature_verified'] is not True
                or row['key_fingerprint'] != build_lock['key']['fingerprint']
                or type(row['bytes']) is not int or not 0 < row['bytes'] <= 1024**2
                or not re.fullmatch(r'[0-9a-f]{64}',row['sha256'])):
            raise ValueError('Portal runtime package identity or signing record changed')
        return row
    except (KeyError,TypeError,AttributeError) as error:
        raise ValueError('Malformed portal runtime package record') from error


def require_runtime_result(result, package, version):
    try:
        expected_identity = {'uid': [10001]*4, 'gid': [10001]*4, 'groups': [],
                             'capabilities': {name: '0000000000000000' for name in
                                              ('CapInh', 'CapPrm', 'CapEff', 'CapAmb')},
                             'no_new_privileges': 1}
        if (result['passed'] is not True or result['os_qualified'] is not False
                or result['consent_qualified'] is not False
                or result['all_base_packages_unchanged'] is not True
                or result['base_crypto_configuration_unchanged'] is not True
                or result['negative_controls'] != {'missing_key_rejected': True, 'tampered_package_rejected': True}
                or type(result['base_package_count']) is not int or result['base_package_count'] <= 0
                or result['runtime_package'] != package
                or len(result['required_packages']) != 1
                or result['added_packages'] not in ([], result['required_packages'])
                or result['probe_identity'] != expected_identity
                or result['loader_probes'] != LOADER_PROBES
                or result['portal_version'] != 'xdg-desktop-portal-hyprland v'+version
                or result['limits'] != GUEST_LIMITS
                or any(result['cgroup_final'][key] != value for key, value in GUEST_LIMITS.items())):
            raise ValueError('Incomplete or overclaimed native portal runtime result')
        events = dict(line.split() for line in result['cgroup_final']['memory.events'].splitlines())
        if any(events[key] != '0' for key in ('oom', 'oom_kill', 'oom_group_kill')):
            raise ValueError('Portal runtime check recorded an OOM event')
    except (KeyError, TypeError, AttributeError) as error:
        raise ValueError('Malformed portal runtime result') from error
