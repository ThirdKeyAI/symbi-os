"""Check exact machine-readable compiler identity after RPM authentication."""


def require_compiler(actual):
    # Observed after authenticating and installing the exact four locked RPMs;
    # retained evidence: P0-03-elephant-toolchain/45727353652/toolchain/.
    # Pin Fedora's full identity and experiment selection, without suffix stripping.
    expected = {'GOVERSION': 'go1.27.4-X:nodwarf5', 'GOOS': 'linux', 'GOARCH': 'amd64',
                'GOTOOLCHAIN': 'local', 'CGO_ENABLED': '1', 'GOEXPERIMENT': 'nodwarf5'}
    if not isinstance(actual, dict):
        raise ValueError('Expected structured Go compiler identity')
    for name, value in expected.items():
        if actual.get(name) != value:
            raise ValueError(f'Unexpected {name}: {str(actual.get(name))[:160]!r}; expected {value!r}')
