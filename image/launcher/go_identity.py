"""Check exact machine-readable compiler identity after RPM authentication."""


def require_compiler(actual):
    expected = {'GOVERSION': 'go1.27.4', 'GOOS': 'linux', 'GOARCH': 'amd64',
                'GOTOOLCHAIN': 'local', 'CGO_ENABLED': '1'}
    if not isinstance(actual, dict):
        raise ValueError('Expected structured Go compiler identity')
    for name, value in expected.items():
        if actual.get(name) != value:
            raise ValueError(f'Unexpected {name}: {str(actual.get(name))[:160]!r}; expected {value!r}')
