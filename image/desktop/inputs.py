"""Select runtime files and additive package transactions for the real image."""
from pathlib import Path
import re


def required_package_delta(before, required):
    if not before or not required:
        raise ValueError('Missing original or required package inventory')
    for rows in (before, required):
        if len(set(rows)) != len(rows) or any(len(row.split('\t')) != 5 for row in rows):
            raise ValueError('Ambiguous or malformed package inventory')
        if any(not all(row.split('\t')) for row in rows):
            raise ValueError('Empty RPM identity field')
    delta = []
    if len({row.split('\t')[0] for row in required}) != len(required):
        raise ValueError('Multiple required identities for one package')
    for row in required:
        if row in before:
            continue
        if any(old.split('\t')[0] == row.split('\t')[0] for old in before):
            raise ValueError('Desktop installation cannot replace a base package')
        delta.append(row)
    return sorted(delta)


def require_transaction(before, after, required):
    delta = required_package_delta(before, required)
    if len(set(after)) != len(after) or set(after) != set(before) | set(delta):
        raise ValueError('Desktop transaction changed the base or added unreviewed packages')


def select_prefix_files(prefix):
    if prefix.is_symlink() or prefix.resolve() != prefix or not prefix.is_dir():
        raise ValueError('Expected the extracted regular private prefix')
    selected = {}
    for path in sorted(prefix.rglob('*')):
        relative = path.relative_to(prefix).as_posix()
        if path.is_symlink():
            try:
                resolved = path.resolve(strict=True)
            except (OSError, RuntimeError) as error:
                raise ValueError('Dangling or cyclic runtime prefix link') from error
            if not resolved.is_relative_to(prefix) or not resolved.is_file():
                raise ValueError('Runtime prefix links must point to internal regular files')
        elif path.is_dir():
            continue
        elif not path.is_file():
            raise ValueError('Unexpected special runtime file')
        parts = Path(relative).parts
        keep = (relative in ('bin/Hyprland', 'bin/hyprctl', 'bin/hyprland')
                or parts[0] == 'share'
                or (parts[0] in ('lib', 'lib64') and re.fullmatch(r'.+\.so(?:\.[0-9]+)*', path.name)))
        if keep:
            selected[relative] = path
    if not {'bin/Hyprland', 'bin/hyprctl'}.issubset(selected):
        raise ValueError('Missing compositor executables')
    for relative, path in selected.items():
        if path.is_symlink() and path.resolve().relative_to(prefix).as_posix() not in selected:
            raise ValueError('A retained link targets an excluded build input')
    return selected
