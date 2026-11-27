"""Canonical Fedora installed-package inventory parsing shared by image stages."""
import hashlib
import re


ROW = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9+_.-]*\t[0-9]+\t"
    r"[A-Za-z0-9~^+_.:]+\t[A-Za-z0-9~^+_.]+\t(?:[A-Za-z0-9_]+|\(none\))"
)
MAXIMUM_BYTES = 1024**2


def parse_inventory(raw):
    """Validate raw RPM query output and return unique rows in canonical order."""
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAXIMUM_BYTES:
        raise ValueError("installed package inventory size is invalid")
    if not raw.endswith(b"\n") or b"\r" in raw or b"\0" in raw:
        raise ValueError("installed package inventory needs LF-terminated rows")
    try:
        rows = raw[:-1].decode("ascii").split("\n")
    except UnicodeDecodeError as error:
        raise ValueError("installed package inventory is not ASCII") from error
    if (not rows or any(not row or ROW.fullmatch(row) is None for row in rows)
            or len(rows) != len(set(rows))):
        raise ValueError("installed package inventory has malformed or duplicate rows")
    return sorted(rows)


def serialize_inventory(rows):
    """Serialize already parsed rows with one trailing LF."""
    if (not isinstance(rows, list) or not rows or rows != sorted(rows)
            or len(rows) != len(set(rows))
            or any(not isinstance(row, str) or ROW.fullmatch(row) is None for row in rows)):
        raise ValueError("canonical package inventory rows are invalid")
    return ("\n".join(rows) + "\n").encode("ascii")


def inventory_digest(raw):
    return hashlib.sha256(serialize_inventory(parse_inventory(raw))).hexdigest()
