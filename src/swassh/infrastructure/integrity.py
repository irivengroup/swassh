"""Bounded SHA-256 and explicit native remote-tool capability selection."""
from __future__ import annotations
import hashlib
import os
import re
import shlex
import stat
from pathlib import Path
from .filesystem import PinnedDirectory

TOOLS = {'sha256sum', 'shasum', 'openssl', 'digest'}
PROBE = ('if command -v sha256sum >/dev/null 2>&1; then printf sha256sum; '
    'elif command -v shasum >/dev/null 2>&1; then printf shasum; '
    'elif command -v openssl >/dev/null 2>&1; then printf openssl; '
    'elif command -v digest >/dev/null 2>&1; then printf digest; else exit 69; fi')


def digest_file(path: str | Path, maximum: int) -> str:
    """Hash a bounded regular file without following its final entry on either OS."""
    path = Path(path).absolute()
    with PinnedDirectory(path.parent) as parent:
        fd = parent.open(path.name, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > maximum:
            raise ValueError('integrity input must be a bounded private regular file')
        digest = hashlib.sha256()
        size = 0
        while chunk := stream.read(1024 * 1024):
            size += len(chunk)
            if size > maximum:
                raise ValueError('integrity input exceeded its budget')
            digest.update(chunk)  # OpenSSL-backed hashlib releases the GIL here.
        after = os.fstat(stream.fileno())
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError('integrity input changed while hashing')
        return digest.hexdigest()


def hash_command(tool, path):
    if tool not in TOOLS:
        raise ValueError('unapproved remote hash utility')
    quoted = shlex.quote(path)
    if tool == 'sha256sum':
        return 'sha256sum -- ' + quoted
    if tool == 'shasum':
        return 'shasum -a 256 -- ' + quoted
    if tool == 'openssl':
        return 'openssl dgst -sha256 ' + quoted
    return 'digest -a sha256 ' + quoted


def parse_hash(tool, output):
    if tool not in TOOLS or len(output) > 8192:
        raise ValueError('invalid remote hash response')
    if tool in {'sha256sum', 'shasum'}:
        match = re.fullmatch(r'\\?([0-9a-fA-F]{64}) [ *][^\r\n]+\n?', output)
    elif tool == 'openssl':
        match = re.fullmatch(r'[^\r\n]+[ =]([0-9a-fA-F]{64})\n?', output)
    else:
        match = re.fullmatch(r'([0-9a-fA-F]{64})\n?', output)
    if not match:
        raise ValueError('invalid remote hash response')
    return match.group(1).lower()


def publish_command(tool, temporary, final, expected):
    if not re.fullmatch('[0-9a-f]{64}', expected):
        raise ValueError('invalid expected digest')
    # The hash output is parsed again by the remote shell immediately before mv.
    # No retry of this mutating command is permitted, even on a lost response.
    command = hash_command(tool, temporary)
    if tool in {'sha256sum', 'shasum'}:
        extraction = "${value%% *}"
        # All temporary names are generated ASCII, so sha256sum cannot escape them.
    elif tool == 'openssl':
        extraction = "${value##* }"
    else:
        extraction = "$value"
    return ('value=$(' + command + ') && test "' + extraction + '" = ' + expected
        + ' && mv -f ' + shlex.quote(temporary) + ' ' + shlex.quote(final))
