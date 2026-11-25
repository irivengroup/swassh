"""Bounded, descriptor-based snapshots for stdin and connection profile files."""
import hashlib
import json
import os
from pathlib import Path
import stat
from dataclasses import replace
from ..application.profiles import HostProfile
from .filesystem import PinnedDirectory


class InputSnapshot:
    """Read one stable regular file; never follow its final symbolic link."""
    @staticmethod
    def read(path, maximum):
        local = Path(path).expanduser().absolute()
        with PinnedDirectory(local.parent) as parent:
            fd = parent.open(local.name, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
            with os.fdopen(fd, 'rb') as stream:
                before = os.fstat(stream.fileno())
                if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
                    raise ValueError('input must be a regular file within its size budget')
                data = stream.read(maximum + 1)
                after = os.fstat(stream.fileno())
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        if len(data) > maximum or len(data) != before.st_size or any(
                getattr(before, name) != getattr(after, name) for name in fields):
            raise ValueError('input changed during snapshot or exceeded its size budget')
        return data

    @classmethod
    def stdin(cls, options):
        """Take one immutable invocation snapshot and check a scheduled digest."""
        if options.stdin_file is None:
            return None
        data = cls.read(options.stdin_file, options.max_stdin_bytes)
        if options.stdin_sha256 is not None and hashlib.sha256(data).hexdigest() != options.stdin_sha256:
            raise ValueError('scheduled stdin changed; register a new invocation')
        return data


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate profile property')
        result[key] = value
    return result


def decode_profiles(rows):
    """Decode strict profile objects, shared by CLI and durable schedules."""
    if not isinstance(rows, list) or len(rows) > 10000:
        raise ValueError('profiles must be a list of at most 10000 objects')
    profiles = []
    for item in rows:
        if not isinstance(item, dict) or 'hostname' not in item or not set(item) <= set(HostProfile.__dataclass_fields__):
            raise ValueError('invalid profile schema')
        item = dict(item)
        if item.get('client_keys') is not None:
            if not isinstance(item['client_keys'], list):
                raise ValueError('profile keys must be an array')
            item['client_keys'] = tuple(item['client_keys'])
        profiles.append(HostProfile(**item))
    return tuple(profiles)


def load_profiles(path):
    """Load UTF-8 JSON; relative key/trust paths are relative to this file."""
    location = Path(path).expanduser().absolute()
    rows = json.loads(InputSnapshot.read(location, 4 * 1024**2).decode('utf-8'), object_pairs_hook=_unique)
    def absolute(value):
        if not isinstance(value, str) or not value:
            raise ValueError('profile paths must be nonempty strings')
        candidate = Path(value).expanduser()
        return str(candidate if candidate.is_absolute() else location.parent / candidate)
    return tuple(replace(profile,
        client_keys=tuple(absolute(key) for key in profile.client_keys) if profile.client_keys is not None else None,
        known_hosts=absolute(profile.known_hosts) if profile.known_hosts is not None else None)
        for profile in decode_profiles(rows))
