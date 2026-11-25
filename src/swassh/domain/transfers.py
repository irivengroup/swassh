"""Literal file and directory transfers and deterministic collision-safe target paths."""
from __future__ import annotations
import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import PurePosixPath
from .models import Host

class TransferDirection(StrEnum):
    PUSH = "push"
    PULL = "pull"

@dataclass(frozen=True, slots=True)
class FileTransfer:
    direction: TransferDirection
    local_path: str
    remote_path: str

    def __post_init__(self) -> None:
        if not isinstance(self.direction, TransferDirection):
            raise ValueError("direction must be a TransferDirection")
        for value in (self.local_path, self.remote_path):
            if (not isinstance(value, str) or not value or len(value.encode()) > 4096
                or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in value)):
                raise ValueError("paths must be nonempty and contain no control characters")
        remote = PurePosixPath(self.remote_path)
        if (not self.remote_path.startswith("/")
            or remote.name in {"", ".", ".."} or ".." in remote.parts):
            raise ValueError("remote path must be an absolute non-root POSIX path")

    @property
    def descriptor(self) -> str:
        data = json.dumps([self.direction.value, self.local_path, self.remote_path])
        return self.direction.value + ":" + hashlib.sha256(data.encode()).hexdigest()

def host_directory(host: Host) -> str:
    # Validated DNS names start with a slug character; IPv6 colons become underscores.
    slug = re.sub(r"[^A-Za-z0-9_.-]", "_", host.hostname)[:48].strip(".")
    return slug + "-" + hashlib.sha256(host.target.encode()).hexdigest()[:32]

def local_filename(remote_path: str) -> str:
    name = PurePosixPath(remote_path).name
    safe = re.sub(r'[<>:"/\\|?*]', "_", name).rstrip(". ")[:120]
    if safe.split(".", 1)[0].upper() in {"CON", "PRN", "AUX", "NUL",
            *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}:
        safe = "_" + safe
    while len(safe.encode()) > 200:
        safe = safe[:-1]
    if not safe or safe != name:
        safe = (safe or "file") + "-" + hashlib.sha256(name.encode()).hexdigest()[:16]
    return safe
