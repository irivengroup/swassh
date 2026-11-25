"""Immutable domain objects; no SSH implementation dependency."""

from __future__ import annotations

import re
import math
import json
from dataclasses import dataclass
from enum import StrEnum

from .hosts import Host


# Match the literal C0/C1 controls in the native regex engine. Keep the
# historical iterator check for string subclasses as an additional constraint;
# a custom iterator must never conceal controls in the actual string payload.
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f-\x9f]")


class Status(StrEnum):
    SUCCESS = "success"
    FAILED = "failed"
    UNREACHABLE = "unreachable"
    AUTH_FAILED = "auth_failed"
    HOST_KEY_FAILED = "host_key_failed"
    TIMEOUT = "timeout"
    INTERRUPTED = "interrupted"
    ERROR = "error"
    SKIPPED = "skipped"


@dataclass(frozen=True, slots=True)
class TransferReceipt:
    direction: str
    local_path: str
    remote_path: str
    backend: str | None = None
    bytes_transferred: int | None = None
    fallback_reason: str | None = None
    temporary_path: str | None = None


    def __post_init__(self) -> None:
        if self.direction not in {"push", "pull"} or self.backend not in {None, "rsync", "sftp"}:
            raise ValueError("invalid transfer direction or backend")
        for name in ("local_path", "remote_path", "temporary_path", "fallback_reason"):
            value = getattr(self, name)
            if value is None and name in {"temporary_path", "fallback_reason"}:
                continue
            if (not isinstance(value, str) or not value or len(value.encode("utf-8")) > 4096
                    or _CONTROL_CHARACTERS.search(value) is not None
                    or (type(value) is not str
                        and any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in value))):
                raise ValueError("transfer receipt paths must be bounded literal strings")
        if self.bytes_transferred is not None and (not isinstance(self.bytes_transferred, int)
                or isinstance(self.bytes_transferred, bool) or self.bytes_transferred < 0):
            raise ValueError("transfer size must be a nonnegative integer")


@dataclass(frozen=True, slots=True)
class Result:
    host: Host
    status: Status
    stdout: str = ""
    stderr: str = ""
    exit_code: int | None = None
    exit_signal: str | None = None
    error: str | None = None
    attempts: int = 1
    duration: float = 0.0
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    transfer: TransferReceipt | None = None
    phase: str | None = None
    changed: bool = False

    @property
    def ok(self) -> bool:
        """True only for a successful operation, never for skipped hosts."""
        return self.status == Status.SUCCESS

    def raise_for_status(self) -> Result:
        """Return self or raise CommandError retaining this immutable result."""
        if not self.ok:
            from .errors import CommandError
            raise CommandError(self)
        return self

    def json(self) -> object:
        """Decode successful, complete stdout as strict JSON.

        Duplicate properties and non-finite constants are rejected. No output
        content is included in the exception message or chained exception.
        """
        from .errors import OutputDecodeError
        self.raise_for_status()
        def unique(pairs):
            values = {}
            for key, value in pairs:
                if key in values:
                    raise ValueError('duplicate property')
                values[key] = value
            return values
        def invalid_constant(value):
            raise ValueError('non-finite constant')
        try:
            if self.stdout_truncated:
                raise ValueError('truncated output')
            return json.loads(self.stdout, object_pairs_hook=unique, parse_constant=invalid_constant)
        except (ValueError, RecursionError):
            raise OutputDecodeError(self) from None


    def __post_init__(self) -> None:
        if not isinstance(self.host, Host) or not isinstance(self.status, Status):
            raise ValueError("result requires Host and Status values")
        if not isinstance(self.changed, bool) or (self.changed and self.status != Status.SUCCESS):
            raise ValueError("changed must be a boolean declared only for successful results")
        for name in ("stdout", "stderr"):
            if not isinstance(getattr(self, name), str):
                raise ValueError("result streams must be strings")
        for name in ("error", "exit_signal"):
            value = getattr(self, name)
            if value is not None and not isinstance(value, str):
                raise ValueError("result error and signal must be strings or None")
        if (not isinstance(self.attempts, int) or isinstance(self.attempts, bool) or self.attempts < (0 if self.status == Status.SKIPPED else 1)
                or not isinstance(self.duration, (int, float)) or isinstance(self.duration, bool)
                or not math.isfinite(self.duration) or self.duration < 0):
            raise ValueError("result attempts and duration are invalid")
        if self.status == Status.SKIPPED and self.attempts != 0:
            raise ValueError("skipped targets must have zero attempts")
        if self.phase not in {None, "canary", "fleet"}:
            raise ValueError("result phase must be canary, fleet or None")
        if self.exit_code is not None and (not isinstance(self.exit_code, int) or isinstance(self.exit_code, bool)):
            raise ValueError("exit_code must be an integer or None")
        if not isinstance(self.stdout_truncated, bool) or not isinstance(self.stderr_truncated, bool):
            raise ValueError("truncation markers must be booleans")
        if self.transfer is not None and not isinstance(self.transfer, TransferReceipt):
            raise ValueError("transfer must be a TransferReceipt or None")
