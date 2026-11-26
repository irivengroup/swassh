"""Bounded scheduling DTOs and ports independent of SQLite and native clients."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import ContextManager, Protocol

from ..domain.commands import validate_command
from ..domain.inventory import normalize_hosts
from ..domain.models import Host
from ..domain.scheduling import JobInfo, JobState, ScheduleError
from .contracts import RunSummary
from .options import Options


@dataclass(frozen=True, slots=True)
class ExecutionFailure:
    """Allowlisted failure metadata; never persist exception messages or paths."""
    category: str
    error_type: str
    errno: int | None = None

    def __post_init__(self):
        allowed = {'timeout': 'TimeoutError', 'permission': 'PermissionError',
                   'missing_file': 'FileNotFoundError', 'io': 'OSError',
                   'invalid_input': 'ValueError', 'invalid_summary': 'ScheduleError',
                   'runtime': 'RuntimeError', 'unexpected': 'Exception'}
        if allowed.get(self.category) != self.error_type or (self.errno is not None
                and (type(self.errno) is not int or not 0 <= self.errno <= 65535)):
            raise ValueError('invalid failure diagnostic')

    @classmethod
    def capture(cls, error):
        for kind, category in ((TimeoutError, 'timeout'), (PermissionError, 'permission'),
                (FileNotFoundError, 'missing_file'), (OSError, 'io'),
                (ScheduleError, 'invalid_summary'), (ValueError, 'invalid_input'),
                (RuntimeError, 'runtime'), (Exception, 'unexpected')):
            if isinstance(error, kind):
                number = error.errno if isinstance(error, OSError) else None
                number = number if type(number) is int and 0 <= number <= 65535 else None
                return cls(category, kind.__name__, number)
        raise TypeError('expected an execution exception')


@dataclass(frozen=True, slots=True)
class ScheduledInvocation:
    command: str
    hosts: tuple[Host, ...]
    options: Options
    report_path: str
    format: str = 'json'
    spool_dir: str | None = None

    def __post_init__(self):
        validate_command(self.command)
        if not isinstance(self.hosts, tuple) or normalize_hosts(self.hosts) != self.hosts:
            raise ScheduleError('scheduled hosts must be a normalized nonempty tuple')
        if not isinstance(self.options, Options) or self.format not in {'text', 'json', 'csv'}:
            raise ScheduleError('invalid scheduled execution options or report format')
        if self.report_path is None:
            raise ScheduleError("a scheduled report path is required")
        for path in (self.report_path, self.spool_dir):
            if path is not None and (not isinstance(path, str) or not path or not Path(path).is_absolute()
                    or len(path.encode('utf-8')) > 4096 or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in path)):
                raise ScheduleError('scheduled report and spool paths must be bounded absolute paths')


@dataclass(frozen=True, slots=True)
class ClaimedJob:
    info: JobInfo
    invocation: ScheduledInvocation


class ScheduleStore(Protocol):
    def create(self, id: str, invocation: ScheduledInvocation, due_at: datetime,
               now: datetime, misfire_grace: int) -> JobInfo: ...
    def list(self, limit: int = 20, offset: int = 0) -> list[JobInfo]: ...
    def get(self, id: str) -> JobInfo: ...
    def cancel(self, id: str, now: datetime) -> JobInfo: ...
    def purge(self, id: str, now: datetime) -> None: ...
    def recover_running(self, now: datetime) -> int: ...
    def claim_due(self, now: datetime) -> ClaimedJob | None: ...
    def finish(self, id: str, state: JobState, now: datetime, *,
               summary: RunSummary | None = None, reason: str | None = None) -> JobInfo: ...
    def events(self, limit: int = 64) -> list[tuple[int, dict]]: ...
    def acknowledge_events(self, through: int) -> None: ...
    def worker_lock(self) -> ContextManager: ...
    def close(self) -> None: ...


class ScheduledExecutor(Protocol):
    async def __call__(self, job: ClaimedJob) -> RunSummary: ...
