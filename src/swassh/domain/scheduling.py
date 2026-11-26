"""One-shot UTC schedules, explicit DST handling and non-replayable job states."""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from enum import StrEnum
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
from .models import Status


class ScheduleError(ValueError):
    """A safe, operator-facing scheduling error without command contents."""


class JobState(StrEnum):
    PENDING = 'pending'
    RUNNING = 'running'
    SUCCEEDED = 'succeeded'
    FAILED = 'failed'
    CANCELLED = 'cancelled'
    MISSED = 'missed'
    INTERRUPTED = 'interrupted'


TERMINAL_STATES = frozenset(JobState) - {JobState.PENDING, JobState.RUNNING}


def utc_time(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ScheduleError('a timezone-aware date and time is required')
    try:
        return value.astimezone(UTC)
    except OverflowError as exc:
        raise ScheduleError("date is outside the supported UTC calendar") from exc


def timestamp(value: datetime) -> str:
    return utc_time(value).isoformat(timespec='microseconds')


def validate_job_id(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r'[0-9a-f]{32}', value):
        raise ScheduleError('job ID must be the complete 32-character identifier')
    return value


def parse_schedule_time(value: str, zone: str | None = None, fold: int | None = None) -> datetime:
    pattern = r'[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}(?::[0-9]{2}(?:\.[0-9]{1,6})?)?(?:Z|[+-][0-9]{2}:[0-9]{2})?'
    if not isinstance(value, str) or not re.fullmatch(pattern, value):
        raise ScheduleError('use YYYY-MM-DD HH:MM[:SS] or an ISO timestamp with UTC offset')
    if fold is not None and (not isinstance(fold, int) or isinstance(fold, bool) or fold not in (0, 1)):
        raise ScheduleError('fold must be 0 or 1')
    offset_match = re.search(r"[+-]([0-9]{2}):([0-9]{2})$", value)
    if offset_match and (int(offset_match[1]) > 23 or int(offset_match[2]) > 59):
        raise ScheduleError("invalid UTC offset")
    try:
        local = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ScheduleError('invalid calendar date, time or UTC offset') from exc
    if local.tzinfo is not None:
        if zone is not None or fold is not None:
            raise ScheduleError('use either an explicit UTC offset or timezone/fold, not both')
        return utc_time(local)
    if zone is None or zone in ('UTC', 'Z'):
        if fold is not None:
            raise ScheduleError('fold requires an IANA timezone')
        return local.replace(tzinfo=UTC)
    if not isinstance(zone, str) or len(zone) > 128:
        raise ScheduleError('invalid timezone')
    if re.fullmatch(r'[+-][0-9]{2}:[0-9]{2}', zone):
        if fold is not None:
            raise ScheduleError('fold requires an IANA timezone')
        hours, minutes = map(int, zone[1:].split(':'))
        if hours > 23 or minutes > 59:
            raise ScheduleError('invalid UTC offset')
        offset = timedelta(hours=hours, minutes=minutes) * (-1 if zone[0] == '-' else 1)
        return utc_time(local.replace(tzinfo=timezone(offset)))
    try:
        tz = ZoneInfo(zone)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ScheduleError('IANA timezone unavailable; use UTC, an explicit offset or system zoneinfo data') from exc
    candidates = {}
    for choice in (0, 1):
        candidate = local.replace(tzinfo=tz, fold=choice)
        instant = utc_time(candidate)
        if instant.astimezone(tz).replace(tzinfo=None) == local:
            candidates[choice] = instant
    if not candidates:
        raise ScheduleError('this local time does not exist during the daylight-saving transition')
    if len(set(candidates.values())) > 1 and fold is None:
        raise ScheduleError('this local time is ambiguous; choose --fold 0 or --fold 1')
    return candidates[fold if fold is not None else min(candidates)]


@dataclass(frozen=True, slots=True)
class JobInfo:
    id: str
    state: JobState
    due_at: datetime
    created_at: datetime
    deadline: datetime
    host_count: int
    command_sha256: str
    report_path: str
    canary: int
    started_at: datetime | None = None
    finished_at: datetime | None = None
    run_id: str | None = None
    counts: dict[str, int] | None = None
    reason: str | None = None

    def __post_init__(self):
        validate_job_id(self.id)
        if not isinstance(self.state, JobState):
            raise ScheduleError('invalid job state')
        for value in (self.due_at, self.created_at, self.deadline):
            utc_time(value)
        if any(not isinstance(v, int) or isinstance(v, bool) or not 1 <= v <= 100_000
               for v in (self.host_count, self.canary)):
            raise ScheduleError('invalid scheduled host or canary count')
        if not self.created_at < self.due_at < self.deadline:
            raise ScheduleError('invalid scheduled calendar ordering')
        if not isinstance(self.command_sha256, str) or not re.fullmatch(r'[0-9a-f]{64}', self.command_sha256):
            raise ScheduleError('invalid scheduled command digest')
        for value in (self.started_at, self.finished_at):
            if value is not None:
                utc_time(value)
        if self.run_id is not None:
            validate_job_id(self.run_id)
        if self.counts is not None and (not isinstance(self.counts, dict)
                or set(self.counts) != {status.value for status in Status}
                or any(type(v) is not int or v < 0 for v in self.counts.values())
                or sum(self.counts.values()) != self.host_count):
            raise ScheduleError('invalid scheduled execution counters')

    def to_dict(self):
        return {name: value.isoformat() if isinstance(value, datetime) else value
                for name, value in ((field, getattr(self, field)) for field in self.__dataclass_fields__)}
