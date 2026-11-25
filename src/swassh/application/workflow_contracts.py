"""Immutable prepared workflows and native execution results, independent of SQL."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import re
from typing import ContextManager, Protocol

from ..domain.workflows import Workflow, WorkflowError, WorkflowState, _identifier
from ..domain.scheduling import validate_job_id, timestamp
from ..domain.models import Status
from .contracts import RunSummary
from .schedule_contracts import ExecutionFailure, ScheduledInvocation


def _counts(value, total):
    if value is None:
        return
    if not isinstance(value, tuple) or any(not isinstance(item, tuple) or len(item) != 2 for item in value):
        raise WorkflowError('invalid workflow checkpoint counters')
    counters = dict(value)
    if (len(counters) != len(value) or set(counters) != {status.value for status in Status}
            or any(type(count) is not int or count < 0 for count in counters.values())
            or sum(counters.values()) != total):
        raise WorkflowError('invalid workflow checkpoint counters')


def _time(value):
    if value is not None:
        try:
            if not isinstance(value, str) or timestamp(datetime.fromisoformat(value)) != value:
                raise ValueError
        except (ValueError, TypeError):
            raise WorkflowError('invalid workflow timestamp') from None


def _path(value):
    if (not isinstance(value, str) or not value or not Path(value).is_absolute()
            or len(value.encode('utf-8')) > 4096 or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in value)):
        raise WorkflowError('invalid workflow report path')


@dataclass(frozen=True, slots=True)
class WorkflowVerificationInfo:
    """Latest verification receipt; the original execution receipt stays intact."""
    attempt: int
    report_path: str
    finished_at: str
    run_id: str | None
    counts: tuple[tuple[str, int], ...]
    host_count: int

    def __post_init__(self):
        if type(self.attempt) is not int or not 1 <= self.attempt <= 16:
            raise WorkflowError('invalid workflow verification attempt')
        if type(self.host_count) is not int or not 1 <= self.host_count <= 100000:
            raise WorkflowError('invalid workflow verification host count')
        _path(self.report_path)
        if self.finished_at is None:
            raise WorkflowError('missing workflow verification timestamp')
        _time(self.finished_at)
        if self.run_id is not None:
            validate_job_id(self.run_id)
        if self.counts is None:
            raise WorkflowError('missing workflow verification counters')
        _counts(self.counts, self.host_count)

    def to_dict(self):
        return {'attempt': self.attempt, 'report_path': self.report_path,
                'finished_at': self.finished_at, 'run_id': self.run_id,
                'counts': dict(self.counts)}


@dataclass(frozen=True, slots=True)
class PreparedWorkflow:
    workflow: Workflow
    invocations: tuple[ScheduledInvocation, ...] = field(repr=False)

    def __post_init__(self):
        if not isinstance(self.workflow, Workflow) or not isinstance(self.invocations, tuple):
            raise WorkflowError('invalid prepared workflow')
        if len(self.invocations) != len(self.workflow.ordered_steps):
            raise WorkflowError('prepared workflow invocation count mismatch')
        for step, invocation in zip(self.workflow.ordered_steps, self.invocations):
            if (not isinstance(invocation, ScheduledInvocation) or invocation.command != step.descriptor
                    or invocation.hosts != step.hosts):
                raise WorkflowError('prepared workflow command or target mismatch')
            if invocation.options.retries or invocation.options.stdin_file or invocation.options.pty:
                raise WorkflowError('durable workflows require retries=0, no stdin file and no PTY')

    def invocation(self, step_id):
        for step, invocation in zip(self.workflow.ordered_steps, self.invocations):
            if step.id == step_id:
                return invocation
        raise WorkflowError('workflow step not found')


@dataclass(frozen=True, slots=True)
class WorkflowStepInfo:
    """Immutable observable checkpoint, excluding commands and credentials."""
    id: str
    state: WorkflowState
    host_count: int
    report_path: str
    started_at: str | None = None
    finished_at: str | None = None
    reason: str | None = None
    run_id: str | None = None
    counts: tuple[tuple[str, int], ...] | None = None
    verification: WorkflowVerificationInfo | None = None

    def __post_init__(self):
        _identifier(self.id)
        if not isinstance(self.state, WorkflowState) or type(self.host_count) is not int or not 1 <= self.host_count <= 100000:
            raise WorkflowError('invalid workflow checkpoint')
        if self.reason is not None and (not isinstance(self.reason, str) or not re.fullmatch('[a-z_]{1,64}', self.reason)):
            raise WorkflowError('invalid workflow reason code')
        if self.run_id is not None:
            validate_job_id(self.run_id)
        _path(self.report_path)
        _time(self.started_at)
        _time(self.finished_at)
        _counts(self.counts, self.host_count)
        if self.verification is not None and (not isinstance(self.verification, WorkflowVerificationInfo)
                or self.verification.host_count != self.host_count):
            raise WorkflowError('invalid workflow verification receipt')

    def to_dict(self):
        return {'id': self.id, 'state': self.state.value, 'host_count': self.host_count,
                'report_path': self.report_path, 'started_at': self.started_at,
                'finished_at': self.finished_at, 'reason': self.reason, 'run_id': self.run_id,
                'counts': dict(self.counts) if self.counts is not None else None,
                'verification': self.verification.to_dict() if self.verification else None}


@dataclass(frozen=True, slots=True)
class WorkflowInfo:
    id: str
    name: str
    state: WorkflowState
    created_at: str
    definition_sha256: str
    steps: tuple[WorkflowStepInfo, ...]

    def __post_init__(self):
        validate_job_id(self.id)
        _identifier(self.name)
        if (not isinstance(self.state, WorkflowState) or self.state == WorkflowState.BLOCKED
                or not isinstance(self.steps, tuple) or not 1 <= len(self.steps) <= 256
                or any(not isinstance(step, WorkflowStepInfo) for step in self.steps)):
            raise WorkflowError('invalid workflow metadata')
        if not isinstance(self.definition_sha256, str) or not re.fullmatch('[0-9a-f]{64}', self.definition_sha256):
            raise WorkflowError('invalid workflow definition digest')
        if self.created_at is None:
            raise WorkflowError('missing workflow creation timestamp')
        _time(self.created_at)

    def to_dict(self):
        return {'id': self.id, 'name': self.name, 'state': self.state.value,
                'created_at': self.created_at, 'definition_sha256': self.definition_sha256,
                'steps': [step.to_dict() for step in self.steps]}


class WorkflowStore(Protocol):
    """Durable claims must commit before the caller may perform remote effects."""
    def create(self, id: str, prepared: PreparedWorkflow, now: datetime) -> WorkflowInfo: ...
    def get(self, id: str) -> WorkflowInfo: ...
    def definition(self, id: str) -> PreparedWorkflow: ...
    def list(self, limit: int, offset: int) -> list[WorkflowInfo]: ...
    def claim_run(self, now: datetime) -> str | None: ...
    def claim_step(self, id: str, now: datetime) -> str | None: ...
    def finish_step(self, id: str, step: str, succeeded: bool, now: datetime,
                    summary: RunSummary | None = None, failure: ExecutionFailure | None = None) -> None: ...
    def recover(self, now: datetime) -> int: ...
    def resume(self, id: str, now: datetime) -> WorkflowInfo: ...
    def prepare_reconciliation(self, id: str, step: str, now: datetime) -> int: ...
    def reconcile(self, id: str, step: str, now: datetime, summary: RunSummary) -> None: ...
    def cancel(self, id: str, now: datetime) -> WorkflowInfo: ...
    def purge(self, id: str, now: datetime) -> None: ...
    def events(self, limit: int = 64) -> list[tuple[int, dict]]: ...
    def acknowledge_events(self, through: int) -> None: ...
    def worker_lock(self) -> ContextManager: ...
    def close(self) -> None: ...
