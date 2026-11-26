"""Immutable resource and completion DTOs crossing the application ports."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime

from ..domain.models import Status

MIB = 1024 * 1024


@dataclass(frozen=True, slots=True)
class ResourcePlan:
    requested_workers: int
    workers: int
    memory_budget_bytes: int
    estimated_worker_bytes: int
    connect_rate: float

    def to_dict(self) -> dict[str, int | float]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class RunSummary:
    total: int
    counts: dict[str, int]
    started_at: datetime
    finished_at: datetime
    plan: ResourcePlan
    run_id: str | None = None
    report_worker_pid: int | None = None
    canary_requested: int | None = None
    canary_count: int = 0
    canary_passed: bool | None = None
    show_output: bool = True
    output_lines: int = 10

    @property
    def ok(self) -> bool:
        return self.counts[Status.SUCCESS.value] == self.total
