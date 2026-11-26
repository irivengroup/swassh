"""Immutable execution outcome; grouping is independent of output formats."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import datetime

from .models import Result, Status


@dataclass(frozen=True, slots=True)
class ExecutionReport:
    command: str
    results: tuple[Result, ...]
    started_at: datetime
    finished_at: datetime
    run_id: str | None = None
    canary_requested: int | None = None
    show_output: bool = True
    output_lines: int = 10

    @property
    def canary_count(self) -> int:
        return sum(result.phase == "canary" for result in self.results)

    @property
    def canary_passed(self) -> bool | None:
        if self.canary_requested is None:
            return None
        return all(result.status == Status.SUCCESS for result in self.results if result.phase == "canary")

    @property
    def ok(self) -> bool:
        return all(result.status == Status.SUCCESS for result in self.results)

    def raise_for_status(self) -> ExecutionReport:
        """Return the complete report or raise ExecutionError retaining it."""
        if not self.ok:
            from .errors import ExecutionError
            raise ExecutionError(self)
        return self

    @property
    def counts(self) -> dict[str, int]:
        counts = Counter(result.status.value for result in self.results)
        return {status.value: counts[status.value] for status in Status}

    def groups(self) -> dict[str, tuple[Result, ...]]:
        return {
            status.value: tuple(r for r in self.results if r.status == status)
            for status in Status
        }
