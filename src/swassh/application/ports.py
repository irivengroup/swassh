"""Inbound-independent contracts for the execution use cases."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import AsyncContextManager, Protocol, Self

from ..domain.models import Host, Result
from ..domain.report import ExecutionReport
from ..domain.transfers import FileTransfer
from .transfer_settings import TransferSettings
from .contracts import ResourcePlan, RunSummary
from .options import Options


class Transport(Protocol):
    async def execute(self, host: Host, command: str) -> Result: ...


class TransportFactory(Protocol):
    def __call__(self, options: Options) -> Transport: ...


class AuditSession(Protocol):
    async def __aenter__(self) -> Self: ...

    async def __aexit__(self, exc_type, exc, traceback) -> None: ...

    async def emit(self, event: str, fields: Mapping[str, object]) -> None: ...


class AuditFactory(Protocol):
    def __call__(self, path: str | None, run_id: str) -> AuditSession: ...


class ResourcePlanner(Protocol):
    def __call__(self, options: Options) -> ResourcePlan: ...


class ReportWriter(Protocol):
    """One serialized writer; awaiting append provides backpressure."""

    worker_pid: int | None

    async def __aenter__(self) -> Self: ...

    async def __aexit__(self, exc_type, exc, traceback) -> None: ...

    async def append(self, results: Sequence[Result]) -> None: ...

    async def summary(self) -> dict[str, int]: ...

    async def export(
        self, path: Path, format: str, command: str, summary: RunSummary
    ) -> None: ...


class ReporterFactory(Protocol):
    def __call__(self, directory: str | Path, max_bytes: int) -> ReportWriter: ...


class ReportFactory(Protocol):
    def __call__(
        self,
        command: str,
        results: tuple[Result, ...],
        started_at: datetime,
        finished_at: datetime,
        run_id: str,
    ) -> ExecutionReport: ...


class FileTransport(Protocol):
    async def __aenter__(self) -> Self: ...
    async def __aexit__(self, exc_type, exc, traceback) -> None: ...
    async def transfer(self, host: Host) -> Result: ...


class FileTransportFactory(Protocol):
    def __call__(self, options: Options, settings: TransferSettings,
                 request: FileTransfer, bandwidth_kib: int) -> FileTransport: ...


async def checkpoint_audit(audit: AuditSession) -> None:
    """Optional durable checkpoint; existing injected audit ports stay compatible."""
    flush = getattr(audit, 'flush', None)
    if flush is not None:
        await flush()


async def prepare_report_destination(writer: ReportWriter, path: Path) -> None:
    """System writers validate destinations before transport admission."""
    prepare = getattr(writer, 'prepare', None)
    if prepare is not None:
        await prepare(path)


class InvocationFactory(Protocol):
    def __call__(self, options: Options) -> "AsyncContextManager[None]": ...


class ProgressSink(Protocol):
    def __call__(self, metrics: Mapping[str, object], *, final: bool = False) -> None: ...
