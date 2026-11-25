"""Transfer use cases compose the existing bounded workers and reporting ports."""
from __future__ import annotations
from collections.abc import AsyncGenerator, Iterable
from contextlib import aclosing
from dataclasses import replace
from pathlib import Path
from ..domain.models import Host, Result
from ..domain.report import ExecutionReport
from ..domain.transfers import FileTransfer
from .contracts import MIB, ResourcePlan, RunSummary
from .options import Options
from .ports import AuditFactory, FileTransport, FileTransportFactory, ReportFactory, ReporterFactory, ResourcePlanner
from .swarm import Swarm
from .boundaries import invocation
from .transfer_settings import TransferSettings

class _TransferOperation:
    def __init__(self, client: FileTransport, descriptor: str):
        self.client, self.descriptor = client, descriptor

    def metrics(self):
        method = getattr(self.client, "metrics", None)
        return method() if method else {}

    async def execute(self, host: Host, command: str) -> Result:
        if command != self.descriptor:
            raise ValueError("transfer descriptor mismatch")
        return await self.client.transfer(host)

class TransferService:
    def __init__(self, options: Options, settings: TransferSettings, *,
                 transport_factory: FileTransportFactory, audit_factory: AuditFactory,
                 planner: ResourcePlanner, reporter_factory: ReporterFactory,
                 report_factory: ReportFactory, invocation_factory=None, progress_sink=None):
        self._invocation_factory, self._progress_sink = invocation_factory, progress_sink
        if options.retries:
            raise ValueError("file transfers require retries=0 to avoid ambiguous replay")
        if options.stdin_file is not None or options.stream_output or options.pty:
            raise ValueError('stdin, PTY and live command output are unavailable for transfers')
        self.options, self.settings = options, settings
        self._factory, self._audit = transport_factory, audit_factory
        self._planner, self._reporter, self._report = planner, reporter_factory, report_factory

    def plan(self) -> ResourcePlan:
        plan = self._planner(self.options)
        # Native rsync compression/file lists and hard-link tables cost extra memory.
        cost = plan.estimated_worker_bytes + 24 * MIB
        workers = min(plan.workers, plan.memory_budget_bytes // cost, self.settings.bandwidth_kib, self.options.bastion_bandwidth_kib)
        if workers < 1:
            raise ValueError("insufficient memory budget for one native transfer worker")
        return replace(plan, workers=workers, estimated_worker_bytes=cost)

    def _client(self, request: FileTransfer, plan: ResourcePlan) -> FileTransport:
        return self._factory(self.options, replace(self.settings, max_rsync_alloc_mib=min(
            self.settings.max_rsync_alloc_mib, max(1, plan.memory_budget_bytes // plan.workers // MIB // 2))), request,
                             min(self.settings.bandwidth_kib, self.options.bastion_bandwidth_kib) // plan.workers)

    def _descriptor(self, request):
        return request.descriptor + (":preview" if self.settings.dry_run else
            ":verify-sha256" if self.settings.verify_sha256 else "")

    def _swarm(self, client: FileTransport, request: FileTransfer, plan: ResourcePlan) -> Swarm:
        return Swarm(self.options,
            transport_factory=lambda _: _TransferOperation(client, self._descriptor(request)),
            audit_factory=self._audit, planner=lambda _: plan,
            reporter_factory=self._reporter, report_factory=self._report, progress_sink=self._progress_sink)

    async def iter_results(self, hosts: Iterable[Host | str], request: FileTransfer) -> AsyncGenerator[Result, None]:
        async with invocation(self):
            async with aclosing(self._iter_results(hosts, request)) as results:
                async for result in results:
                    yield result

    async def _iter_results(self, hosts: Iterable[Host | str], request: FileTransfer) -> AsyncGenerator[Result, None]:
        plan = self.plan()
        async with self._client(request, plan) as client:
            async with aclosing(self._swarm(client, request, plan).iter_results(hosts, self._descriptor(request))) as results:
                async for result in results:
                    yield result

    async def run(self, hosts: Iterable[Host | str], request: FileTransfer) -> ExecutionReport:
        async with invocation(self):
            return await self._run(hosts, request)

    async def _run(self, hosts: Iterable[Host | str], request: FileTransfer) -> ExecutionReport:
        plan = self.plan()
        async with self._client(request, plan) as client:
            return await self._swarm(client, request, plan).run(hosts, self._descriptor(request))

    async def run_to_file(self, hosts: Iterable[Host | str], request: FileTransfer, path: str | Path,
                          format: str = "json", *, spool_dir: str | Path | None = None) -> RunSummary:
        async with invocation(self):
            return await self._run_to_file(hosts, request, path, format, spool_dir=spool_dir)

    async def _run_to_file(self, hosts: Iterable[Host | str], request: FileTransfer,
                          path: str | Path, format: str = "json", *,
                          spool_dir: str | Path | None = None) -> RunSummary:
        plan = self.plan()
        async with self._client(request, plan) as client:
            return await self._swarm(client, request, plan).run_to_file(
                hosts, self._descriptor(request), path, format, spool_dir=spool_dir)
