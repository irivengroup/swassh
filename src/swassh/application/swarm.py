"""Bounded worker swarm: O(concurrency) tasks, not one task per host."""

from __future__ import annotations

import asyncio
import hashlib
import uuid
import time
from collections.abc import AsyncGenerator, Iterable
from contextlib import aclosing
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from ..domain.inventory import normalize_hosts
from ..domain.commands import validate_command
from ..domain.models import Host, Result, Status
from ..domain.report import ExecutionReport
from .contracts import MIB, ResourcePlan, RunSummary
from .options import Options
from .profiles import ProfileResolver
from .admission import Admission
from .boundaries import invocation
from .ports import (
    AuditFactory,
    checkpoint_audit,
    prepare_report_destination,
    ReporterFactory,
    ReportFactory,
    ResourcePlanner,
    TransportFactory,
)

class Swarm:
    """Reusable orchestration service; each run owns its connections and workers."""

    def __init__(
        self,
        options: Options,
        *,
        transport_factory: TransportFactory,
        audit_factory: AuditFactory,
        planner: ResourcePlanner,
        reporter_factory: ReporterFactory,
        report_factory: ReportFactory,
        invocation_factory=None,
        progress_sink=None,
    ):
        self._invocation_factory, self._progress_sink = invocation_factory, progress_sink
        self.options = options
        self._transport_factory = transport_factory
        self._audit_factory = audit_factory
        self._planner = planner
        self._reporter_factory = reporter_factory
        self._report_factory = report_factory

    def plan(self) -> ResourcePlan:
        return self._planner(self.options)

    def _targets(self, hosts: Iterable[Host | str]) -> tuple[Host, ...]:
        return ProfileResolver(self.options).targets(hosts)

    async def iter_results(self, hosts: Iterable[Host | str], command: str, *,
                           run_id: str | None = None, _plan: ResourcePlan | None = None) -> AsyncGenerator[Result, None]:
        async with invocation(self):
            async with aclosing(self._iter_results(hosts, command, run_id=run_id, _plan=_plan)) as results:
                async for result in results:
                    yield result

    async def _iter_results(
        self, hosts: Iterable[Host | str], command: str, *, run_id: str | None = None, _plan: ResourcePlan | None = None
    ) -> AsyncGenerator[Result, None]:
        validate_command(command)
        transport = self._transport_factory(self.options)
        try:
            async with aclosing(self._transport_results(hosts, command, transport, run_id=run_id, _plan=_plan)) as results:
                async for result in results:
                    yield result
        finally:
            close = getattr(transport, 'aclose', None)
            if close is not None:
                await close()

    async def _transport_results(self, hosts, command, transport, *, run_id=None, _plan=None):
        """Yield completed hosts as they finish. Closing the iterator cancels workers.

        Use contextlib.aclosing() when stopping iteration early.
        """
        validate_command(command)
        targets = self._targets(hosts)
        plan = _plan or self.plan()
        admission = Admission(plan.workers, self.options.connect_rate / (2 if self.options.jump_host else 1),
            adaptive=self.options.adaptive, threshold=self.options.circuit_threshold)
        counts = {status.value: 0 for status in Status}
        def snapshot():
            values = admission.snapshot(len(targets), counts)
            measure = getattr(transport, "metrics", None)
            if measure:
                values.update(measure())
            return values
        async def show_progress():
            while True:
                await asyncio.sleep(self.options.progress_interval)
                self._progress_sink(snapshot())
        async def phase_results(phase_targets, phase):
            iterator = iter(phase_targets)
            queue: asyncio.Queue[Result] = asyncio.Queue(maxsize=plan.workers)
            async def worker():
                for host in iterator:
                    try:
                        try:
                            if not await admission.acquire():
                                result = Result(host, Status.SKIPPED, attempts=0,
                                    error="adaptive circuit open; target not executed")
                            else:
                                try:
                                    result = await transport.execute(host, command)
                                except BaseException:
                                    await admission.complete(Result(host, Status.ERROR))
                                    raise
                                if not isinstance(result, Result) or result.host != host:
                                    await admission.complete(Result(host, Status.ERROR))
                                    raise ValueError("transport returned a mismatched result")
                                await admission.complete(result)
                        except asyncio.CancelledError:
                            if asyncio.current_task().cancelling():
                                raise
                            raise RuntimeError("transport cancelled without caller cancellation") from None
                        if not isinstance(result, Result) or result.host != host:
                            raise ValueError("transport returned a mismatched result")
                        result = replace(result, phase=phase)
                    except Exception as exc:
                        result = Result(host, Status.ERROR,
                            error=f"transport error: {type(exc).__name__}", phase=phase)
                    await queue.put(result)
            workers = [asyncio.create_task(worker(), name=f"swassh-worker-{index}")
                for index in range(min(len(phase_targets), plan.workers))]
            failure = asyncio.get_running_loop().create_future()
            def completed(task):
                if (task.cancelled() or task.exception() is not None) and not failure.done():
                    failure.set_result(None)
            for task in workers:
                task.add_done_callback(completed)
            getter = None
            try:
                for _ in phase_targets:
                    if queue.empty():
                        getter = asyncio.create_task(queue.get())
                        done, _ = await asyncio.wait([getter, failure], return_when=asyncio.FIRST_COMPLETED)
                        if getter not in done:
                            raise RuntimeError("workers ended before all targets produced results")
                        result = await getter
                        getter = None
                    else:
                        result = queue.get_nowait()
                    yield result
            finally:
                if getter is not None:
                    getter.cancel()
                    await asyncio.gather(getter, return_exceptions=True)
                for task in workers:
                    task.cancel()
                await asyncio.gather(*workers, return_exceptions=True)
                failure.cancel()

        run_id = run_id or uuid.uuid4().hex
        canaries = min(self.options.canary, len(targets))
        canary_passed = None
        async with self._audit_factory(self.options.log_file, run_id) as audit:
            last_metrics = time.monotonic()
            async def record(result):
                nonlocal last_metrics
                counts[result.status.value] += 1
                await audit.emit("host_result", {
                    "target": result.host.target, "phase": result.phase,
                    "status": result.status.value, "exit_code": result.exit_code,
                    "exit_signal": result.exit_signal, "attempts": result.attempts,
                    "duration": result.duration, "stdout_truncated": result.stdout_truncated,
                    "stderr_truncated": result.stderr_truncated,
                    **({"operation": result.transfer.direction, "backend": result.transfer.backend,
                        "bytes_transferred": result.transfer.bytes_transferred,
                        "fallback_reason": result.transfer.fallback_reason} if result.transfer else {})})
                now = time.monotonic()
                interval = self.options.progress_interval or 5.0
                if now - last_metrics >= interval:
                    metrics = snapshot()
                    await audit.emit("run_metrics", metrics)
                    last_metrics = now
            await audit.emit("run_started", {"total": len(targets), "resource_plan": plan.to_dict(),
                "command_sha256": hashlib.sha256(command.encode()).hexdigest(),
                "canary_requested": self.options.canary, "canary_count": canaries,
                "adaptive": self.options.adaptive,
                "shared_ceiling": {"connections": self.options.bastion_concurrency,
                    "starts_per_second": self.options.bastion_connect_rate,
                    "memory_mib": self.options.bastion_memory_mib,
                    "bandwidth_kib": self.options.bastion_bandwidth_kib},
                "transfer_preview": command.endswith(":preview"),
                "transfer_integrity": command.endswith(":verify-sha256")})
            progress_task = (asyncio.create_task(show_progress(), name="swassh-progress")
                if self._progress_sink and self.options.progress_interval else None)
            try:
                await audit.emit("canary_started", {"selected": canaries, "pending": len(targets)-canaries})
                await checkpoint_audit(audit)
                canary_ok = True
                async with aclosing(phase_results(targets[:canaries], "canary")) as results:
                    async for result in results:
                        canary_ok &= result.status == Status.SUCCESS
                        await record(result)
                        yield result
                canary_passed = canary_ok
                await audit.emit("canary_passed" if canary_passed else "canary_failed",
                    {"selected": canaries, "pending": len(targets)-canaries})
                if canary_passed:
                    if canaries < len(targets):
                        await audit.emit("fleet_started", {"total": len(targets)-canaries})
                        await checkpoint_audit(audit)
                        async with aclosing(phase_results(targets[canaries:], "fleet")) as results:
                            async for result in results:
                                await record(result)
                                yield result
                else:
                    for host in targets[canaries:]:
                        result = Result(host, Status.SKIPPED, attempts=0, phase="fleet",
                            error="canary failed; target not executed")
                        await record(result)
                        yield result
            finally:
                if progress_task:
                    progress_task.cancel()
                    await asyncio.gather(progress_task, return_exceptions=True)
                metrics = snapshot()
                await audit.emit("run_metrics", metrics | {"final": True})
                if self._progress_sink and self.options.progress_interval:
                    self._progress_sink(metrics, final=True)
                complete = sum(counts.values()) == len(targets)
                await audit.emit("execution_completed" if complete else "execution_interrupted", {
                    "total": len(targets), "completed": sum(counts.values()), "counts": counts,
                    "executed": sum(counts.values())-counts[Status.SKIPPED.value],
                    "skipped": counts[Status.SKIPPED.value], "canary_passed": canary_passed})

    async def run(self, hosts: Iterable[Host | str], command: str) -> ExecutionReport:
        async with invocation(self):
            return await self._run(hosts, command)

    async def _run(self, hosts: Iterable[Host | str], command: str) -> ExecutionReport:
        targets = self._targets(hosts)
        started = datetime.now(UTC)
        run_id = uuid.uuid4().hex
        completed = {}
        retained = 0
        plan = self.plan()
        budget = plan.memory_budget_bytes // 4
        async with aclosing(
            self.iter_results(targets, command, run_id=run_id, _plan=plan)
        ) as results:
            async for result in results:
                retained += 1024 + 4 * (len(result.stdout) + len(result.stderr) + len(result.error or ""))
                if result.transfer:
                    retained += 4 * (len(result.transfer.local_path) + len(result.transfer.remote_path)
                                     + len(result.transfer.fallback_reason or "") + len(result.transfer.temporary_path or ""))
                if retained > budget:
                    raise ValueError(
                        "in-memory report budget exceeded; use Swarm.run_to_file()"
                    )
                completed[result.host.target] = result
        report = self._report_factory(
            command,
            tuple(completed[host.target] for host in targets),
            started,
            datetime.now(UTC),
            run_id,
        )
        return replace(report, canary_requested=self.options.canary,
                       show_output=self.options.show_output, output_lines=self.options.output_lines)

    async def run_to_file(self, hosts: Iterable[Host | str], command: str, path: str | Path,
                          format: str = "json", *, spool_dir: str | Path | None = None) -> RunSummary:
        async with invocation(self):
            return await self._run_to_file(hosts, command, path, format, spool_dir=spool_dir)

    async def _run_to_file(
        self,
        hosts: Iterable[Host | str],
        command: str,
        path: str | Path,
        format: str = "json",
        *,
        spool_dir: str | Path | None = None,
    ) -> RunSummary:
        """Mass-fleet API: bounded batches, private spool and streaming final export.

        Final reports are in completion order. Cancellation leaves any prior report
        intact and removes the incomplete private spool.
        """
        if format not in {"json", "csv", "text"}:
            raise ValueError("report format must be json, csv or text")
        destination = Path(path)
        plan = self.plan()
        started = datetime.now(UTC)
        run_id = uuid.uuid4().hex
        try:
            async with self._reporter_factory(
                spool_dir or destination.parent, self.options.max_report_mib * MIB
            ) as writer:
                await prepare_report_destination(writer, destination)
                # Preserve the legacy bound for every injected writer unless
                # that receiver explicitly advertises budgeted report batches.
                batch_limit = min(32, plan.workers)
                if getattr(writer, 'supports_spare_memory_batches', False) is True:
                    spare = max(0, plan.memory_budget_bytes - plan.workers * plan.estimated_worker_bytes)
                    report_slot = 8 * MIB + 16 * self.options.max_output_bytes
                    batch_limit = min(32, plan.workers + spare // report_slot)
                batch: list[Result] = []
                canary_count, canary_passed = 0, True
                async with aclosing(
                    self.iter_results(hosts, command, run_id=run_id, _plan=plan)
                ) as results:
                    async for result in results:
                        if result.phase == "canary":
                            canary_count += 1
                            canary_passed &= result.status == Status.SUCCESS
                        batch.append(result)
                        if len(batch) >= batch_limit:
                            await writer.append(batch)
                            batch.clear()
                if batch:
                    await writer.append(batch)
                counts = await writer.summary()
                summary = RunSummary(
                    sum(counts.values()),
                    counts,
                    started,
                    datetime.now(UTC),
                    plan,
                    run_id,
                    writer.worker_pid,
                    canary_requested=self.options.canary, canary_count=canary_count,
                    canary_passed=canary_passed,
                    show_output=self.options.show_output, output_lines=self.options.output_lines,
                )
                await writer.export(destination, format, command, summary)
                async with self._audit_factory(self.options.log_file, run_id) as audit:
                    await audit.emit(
                        "report_written", {"total": summary.total, "format": format}
                    )
                return summary
        except asyncio.CancelledError:
            async with self._audit_factory(self.options.log_file, run_id) as audit:
                await audit.emit("report_cancelled", {})
            raise
        except Exception as exc:
            async with self._audit_factory(self.options.log_file, run_id) as audit:
                await audit.emit("report_failed", {"error_type": type(exc).__name__})
            raise
