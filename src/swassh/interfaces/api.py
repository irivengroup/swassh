"""Stable public facade with default composition; core use cases stay injectable."""

from __future__ import annotations

import asyncio
from collections.abc import Iterable
from pathlib import Path

from ..application.contracts import RunSummary
from ..application.options import Options
from ..application.ports import Transport, TransportFactory
from ..application.swarm import Swarm as ExecutionService
from ..bootstrap import dependencies
from ..domain.models import Host
from ..infrastructure.report import Report


class Swarm(ExecutionService):
    """Compatible Swarm API, using the standard system adapters by default."""

    def __init__(
        self, options: Options | None = None, *, transport: Transport | None = None,
        transport_factory: TransportFactory | None = None,
    ):
        options = options or Options()
        runtime = dependencies(transport, options=options, transport_factory=transport_factory)
        super().__init__(
            options,
            transport_factory=runtime.transport_factory,
            audit_factory=runtime.audit_factory,
            planner=runtime.planner,
            reporter_factory=runtime.reporter_factory,
            report_factory=runtime.report_factory,
            invocation_factory=runtime.invocation_factory, progress_sink=runtime.progress_sink,
        )


def execute(
    hosts: Iterable[Host | str], command: str, options: Options | None = None
) -> Report:
    """Synchronous API. In an existing event loop, await Swarm.run() instead."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(Swarm(options).run(hosts, command))
    raise RuntimeError("execute() cannot run inside an event loop; await Swarm.run()")


def execute_to_file(
    hosts: Iterable[Host | str],
    command: str,
    path: str | Path,
    options: Options | None = None,
    format: str = "json",
    *,
    spool_dir: str | Path | None = None,
) -> RunSummary:
    """Synchronous mass-fleet API; returns counters without collecting all results."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(
            Swarm(options).run_to_file(
                hosts, command, path, format, spool_dir=spool_dir
            )
        )
    raise RuntimeError(
        "execute_to_file() cannot run inside an event loop; await Swarm.run_to_file()"
    )
