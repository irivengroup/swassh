"""Public asynchronous and synchronous file-transfer facades."""
from __future__ import annotations
import asyncio
from collections.abc import Iterable
from pathlib import Path
from ..application.options import Options
from ..application.transfer_settings import TransferSettings
from ..application.transfers import TransferService
from ..application.contracts import RunSummary
from ..bootstrap import dependencies, file_transport_factory
from ..domain.models import Host
from ..domain.transfers import FileTransfer, TransferDirection


class FileSwarm(TransferService):
    def __init__(self, options: Options | None = None, settings: TransferSettings | None = None):
        options = options or Options()
        runtime = dependencies(options=options)
        super().__init__(options, settings or TransferSettings(),
            transport_factory=file_transport_factory(), audit_factory=runtime.audit_factory,
            planner=runtime.planner, reporter_factory=runtime.reporter_factory,
            report_factory=runtime.report_factory,
            invocation_factory=runtime.invocation_factory, progress_sink=runtime.progress_sink)


def _transfer_to_file(direction: TransferDirection, hosts: Iterable[Host | str],
                      source: str | Path, destination: str | Path, path: str | Path,
                      options: Options | None, format: str, settings: TransferSettings | None,
                      spool_dir: str | Path | None) -> RunSummary:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        local, remote = (source, destination) if direction == TransferDirection.PUSH else (destination, source)
        request = FileTransfer(direction, str(local), str(remote))
        return asyncio.run(FileSwarm(options, settings).run_to_file(
            hosts, request, path, format, spool_dir=spool_dir))
    raise RuntimeError("transfer API cannot run inside an event loop; await FileSwarm.run_to_file()")


def push_to_file(hosts: Iterable[Host | str], source: str | Path, destination: str | Path,
                 path: str | Path, options: Options | None = None, format: str = "json", *,
                 settings: TransferSettings | None = None, spool_dir: str | Path | None = None) -> RunSummary:
    return _transfer_to_file(TransferDirection.PUSH, hosts, source, destination, path,
                             options, format, settings, spool_dir)


def pull_to_file(hosts: Iterable[Host | str], source: str | Path, destination: str | Path,
                 path: str | Path, options: Options | None = None, format: str = "json", *,
                 settings: TransferSettings | None = None, spool_dir: str | Path | None = None) -> RunSummary:
    return _transfer_to_file(TransferDirection.PULL, hosts, source, destination, path,
                             options, format, settings, spool_dir)
