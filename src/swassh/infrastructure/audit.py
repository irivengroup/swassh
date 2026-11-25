"""Private JSONL audit trail, threaded batches and three gzip rotations."""

from __future__ import annotations

from ..application.task_ownership import wait_owned

import asyncio
import gzip
import importlib
import json
import logging
import os
import shutil
import stat
import tempfile
from collections.abc import Mapping
from datetime import UTC, datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

from typing import Self

from .filesystem import open_private_append, private_directory, sync_directory
from .lifecycle import finish_task

LOG_MAX_BYTES = 100 * 1024 * 1024
LOG_RETENTIONS = 3


def default_log_path() -> Path:
    if os.name == "nt":
        parent = Path(
            os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local"))
        )
    else:
        parent = Path(
            os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local" / "state"))
        )
    return parent / "swassh" / "swassh.jsonl"


def _private_open(path: str | Path) -> Any:
    return open_private_append(path)


def _compress(source: str, destination: str) -> None:
    descriptor, temporary = tempfile.mkstemp(
        prefix=".swassh-gzip-", dir=Path(destination).parent
    )
    try:
        with os.fdopen(descriptor, "wb") as output:
            with (
                gzip.GzipFile(fileobj=output, mode="wb") as archive,
                os.fdopen(os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                                 | getattr(os, "O_NONBLOCK", 0)), "rb") as stream,
            ):
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise ValueError("rotation source must be an unlinked regular file")
                shutil.copyfileobj(stream, archive, length=1024 * 1024)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, destination)
        os.unlink(source)
        sync_directory(Path(destination).parent)
    finally:
        Path(temporary).unlink(missing_ok=True)


class AuditHandler(RotatingFileHandler):
    def __init__(self, path: Path):
        self._directory_dirty = False
        super().__init__(
            path, maxBytes=LOG_MAX_BYTES, backupCount=LOG_RETENTIONS, encoding="utf-8"
        )
        self.namer = lambda name: name + ".gz"
        self.rotator = _compress
        self.setFormatter(logging.Formatter("%(message)s"))

    def _open(self) -> Any:
        stream = _private_open(self.baseFilename)
        self._directory_dirty = True
        return stream

    def synchronize(self) -> None:
        self.flush()
        os.fsync(self.stream.fileno())
        if self._directory_dirty:
            sync_directory(Path(self.baseFilename).parent)
            self._directory_dirty = False

    def handleError(self, record: logging.LogRecord) -> None:
        # Audit failures are propagated, rather than printing secrets or silently dropping records.
        raise OSError("audit log write failed")


class _WriterLock:
    """One writer per log path across processes, including rotations."""

    def __init__(self, path: Path):
        self.stream = _private_open(str(path) + ".lock")
        try:
            if os.fstat(self.stream.fileno()).st_size == 0:
                self.stream.write("0")
                self.stream.flush()
            self.stream.seek(0)
            try:
                if os.name == "nt":
                    msvcrt = importlib.import_module("msvcrt")
                    msvcrt.locking(self.stream.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(self.stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                raise OSError("audit log already has an active writer") from None
        except BaseException:
            # The constructor owns this descriptor as soon as opening succeeds,
            # including failures before the operating-system lock is attempted.
            self.stream.close()
            raise

    def close(self) -> None:
        # Closing releases the advisory OS lock; its tiny marker file is intentionally retained.
        self.stream.close()


class AuditTrail:
    """A buffer of at most 64 records. Disk slowness applies backpressure."""

    def __init__(self, path: str | None, run_id: str):
        self.path = Path(path) if path else None
        self.run_id = run_id
        self._batch: list[logging.LogRecord] = []
        self.handler: AuditHandler | None = None
        self.lock: _WriterLock | None = None

    async def __aenter__(self) -> Self:
        if self.path is not None:
            private_directory(self.path.parent)
            self.lock = _WriterLock(self.path)
            try:
                self.handler = AuditHandler(self.path)
            except BaseException:
                self.lock.close()
                raise
        return self

    async def emit(self, event: str, values: Mapping[str, Any]) -> None:
        if self.handler is None:
            return
        payload = {
            **values,
            "timestamp": datetime.now(UTC).isoformat(),
            "run_id": self.run_id,
            "pid": os.getpid(),
            "event": event,
        }
        self._batch.append(
            logging.LogRecord(
                "swassh",
                logging.INFO,
                "",
                0,
                json.dumps(payload, ensure_ascii=True),
                (),
                None,
            )
        )
        if len(self._batch) >= 64:
            await self.flush()

    async def flush(self) -> None:
        if self.handler is None or not self._batch:
            return
        handler, records = self.handler, self._batch
        self._batch = []

        def write() -> None:
            for record in records:
                handler.handle(record)
            handler.synchronize()

        task = asyncio.create_task(asyncio.to_thread(write))
        try:
            await wait_owned(task)
        except asyncio.CancelledError:
            await finish_task(task)
            raise

    async def __aexit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        try:
            await self.flush()
        finally:
            try:
                if self.handler is not None:
                    self.handler.close()
            finally:
                # A failed flush/close must not keep subsequent runs locked out.
                if self.lock is not None:
                    self.lock.close()
