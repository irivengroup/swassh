"""Disk-backed reports with bounded SQLite cache and streaming atomic exports."""

from __future__ import annotations

import csv
import json
import os
import sqlite3
import tempfile
import threading
from collections.abc import Iterable, Iterator
from dataclasses import asdict
from pathlib import Path
from typing import Any, TextIO

from .filesystem import AtomicOutput, trusted_parents, sync_directory
from ..domain.models import Host, Result, Status, TransferReceipt
from .report import CSV_FIELDS, ReportFormatter, csv_row, response_payload
from ..application.contracts import RunSummary


class ReportStore:
    """A private per-run spool. All operations are serialized by the caller."""

    def __init__(self, directory: str | Path | None, max_bytes: int):
        trusted_parents(Path(directory or tempfile.gettempdir()) / "swassh-spool-boundary")
        descriptor, name = tempfile.mkstemp(
            prefix="swassh-", suffix=".sqlite", dir=directory
        )
        os.close(descriptor)
        self.path = Path(name)
        self.max_bytes = max_bytes
        self.bytes = 0
        self._cancelled = threading.Event()
        self.counts = {status.value: 0 for status in Status}
        self.db = None
        try:
            self.db = sqlite3.connect(self.path, check_same_thread=False)
            self.db.execute("PRAGMA cache_size=-2048")
            self.db.execute("PRAGMA temp_store=FILE")
            self.db.execute("PRAGMA synchronous=FULL")
            page_size = self.db.execute("PRAGMA page_size").fetchone()[0]
            self.db.execute(f"PRAGMA max_page_count={max(1, self.max_bytes // page_size)}")
            self.db.executescript("""
                CREATE TABLE responses (seq INTEGER PRIMARY KEY, id TEXT UNIQUE NOT NULL,
                                        payload TEXT NOT NULL, status TEXT NOT NULL, changed INTEGER NOT NULL,
                                        count INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE results (seq INTEGER PRIMARY KEY, target TEXT UNIQUE NOT NULL,
                                      status TEXT NOT NULL, response_id TEXT NOT NULL,
                                      metadata TEXT NOT NULL);
                CREATE INDEX result_status ON results(status, seq);
                CREATE INDEX result_response ON results(response_id, seq);
            """)
        except BaseException:
            if self.db is not None:
                self.db.close()
            for suffix in ("", "-journal", "-wal", "-shm"):
                Path(str(self.path) + suffix).unlink(missing_ok=True)
            raise

    def cancel(self) -> None:
        self._cancelled.set()

    def _check_cancelled(self) -> None:
        if self._cancelled.is_set():
            raise InterruptedError("report writing cancelled")

    def close(self) -> None:
        self.db.close()
        for suffix in ("", "-journal", "-wal", "-shm"):
            Path(str(self.path) + suffix).unlink(missing_ok=True)

    def append(self, results: Iterable[Result]) -> None:
        previous_bytes, previous_counts = self.bytes, dict(self.counts)
        try:
            with self.db:
                for result in results:
                    self._check_cancelled()
                    payload = response_payload(result)
                    encoded = json.dumps(payload, ensure_ascii=False)
                    digest = payload["id"]
                    cursor = self.db.execute(
                        "INSERT OR IGNORE INTO responses(id,payload,status,changed) VALUES (?,?,?,?)",
                        (digest, encoded, result.status.value, int(result.changed)),
                    )
                    if cursor.rowcount:
                        self.bytes += len(encoded.encode("utf-8")) + 512
                    metadata = asdict(result)
                    for key in payload:
                        if key != "id":
                            metadata.pop(key)
                    record = json.dumps(metadata, ensure_ascii=False)
                    self.bytes += len(record.encode("utf-8")) + 1024
                    # Enforce both a conservative logical estimate and the actual SQLite size.
                    if max(self.bytes, self.path.stat().st_size) > self.max_bytes:
                        raise ValueError(
                            "report spool budget exceeded; increase max_report_mib"
                        )
                    self.db.execute(
                        "INSERT INTO results(target,status,response_id,metadata) VALUES (?,?,?,?)",
                        (result.host.target, result.status.value, digest, record),
                    )
                    self.db.execute(
                        "UPDATE responses SET count=count+1 WHERE id=?", (digest,)
                    )
                    self.counts[result.status.value] += 1
                self._check_cancelled()
            if self.path.stat().st_size > self.max_bytes:
                raise ValueError("report spool budget exceeded; increase max_report_mib")
        except BaseException as exc:
            self.bytes, self.counts = previous_bytes, previous_counts
            if isinstance(exc, sqlite3.Error) and getattr(exc, "sqlite_errorcode", None) == sqlite3.SQLITE_FULL:
                raise ValueError("report spool budget or disk capacity exceeded") from exc
            raise

    def _results(self, status: str | None = None) -> Iterator[Result]:
        query = "SELECT r.metadata,p.payload FROM results r JOIN responses p ON r.response_id=p.id"
        parameters: tuple[str, ...] = ()
        if status is not None:
            query += " WHERE r.status=?"
            parameters = (status,)
        query += " ORDER BY r.seq"
        for metadata, response in self.db.execute(query, parameters):
            self._check_cancelled()
            item = json.loads(metadata)
            payload = json.loads(response)
            payload.pop("id")
            item.update(payload)
            item["host"] = Host(**item["host"])
            item["status"] = Status(item["status"])
            if item.get("transfer") is not None:
                item["transfer"] = TransferReceipt(**item["transfer"])
            yield Result(**item)

    def _value(self, stream: TextIO, value: Any, depth: int) -> None:
        """Indent one bounded value at a time, never the whole fleet."""
        # Only structural LF separates pretty-printed JSON lines. str.splitlines
        # also splits legal Unicode characters inside JSON strings, corrupting
        # their content. One bounded value/write also avoids per-line IPC tracing
        # overhead; array iteration retains its per-record cancellation check.
        encoded = json.dumps(value, ensure_ascii=False, indent=2)
        stream.write(encoded.replace("\n", "\n" + "  " * depth))

    def _array(self, stream: TextIO, values: Iterable[Any], depth: int) -> None:
        stream.write("[")
        separator = ""
        for value in values:
            self._check_cancelled()
            stream.write(separator + "\n" + "  " * (depth + 1))
            self._value(stream, value, depth + 1)
            separator = ","
        stream.write(("\n" + "  " * depth if separator else "") + "]")

    def _json(self, stream: TextIO, command: str, summary: RunSummary) -> None:
        header = {
            "schema_version": 1,
            "run_id": summary.run_id,
            "report_worker_pid": summary.report_worker_pid,
            "command": command,
            "canary": {"requested": summary.canary_requested, "selected": summary.canary_count,
                       "passed": summary.canary_passed},
            "started_at": summary.started_at.isoformat(),
            "finished_at": summary.finished_at.isoformat(),
            "duration": (summary.finished_at - summary.started_at).total_seconds(),
            "total": summary.total,
            "ok": summary.ok,
            "counts": summary.counts,
            "resource_plan": summary.plan.to_dict(),
        }
        stream.write(json.dumps(header, ensure_ascii=False, indent=2).rstrip()[:-2] + ',\n  "groups": {')
        separator = ""
        for status in Status:
            stream.write(separator + "\n    " + json.dumps(status.value) + ": ")
            self._array(stream, (row[0] for row in self.db.execute(
                "SELECT target FROM results WHERE status=? ORDER BY seq", (status.value,))), 2)
            separator = ","
        stream.write('\n  },\n  "response_groups": [')
        separator = ""
        for digest, encoded in self.db.execute("SELECT id,payload FROM responses ORDER BY seq"):
            self._check_cancelled()
            stream.write(separator + "\n    {")
            for name, value in json.loads(encoded).items():
                stream.write("\n      " + json.dumps(name) + ": ")
                self._value(stream, value, 3)
                stream.write(",")
            stream.write('\n      "targets": ')
            self._array(stream, (row[0] for row in self.db.execute(
                "SELECT target FROM results WHERE response_id=? ORDER BY seq", (digest,))), 3)
            stream.write("\n    }")
            separator = ","
        stream.write('\n  ],\n  "results": ')
        self._array(stream, (asdict(result) for result in self._results()), 1)
        stream.write("\n}\n")

    def _csv(self, stream: TextIO) -> None:
        writer = csv.DictWriter(stream, CSV_FIELDS)
        writer.writeheader()
        for result in self._results():
            writer.writerow(csv_row(result))
            stream.write("\r\n")

    def _text(self, stream: TextIO, summary: RunSummary) -> None:
        displayed = []
        for status, changed in [(s, False) for s in Status] + [(Status.SUCCESS, True)]:
            row = self.db.execute(
                "SELECT id,payload,count FROM responses WHERE status=? AND changed=? "
                "ORDER BY count DESC,seq LIMIT 1",
                (status.value, int(changed)),
            ).fetchone()
            if row is None:
                continue
            digest, encoded, count = row
            groups = self.db.execute(
                "SELECT COUNT(*) FROM responses WHERE status=? AND changed=?", (status.value, int(changed))
            ).fetchone()[0]
            targets = [
                item[0]
                for item in self.db.execute(
                    "SELECT target FROM results WHERE response_id=? ORDER BY seq LIMIT 3",
                    (digest,),
                )
            ]
            displayed.append((json.loads(encoded), count, targets, groups - 1))
        if summary.show_output:
            displayed = ((response_payload(r), 1, [r.host.target], 0) for r in self._results())
        ReportFormatter(max_lines=summary.output_lines).write(stream, summary.total, summary.counts, displayed,
            canary_requested=summary.canary_requested, canary_count=summary.canary_count,
            canary_passed=summary.canary_passed, show_output=summary.show_output,
            changed_count=self.db.execute("SELECT COALESCE(SUM(count),0) FROM responses WHERE changed=1").fetchone()[0])


    def export(
        self, destination: Path, format: str, command: str, summary: RunSummary
    ) -> None:
        if format not in {"json", "csv", "text"}:
            raise ValueError("report format must be json, csv or text")
        with AtomicOutput(destination) as stream:
            if format == "json":
                self._json(stream, command, summary)
            elif format == "csv":
                self._csv(stream)
            else:
                self._text(stream, summary)
            self._check_cancelled()


# A single process owns this store; it never receives Python code from an inventory.
_PROCESS_STORE: ReportStore | None = None
_PROCESS_BUDGET = _PROCESS_LEASE = None


def initialize_store(directory: str, max_bytes: int, cancelled: Any, parent=None, budget=None, invocation=None) -> None:
    if parent is not None:
        import threading
        def watch_parent():
            try:
                parent.recv_bytes()
            except (EOFError, OSError):
                os._exit(125)
            os._exit(125)
        threading.Thread(target=watch_parent, name="swassh-parent-watch", daemon=True).start()
    global _PROCESS_STORE, _PROCESS_BUDGET, _PROCESS_LEASE
    if budget and invocation:
        from .bastion import SharedBudget
        _PROCESS_BUDGET = SharedBudget(budget)
        _PROCESS_LEASE = _PROCESS_BUDGET.ticket(parent=invocation)
    _PROCESS_STORE = ReportStore(directory, max_bytes)
    _PROCESS_STORE._cancelled = cancelled


def store_operation(operation: str, *arguments: Any) -> Any:
    global _PROCESS_STORE, _PROCESS_BUDGET, _PROCESS_LEASE
    store = _PROCESS_STORE
    if store is None:
        raise RuntimeError("report worker was not initialized")
    if operation == "append":
        store.append(arguments[0])
        return None
    if operation == "summary":
        return dict(store.counts)
    if operation == "export":
        store.export(*arguments)
        return None
    if operation == "close":
        store.close()
        _PROCESS_STORE = None
        # Retain the dependent lease until this worker actually exits. The
        # parent joins it before releasing its memory; next admission reclaims
        # the stale child row using its OS lock, without relying on a PID.
        return None
    if operation == "identity":
        return str(store.path), os.getpid()
    raise ValueError("unknown report worker operation")
