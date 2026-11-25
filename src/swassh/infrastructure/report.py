"""Stable report schema, exact response grouping and private atomic exports."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import os
import sys
import unicodedata
from collections.abc import Iterable
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .filesystem import AtomicOutput
from ..domain.models import Result, Status
from ..domain.report import ExecutionReport


def response_payload(result: Result) -> dict[str, Any]:
    key = (
        result.status.value,
        result.exit_code,
        result.exit_signal,
        result.stdout,
        result.stderr,
        result.error,
        result.stdout_truncated,
        result.stderr_truncated,
        result.changed,
    )
    digest = hashlib.sha256(json.dumps(key, ensure_ascii=False).encode()).hexdigest()
    return {
        "changed": result.changed,
        "id": digest,
        "status": result.status.value,
        "exit_code": result.exit_code,
        "exit_signal": result.exit_signal,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "error": result.error,
        "stdout_truncated": result.stdout_truncated,
        "stderr_truncated": result.stderr_truncated,
    }


def safe_text(value: str) -> str:
    return "".join("?" if (unicodedata.category(c) in {"Cf", "Cs", "Zl", "Zp"}
        or (ord(c) < 32 and c not in "\n\t") or 127 <= ord(c) <= 159) else c for c in value)


def _csv_safe(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    index = 0
    while index < len(value) and (value[index].isspace() or unicodedata.category(value[index]).startswith("C")):
        index += 1
    return "'" + value if value[index:].startswith(("=", "+", "-", "@")) else value


def csv_row(result: Result) -> dict[str, Any]:
    item = asdict(result)
    item.pop("host")
    transfer = item.pop("transfer")
    for field in ("direction", "local_path", "remote_path", "backend", "bytes_transferred", "fallback_reason", "temporary_path"):
        item["transfer_" + field] = transfer.get(field) if transfer else ""
    item.update(target=result.host.target, label=result.host.label or "")
    return {key: _csv_safe(value) for key, value in item.items()}


CSV_FIELDS = [
    "target",
    "label",
    "status",
    "phase",
    "changed",
    "exit_code",
    "exit_signal",
    "attempts",
    "duration",
    "stdout",
    "stderr",
    "error",
    "stdout_truncated",
    "stderr_truncated",
    "transfer_direction", "transfer_local_path", "transfer_remote_path",
    "transfer_backend", "transfer_bytes_transferred", "transfer_fallback_reason",
    "transfer_temporary_path",
]


class TerminalColor:
    """Decorate trusted headings only; redirected output and NO_COLOR stay plain."""

    _CODES = {"success": "92", "warning": "93", "danger": "91", "info": "94", "bold": "1"}

    def __init__(self, stream=None, enabled: bool | None = None):
        stream = sys.stdout if stream is None else stream
        self.enabled = (bool(getattr(stream, "isatty", lambda: False)())
                        and "NO_COLOR" not in os.environ and os.environ.get("TERM") != "dumb")
        if enabled is not None:
            self.enabled = enabled

    def _wrap(self, text: str, kind: str) -> str:
        return f"\033[{self._CODES[kind]}m{text}\033[0m" if self.enabled else text

    def success(self, text: str) -> str:
        return self._wrap(text, "success")

    def warning(self, text: str) -> str:
        return self._wrap(text, "warning")

    def danger(self, text: str) -> str:
        return self._wrap(text, "danger")

    def info(self, text: str) -> str:
        return self._wrap(text, "info")

    def bold(self, text: str) -> str:
        return self._wrap(text, "bold")

    def heading(self, line: str) -> str:
        """Color only structural report lines, never remote payload as markup."""
        if line.startswith("[FAILED"):
            return self.danger(line)
        if line.startswith("[CHANGED"):
            return self.warning(line)
        if line.startswith("SWASSH"):
            return self.bold(line)
        if line.startswith(("success ", "[OK /")):
            return self.success(line)
        return line

    def write(self, stream, line: str) -> None:
        """Keep text reports printable on legacy Windows redirected encodings."""
        text = self.heading(line)
        encoding = getattr(stream, 'encoding', None)
        if encoding:
            text = text.encode(encoding, errors='backslashreplace').decode(encoding)
        stream.write(text)


class ReportFormatter:
    """Command-agnostic, bounded exception report; complete data stays in exports."""

    def __init__(self, max_lines: int = 10, max_columns: int = 240, colors=None):
        if (isinstance(max_lines, bool) or not isinstance(max_lines, int) or not 0 <= max_lines <= 10000
                or isinstance(max_columns, bool) or not isinstance(max_columns, int) or max_columns < 1):
            raise ValueError("display lines must be 0..10000 and columns a positive integer")
        self.max_lines, self.max_columns = max_lines, max_columns
        self.colors = colors or TerminalColor(enabled=False)

    def _format_complex_output(self, message: str) -> str:
        """Strip and align arbitrary lines; neutralize terminal controls before display."""
        lines = str(message).strip().splitlines()
        if not lines:
            return "  │ (no output)"
        displayed = []
        for line in (lines[:self.max_lines] if self.max_lines else lines):
            clean = safe_text(line).expandtabs(4)
            suffix = " … [line truncated]" if len(clean) > self.max_columns else ""
            displayed.append("  │ " + clean[:self.max_columns] + suffix)
        if self.max_lines and len(lines) > self.max_lines:
            displayed.append(self.colors.info(f"  │ … [{len(lines) - self.max_lines} lines hidden]"))
        return "\n".join(displayed)

    def iter_lines(self, total, counts, groups, *, canary_requested=None, canary_count=0,
                   canary_passed=None, changed_count=0, show_output=False):
        """Yield display lines without collecting all host blocks in the parent or worker."""
        yield self.colors.bold(f"SWASSH — {total:,} hosts")
        if canary_requested is not None:
            outcome = "passed" if canary_passed else "failed; fleet blocked"
            yield (f"Canary: {canary_count:,} hosts — {outcome}")
        yield ""
        yield "STATUS              HOSTS"
        for status, count in counts.items():
            if count:
                yield (self.colors.heading(f"{status:<18} {count:>8,}"))
        if changed_count:
            yield (self.colors.warning(f"changed (success subset): {changed_count:,}"))
        yield ("\nOutput by host:" if show_output else "\nMost common exceptional response per status:")
        for payload, count, samples, other_groups in groups:
            changed = payload.get("changed", False)
            status = payload["status"]
            if status == Status.SUCCESS and not changed and not show_output:
                continue
            # Skips are not remote failures and have no command output to expand.
            label = ("CHANGED" if changed else "OK" if status == Status.SUCCESS
                     else "SKIPPED" if status == Status.SKIPPED else "FAILED")
            yield (self.colors.heading(f"\n[{label} / {status}] {count:,} hosts".lstrip("\n")))
            targets = ", ".join(safe_text(target) for target in samples)
            remaining = count - len(samples)
            yield (f"  hosts: {targets}" + (f" (+{remaining:,})" if remaining else ""))
            yield (f"  exit code: {payload.get('exit_code')}")
            if label != "SKIPPED":
                for name in ("stdout", "stderr", "error"):
                    if payload.get(name):
                        yield (f"  {name}:")
                        yield (self._format_complex_output(payload[name]))
            if payload["stdout_truncated"] or payload["stderr_truncated"]:
                yield ("  capture output truncated")
            if other_groups:
                yield (f"  {other_groups:,} additional response groups (see JSON/CSV)")
        yield ("\nFull host details: --format json|csv --output REPORT")

    def write(self, stream, total, counts, groups, **options) -> None:
        """Write incrementally in the single report process."""
        for line in self.iter_lines(total, counts, groups, **options):
            stream.write(line + "\n")

    def render(self, total, counts, groups, **options) -> str:
        return "\n".join(self.iter_lines(total, counts, groups, **options)) + "\n"


def compact_text(total, counts, groups, **options) -> str:
    """Compatibility entry point shared by memory and multiprocessing writers."""
    return ReportFormatter(max_lines=options.pop("output_lines", 10)).render(total, counts, groups, **options)


class Report(ExecutionReport):
    """Serialization adapter for an execution report."""

    def response_groups(self) -> list[dict[str, Any]]:
        """Group exact captured responses; truncation participates in identity."""
        groups: dict[str, dict[str, Any]] = {}
        for result in self.results:
            payload = response_payload(result)
            digest = payload["id"]
            if digest not in groups:
                groups[digest] = payload | {"targets": []}
            groups[digest]["targets"].append(result.host.target)
        return list(groups.values())

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "run_id": self.run_id,
            "command": self.command,
            "canary": {"requested": self.canary_requested, "selected": self.canary_count,
                       "passed": self.canary_passed},
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat(),
            "duration": (self.finished_at - self.started_at).total_seconds(),
            "total": len(self.results),
            "ok": self.ok,
            "counts": self.counts,
            "groups": {
                status: [r.host.target for r in results]
                for status, results in self.groups().items()
            },
            "response_groups": self.response_groups(),
            "results": [asdict(result) for result in self.results],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2) + "\n"

    def to_csv(self) -> str:
        stream = io.StringIO(newline="")
        writer = csv.DictWriter(stream, CSV_FIELDS)
        writer.writeheader()
        for result in self.results:
            writer.writerow(csv_row(result))
            stream.write("\r\n")
        return stream.getvalue()

    def to_text(self) -> str:
        if self.show_output:
            return compact_text(len(self.results), self.counts,
                ((response_payload(r), 1, [r.host.target], 0) for r in self.results),
                show_output=True, output_lines=self.output_lines,
                canary_requested=self.canary_requested, canary_count=self.canary_count,
                canary_passed=self.canary_passed, changed_count=sum(r.changed for r in self.results))
        groups = self.response_groups()
        displayed = []
        for status, changed in [(s, False) for s in Status] + [(Status.SUCCESS, True)]:
            matching = [group for group in groups if group["status"] == status and group["changed"] == changed]
            if matching:
                largest = max(matching, key=lambda group: len(group["targets"]))
                displayed.append(
                    (
                        largest,
                        len(largest["targets"]),
                        largest["targets"][:3],
                        len(matching) - 1,
                    )
                )
        return compact_text(len(self.results), self.counts, displayed,
            canary_requested=self.canary_requested, canary_count=self.canary_count, canary_passed=self.canary_passed,
            changed_count=sum(result.changed for result in self.results), output_lines=self.output_lines)

    def write(self, path: str | Path, format: str = "json") -> None:
        serializers = {"json": self.to_json, "csv": self.to_csv, "text": self.to_text}
        if format not in serializers:
            raise ValueError("report format must be json, csv or text")
        content = serializers[format]()
        destination = Path(path)
        with AtomicOutput(destination) as stream:
            stream.write(content)
