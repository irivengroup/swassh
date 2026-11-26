"""Strict inventory parsing. Inventories are data, never executable code."""

from __future__ import annotations

import csv
import io
import json
import shlex
import os
import stat
from pathlib import Path
from typing import Any

from .json_data import _unique_object, _invalid_constant
from ..domain.models import Host
from ..domain.inventory import MAX_HOSTS, InventoryError, normalize_hosts, parse_host, _parse_port

MAX_INVENTORY_BYTES = 10 * 1024 * 1024


def _mapping_host(item: Any) -> Host:
    if isinstance(item, str):
        return parse_host(item)
    if not isinstance(item, dict) or set(item) - {
        "hostname",
        "port",
        "username",
        "label",
    }:
        raise InventoryError(
            "host records require hostname, optional port, username and label"
        )
    try:
        return Host(**item)
    except (TypeError, ValueError) as exc:
        raise InventoryError(str(exc)) from exc


def _yaml_content(raw: str) -> str:
    """Remove an unquoted comment without altering quoted scalar bytes.

    This remains a single-line subset. Single quotes escape by doubling;
    double-quoted values use the existing strict JSON decoder. Shell token
    joining would insert spaces between consecutive YAML quote escapes.
    """
    quote = None
    index = 0
    while index < len(raw):
        char = raw[index]
        if quote is None:
            if char == '#':
                return raw[:index].strip()
            if char in {'"', "'"} and (index == 0 or raw[index - 1].isspace()):
                quote = char
        elif quote == '"' and char == '\\':
            index += 1
        elif char == quote:
            if quote == "'" and index + 1 < len(raw) and raw[index + 1] == "'":
                index += 1
            else:
                quote = None
        index += 1
    if quote is not None:
        raise InventoryError('unclosed YAML quote')
    return raw.strip()


def _yaml_records(content: str) -> list[Any]:
    """Deliberately strict SWASSH YAML subset: a scalar/record list, no general YAML."""
    import re

    records: list[Any] = []
    current: dict[str, Any] | None = None
    base_indent: int | None = None
    saw_root = False
    for raw in io.StringIO(content):
        if "\t" in raw:
            raise InventoryError("YAML indentation must use spaces")
        line = _yaml_content(raw)
        if not line:
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if line == "hosts:":
            if saw_root or records or indent:
                raise InventoryError("YAML hosts root must occur once before the list")
            saw_root = True
            continue
        item = line.startswith("- ")
        if item:
            if base_indent is None:
                base_indent = indent
            if indent != base_indent:
                raise InventoryError("YAML list items require consistent indentation")
            line = line[2:].strip()
            current = None
        elif current is None or base_indent is None or indent <= base_indent:
            raise InventoryError("YAML requires a hosts list or a top-level list")
        match = re.fullmatch(r"([A-Za-z_][A-Za-z_0-9]*):(?: +(.*))?", line)
        if match:
            key, value = match.group(1), match.group(2) or ""
            if key not in {"hostname", "port", "username", "label"} or not value:
                raise InventoryError("unknown YAML field or empty value")
            if value.startswith('"'):
                scalar = json.loads(value)
            elif value.startswith("'"):
                if not re.fullmatch(r"'(?:[^']|'')*'", value):
                    raise InventoryError("invalid YAML single-quoted scalar")
                scalar = value[1:-1].replace("''", "'")
            elif any(char in value for char in "&*!{}[]"):
                raise InventoryError(
                    "YAML anchors, tags and flow syntax are not supported"
                )
            elif key == "port":
                scalar = _parse_port(value)
            else:
                scalar = value
            if item:
                current = {}
                records.append(current)
                if len(records) > MAX_HOSTS:
                    raise InventoryError("too many YAML records")
            # Mapping creation or the earlier continuation guard establishes this invariant.
            if key in current:
                raise InventoryError("duplicate YAML host field")
            current[key] = scalar
        elif item:
            if line.startswith('"'):
                line = json.loads(line)
            elif line.startswith("'"):
                if not re.fullmatch(r"'(?:[^']|'')*'", line):
                    raise InventoryError("invalid YAML single-quoted scalar")
                line = line[1:-1].replace("''", "'")
            records.append(line)
            if len(records) > MAX_HOSTS:
                raise InventoryError("too many YAML records")
        else:
            raise InventoryError("invalid YAML host field")
    return records


def load_inventory(path: str | Path) -> tuple[Host, ...]:
    """Read TXT, CSV, JSON or YAML in the documented SWASSH inventory schema."""
    source = Path(path)
    descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(descriptor, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise InventoryError("inventory must be a regular file")
        raw = stream.read(MAX_INVENTORY_BYTES + 1)
    if len(raw) > MAX_INVENTORY_BYTES:
        raise InventoryError("inventory exceeds 10 MiB")
    try:
        content = raw.decode("utf-8-sig")
        suffix = source.suffix.lower()
        if suffix == ".ini":
            raise InventoryError("INI/Ansible inventories are not supported")
        if suffix in {".yaml", ".yml", ".json"}:
            document = (
                json.loads(content, object_pairs_hook=_unique_object, parse_constant=_invalid_constant) if suffix == ".json" else _yaml_records(content)
            )
            if isinstance(document, dict) and set(document) == {"hosts"}:
                document = document["hosts"]
            if not isinstance(document, list):
                raise InventoryError(
                    "structured inventories require a list or a hosts list"
                )
            if len(document) > MAX_HOSTS:
                raise InventoryError("too many structured inventory records")
            return normalize_hosts(_mapping_host(item) for item in document)
        if suffix == ".csv":
            reader = csv.DictReader(io.StringIO(content), strict=True)
            if not reader.fieldnames or "hostname" not in reader.fieldnames:
                raise InventoryError("CSV requires a hostname header")
            if (len(set(reader.fieldnames)) != len(reader.fieldnames)
                    or set(reader.fieldnames) - {"hostname", "port", "username", "label"}):
                raise InventoryError("duplicate or unknown CSV headers")
            records: list[Host] = []
            for row in reader:
                if len(records) >= MAX_HOSTS or None in row or any(value is None for value in row.values()):
                    raise InventoryError("too many or malformed CSV records")
                item = {key: value for key, value in row.items() if value}
                if "port" in item:
                    item["port"] = _parse_port(item["port"])
                records.append(_mapping_host(item))
            return normalize_hosts(records)
        values: list[str] = []
        for line in io.StringIO(content):
            tokens = shlex.split(line, comments=True)
            if len(tokens) > 1:
                raise InventoryError(
                    "TXT requires one host per line; INI/Ansible is not supported"
                )
            values.extend(tokens)
            if len(values) > MAX_HOSTS:
                raise InventoryError("too many TXT records")
        return normalize_hosts(values)
    except (UnicodeError, ValueError, TypeError, RecursionError, csv.Error) as exc:
        if isinstance(exc, InventoryError):
            raise
        raise InventoryError(f"invalid inventory: {exc}") from exc
