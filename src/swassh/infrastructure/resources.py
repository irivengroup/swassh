"""Conservative resource ceilings and paced connection admission."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from ..application.options import Options
from ..application.contracts import MIB, ResourcePlan

def _linux_available_memory() -> int | None:
    try:
        entries = dict(
            line.split(":", 1)
            for line in Path("/proc/meminfo").read_text().splitlines()
        )
        available = int(entries["MemAvailable"].split()[0]) * 1024
    except (OSError, ValueError, KeyError):
        return None
    # Apply every readable cgroup v2 ancestor limit, including nested containers.
    cgroup = Path("/sys/fs/cgroup")
    paths = [cgroup]
    try:
        for entry in Path("/proc/self/cgroup").read_text().splitlines():
            if entry.startswith("0::"):
                relative = Path(entry[3:].lstrip("/"))
                if ".." not in relative.parts:
                    nested = cgroup / relative
                    paths = [nested, *nested.parents]
                    paths = [path for path in paths if path == cgroup or cgroup in path.parents]
                break
    except OSError:
        pass
    for path in paths:
        try:
            maximum = (path / "memory.max").read_text().strip()
            current = int((path / "memory.current").read_text())
            if maximum != "max":
                available = min(available, max(0, int(maximum) - current))
        except (OSError, ValueError):
            pass
    return available


def _sysconf_available_memory() -> int | None:
    # Availability varies by POSIX platform; physical total is not free memory.
    try:
        pages = os.sysconf('SC_AVPHYS_PAGES')
        page_size = os.sysconf('SC_PAGE_SIZE')
    except (AttributeError, OSError, ValueError, KeyError):
        return None
    if type(pages) is not int or type(page_size) is not int or pages < 0 or page_size <= 0:
        return None
    return pages * page_size


def _windows_available_memory() -> int | None:
    import ctypes

    class MemoryStatus(ctypes.Structure):
        _fields_ = [('length', ctypes.c_uint32), ('load', ctypes.c_uint32),
            ('total_physical', ctypes.c_uint64), ('available_physical', ctypes.c_uint64),
            ('total_pagefile', ctypes.c_uint64), ('available_pagefile', ctypes.c_uint64),
            ('total_virtual', ctypes.c_uint64), ('available_virtual', ctypes.c_uint64),
            ('available_extended_virtual', ctypes.c_uint64)]
    try:
        kernel = ctypes.WinDLL('kernel32.dll', use_last_error=True)
        query = kernel.GlobalMemoryStatusEx
        query.argtypes, query.restype = [ctypes.POINTER(MemoryStatus)], ctypes.c_int
        memory = MemoryStatus()
        memory.length = ctypes.sizeof(memory)
        return int(memory.available_physical) if query(ctypes.byref(memory)) else None
    except (AttributeError, OSError):
        return None


def _available_memory() -> int | None:
    if sys.platform == 'win32':
        return _windows_available_memory()
    if sys.platform.startswith('linux'):
        measured = _linux_available_memory()
        if measured is not None:
            return measured
    return _sysconf_available_memory()


def _descriptor_workers(jump: bool) -> int:
    try:
        import resource

        soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
    except (ImportError, AttributeError, OSError, ValueError):
        return 64
    if soft == resource.RLIM_INFINITY:
        return 256
    used = None
    paths = ('/proc/self/fd', '/dev/fd') if sys.platform.startswith('linux') else ('/dev/fd',)
    for path in paths:
        try:
            used = len(os.listdir(path))
            break
        except OSError:
            continue
    # Reserve an additional conservative allowance where descriptor listing is absent.
    capacity = (soft - (used if used is not None else 64) - 64) // (8 if jump else 4)
    if capacity < 1:
        raise ValueError("insufficient file descriptors for safe SSH execution")
    return int(capacity)


def _profile_memory(options: Options) -> int:
    """Reserve lookup objects plus fourfold UTF-8 metadata expansion.

    Options bounds the same metadata inventory to 4 MiB. A small table keeps
    a 4 MiB floor for resolved Options and dictionaries; a large table retains
    the former 16 MiB maximum instead of charging it for every single profile.
    This remains an admission estimate, not an operating-system memory quota.
    """
    if not options.host_profiles:
        return 0
    metadata = sum(256 + len(profile.hostname.encode('utf-8')) + sum(
        len(value.encode('utf-8')) for value in (
            profile.username or '', profile.known_hosts or '', profile.encoding or '',
            *(profile.client_keys or ()))) for profile in options.host_profiles)
    return max(4 * MIB, 4 * metadata)


def resource_plan(options: Options, *, guarded: bool = False, persistent_master: bool = False) -> ResourcePlan:
    # Allow for SSH buffers, UTF-8 decoding, JSON and queued captured responses.
    # Native workers also own a Python encrypted-byte relay. Multiplexed
    # channels keep this allowance for their one shared master's relay.
    per_worker = (48 if guarded else 8) * MIB + 16 * options.max_output_bytes
    if options.jump_host:
        per_worker += 8 * MIB
    budget = options.memory_budget_mib * MIB
    overhead = (64 * MIB if options.stream_output else 0) + (2 * options.max_stdin_bytes if options.stdin_file else 0)
    overhead += _profile_memory(options)
    # The authenticated master lives alongside the command-channel guardian.
    # Reserve its native process cost even while it is idle between commands.
    overhead += ((32 + (8 if options.jump_host else 0)) * MIB if persistent_master else 0)
    available = _available_memory()
    if available is not None:
        budget = min(budget, available // 10)
    budget -= overhead
    if budget < per_worker:
        raise ValueError(
            "insufficient memory budget for one SSH worker; reduce output capture"
        )
    workers = min(
        options.concurrency,
        256,
        budget // per_worker,
        max(1, _descriptor_workers(options.jump_host is not None) // (2 if guarded else 1)),
    )
    return ResourcePlan(
        options.concurrency, workers, budget, per_worker, options.connect_rate
    )
