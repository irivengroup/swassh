"""Measure scheduler throughput with simulated I/O, not real SSH throughput."""

import argparse
import sys
import asyncio
import json
import tempfile
import time
import tracemalloc
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from swassh import Options, Result, Status, Swarm


class SimulatedTransport:
    def __init__(self, delay: float):
        self.delay = delay
        self.active = self.peak = 0

    async def execute(self, host, command):
        self.active += 1
        self.peak = max(self.peak, self.active)
        try:
            await asyncio.sleep(self.delay)
            return Result(host, Status.SUCCESS, stdout="benchmark")
        finally:
            self.active -= 1


async def benchmark(hosts: int, concurrency: int, delay: float) -> dict:
    transport = SimulatedTransport(delay)
    tracemalloc.start()
    started = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="swassh-benchmark-") as directory:
        report = await Swarm(
            Options(concurrency=concurrency), transport=transport
        ).run_to_file(
            (f"host-{i}" for i in range(hosts)),
            "benchmark",
            Path(directory) / "report.csv",
            "csv",
        )
    elapsed = time.perf_counter() - started
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    if not (report.ok and report.total == hosts):
        raise AssertionError()
    if not (transport.peak <= concurrency):
        raise AssertionError()
    return {
        "transport": "simulated",
        "hosts": hosts,
        "concurrency": concurrency,
        "effective_workers": report.plan.workers,
        "peak_concurrency": transport.peak,
        "seconds": elapsed,
        "hosts_per_second": hosts / elapsed,
        "peak_memory_bytes": peak,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--hosts", type=int, default=10000)
    parser.add_argument("--concurrency", type=int, default=100)
    parser.add_argument("--delay", type=float, default=0.001)
    args = parser.parse_args()
    if args.hosts < 1 or args.delay < 0:
        parser.error("hosts must be positive and delay nonnegative")
    print(
        json.dumps(
            asyncio.run(benchmark(args.hosts, args.concurrency, args.delay)), indent=2
        )
    )


if __name__ == "__main__":
    main()
