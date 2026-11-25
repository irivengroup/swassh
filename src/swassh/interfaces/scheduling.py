"""Public scheduling API and compact CLI operations."""
from __future__ import annotations

import asyncio
import csv
import io
import json
import signal
import uuid
from datetime import UTC, datetime
from pathlib import Path

from ..application.scheduling import SchedulingService
from ..bootstrap import scheduler_dependencies
from ..domain.scheduling import ScheduleError, parse_schedule_time
from ..infrastructure.report import safe_text, _csv_safe
from ..infrastructure.resources import resource_plan
from ..infrastructure.schedule_store import default_schedule_directory
from ..infrastructure.scheduled_execution import prepare_invocation


class Scheduler(SchedulingService):
    def __init__(self, state_dir=None):
        store, executor, audit_factory = scheduler_dependencies(
            state_dir if state_dir is not None else default_schedule_directory())
        super().__init__(store, executor, audit_factory=audit_factory,
                         audit_path=str(store.directory / 'scheduler.jsonl'))
        self.state_dir = store.directory

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.store.close()

    def schedule(self, hosts, command, at, *, timezone=None, fold=None, options=None,
                 report_path=None, format='json', spool_dir=None, misfire_grace=300):
        due = parse_schedule_time(at, timezone, fold)
        now = datetime.now(UTC)
        if due <= now:
            raise ScheduleError('scheduled date and time must be in the future')
        id = uuid.uuid4().hex
        invocation = prepare_invocation(id, self.state_dir, hosts, command, options,
            report_path=report_path, format=format, spool_dir=spool_dir)
        resource_plan(invocation.options)
        return self.store.create(id, invocation, due, now, misfire_grace)


def render_jobs(jobs, format='text'):
    values = [job.to_dict() for job in jobs]
    if format == 'json':
        return json.dumps(values, ensure_ascii=False, indent=2) + '\n'
    if format == 'csv':
        fields = ['id', 'state', 'due_at', 'host_count', 'canary', 'report_path', 'reason']
        output = io.StringIO(newline='')
        writer = csv.DictWriter(output, fields)
        writer.writeheader()
        writer.writerows({field: _csv_safe(row[field]) for field in fields} for row in values)
        return output.getvalue()
    lines = ['JOB ID                            STATE         DUE (UTC)                     HOSTS CANARY']
    for job in jobs:
        lines.append(f'{job.id}  {job.state.value:<12}  {job.due_at.isoformat(timespec="seconds"):<28}  {job.host_count:>5} {min(job.canary, job.host_count):>6}')
    if not jobs:
        lines.append('No scheduled jobs.')
    return safe_text('\n'.join(lines)) + '\n'


async def run_worker(scheduler, *, once, poll_interval):
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    installed = []
    for number in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(number, stop.set)
            installed.append(number)
        except (NotImplementedError, RuntimeError):
            pass
    try:
        return await scheduler.serve(once=once, stop_event=stop, poll_interval=poll_interval)
    finally:
        for number in installed:
            loop.remove_signal_handler(number)
