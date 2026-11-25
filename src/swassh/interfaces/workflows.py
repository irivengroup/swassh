"""Public persistent workflows, explicit recovery and local plan rendering."""
from __future__ import annotations

import json
import asyncio
import sys
from datetime import UTC, datetime
from dataclasses import replace
from pathlib import Path
import uuid

from ..application.workflows import WorkflowService
from ..application.options import Options
from ..application.profiles import ProfileResolver
from ..bootstrap import workflow_dependencies
from ..domain.workflows import Workflow, WorkflowError
from ..infrastructure.audit import default_log_path
from ..infrastructure.resources import resource_plan
from ..infrastructure.workflow_execution import load_workflow, prepare_workflow


class WorkflowRunner(WorkflowService):
    """A local serial worker with durable per-step checkpoints and no replay.

    Registration snapshots trusted commands and options in private local storage.
    Keep that directory on reliable local storage under the worker's OS account.
    A failed/interrupted action must be verified before explicit ``resume``.
    """

    def __init__(self, state_dir=None):
        directory = state_dir if state_dir is not None else default_log_path().parent / 'workflows'
        store, executor, audit_factory = workflow_dependencies(directory)
        super().__init__(store, executor, audit_factory=audit_factory,
                         audit_path=str(store.directory / 'workflow.jsonl'))
        self.state_dir = store.directory

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.store.close()

    @staticmethod
    def load(path):
        return load_workflow(path)

    @staticmethod
    def plan(workflow, options=None):
        """No credentials, executable, database or network required for planning."""
        if not isinstance(workflow, Workflow):
            raise WorkflowError('a Workflow is required')
        options = options if options is not None else Options()
        if not isinstance(options,Options):
            raise TypeError('options must be Options')
        if options.retries or options.stdin_file or options.pty:
            raise WorkflowError('durable workflows require retries=0, no stdin and no PTY')
        resolver=ProfileResolver(options)
        workflow=Workflow(workflow.name,tuple(replace(step,hosts=resolver.targets(step.hosts)) for step in workflow.steps))
        return {'name': workflow.name, 'definition_sha256': workflow.digest,
                'steps': [{'id': step.id, 'host_count': len(step.hosts), 'needs': list(step.needs),
                           'operation': 'converge' if step.action else 'command',
                           'reconcilable': step.verifier is not None} for step in workflow.ordered_steps],
                'resource_plan_per_step': resource_plan(options,guarded=True).to_dict(),
                'fleet_dispatch': 'sequential', 'automatic_replay': False}

    def register(self, workflow, options=None):
        id = uuid.uuid4().hex
        prepared = prepare_workflow(id, self.state_dir, workflow, options)
        resource_plan(prepared.invocations[0].options,guarded=True)
        return self.store.create(id, prepared, datetime.now(UTC))

    def resume(self, id):
        """Admit only verified dependencies; successful steps remain terminal."""
        with self.store.worker_lock():
            return self.store.resume(id, datetime.now(UTC))

    def purge(self, id):
        """Delete terminal metadata explicitly, retaining reports and audit events."""
        with self.store.worker_lock():
            return self.store.purge(id, datetime.now(UTC))

    async def reconcile(self, id, step_id):
        """Check the postcondition in a new report without replacing evidence."""
        with self.store.worker_lock():
            prepared = await self._io(self.store.definition, id)
            step = next((item for item in prepared.workflow.steps if item.id == step_id), None)
            if step is None or step.verifier is None:
                raise WorkflowError('a declared read-only verifier is required for this step')
            invocation = prepared.invocation(step_id)
            attempt = await self._io(self.store.prepare_reconciliation, id, step_id, self.clock())
            await self._flush_events()
            path = str(Path(invocation.report_path).with_name('reconcile-' + str(attempt) + '.json'))
            summary = await self.executor.reconcile(id, step, invocation, path)
            await self._io(self.store.reconcile, id, step_id, self.clock(), summary)
            await self._flush_events()
            return await self._io(self.store.get, id)


def render_workflows(values):
    """JSON metadata intentionally omits command text and target inventories."""
    return json.dumps([value.to_dict() for value in values], ensure_ascii=True, indent=2) + '\n'


def workflow_management(args, argv):
    """Reject ignored safety options before opening a worker's persisted state."""
    flags = {token.split('=', 1)[0] for token in argv[1:] if token.startswith('-')}
    management = args.list or args.show or args.cancel or args.purge or args.worker or args.resume or args.reconcile
    if not management:
        if not args.workflow_file:
            raise WorkflowError('registration requires --workflow-file')
        if args.hosts or args.inventory or args.output or args.spool_dir:
            raise WorkflowError('workflow targets come from its specification; reports use private per-step paths')
        if flags & {'--step', '--once', '--poll-interval', '--limit', '--offset'}:
            raise WorkflowError('management options cannot be used when registering a workflow')
        return None
    allowed = {'--state-dir','--format','--list','--show','--cancel','--purge','--worker',
               '--resume','--reconcile','--step','--limit','--offset','--once','--poll-interval'}
    if flags - allowed:
        raise WorkflowError('management actions cannot include inventories or execution options')
    if not args.worker and flags & {'--once', '--poll-interval'}:
        raise WorkflowError('--once and --poll-interval require --worker')
    if not args.list and flags & {'--limit', '--offset'}:
        raise WorkflowError('--limit and --offset require --list')
    if bool(args.reconcile) != bool(args.step):
        raise WorkflowError('--reconcile requires --step, which is unavailable for other actions')
    with WorkflowRunner(args.state_dir) as runner:
        if args.worker:
            from .scheduling import run_worker
            asyncio.run(run_worker(runner, once=args.once, poll_interval=args.poll_interval))
            return 0
        if args.list:
            values = runner.store.list(args.limit, args.offset)
        elif args.show:
            values = [runner.store.get(args.show)]
        elif args.cancel:
            values = [runner.store.cancel(args.cancel, datetime.now(UTC))]
        elif args.resume:
            values = [runner.resume(args.resume)]
        elif args.reconcile:
            values = [asyncio.run(runner.reconcile(args.reconcile, args.step))]
        else:
            runner.purge(args.purge)
            values = []
        sys.stdout.write(render_workflows(values))
        return 0
