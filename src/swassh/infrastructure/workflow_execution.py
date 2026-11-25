"""Strict workflow input, pinned registration and guarded native dispatch."""
from dataclasses import replace
import json
from pathlib import Path

from ..application.options import Options
from ..application.profiles import ProfileResolver
from ..application.workflow_contracts import PreparedWorkflow
from ..domain.workflows import Workflow, WorkflowError
from .bastion import independent_invocation
from .execution_input import InputSnapshot
from .filesystem import private_directory
from .inventory import _unique_object, _invalid_constant
from .scheduled_execution import prepare_invocation


def load_workflow(path):
    """Loading and planning never open state storage or contact a target."""
    try:
        data = InputSnapshot.read(path, 10 * 1024**2)
        return Workflow.from_dict(json.loads(data.decode('utf-8'),
            object_pairs_hook=_unique_object, parse_constant=_invalid_constant))
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise WorkflowError('invalid workflow JSON specification') from None


def prepare_workflow(id, directory, workflow, options=None):
    """Pin executable, credentials, normalized targets and distinct report paths."""
    if not isinstance(workflow, Workflow):
        raise WorkflowError('a Workflow is required')
    options = options if options is not None else Options()
    if not isinstance(options, Options) or options.retries or options.stdin_file or options.pty:
        raise WorkflowError('durable workflows require Options with retries=0, no stdin and no PTY')
    resolver = ProfileResolver(options)
    effective = Workflow(workflow.name, tuple(replace(step, hosts=resolver.targets(step.hosts)) for step in workflow.steps))
    first = effective.ordered_steps[0]
    base = prepare_invocation(id, directory, first.hosts, first.descriptor, options)
    invocations = []
    for step in effective.ordered_steps:
        node = Path(directory).expanduser().absolute() / 'runs' / id / step.id
        pinned = replace(base.options, log_file=base.options.log_file if options.log_file else str(node / 'audit.jsonl'))
        invocations.append(replace(base, hosts=step.hosts, command=step.descriptor,
                                   options=pinned, report_path=str(node / 'report.json')))
    return PreparedWorkflow(effective, tuple(invocations))


class NativeWorkflowExecutor:
    """Reuse the normal resource, canary, trust, output and report boundaries."""

    def __init__(self, swarm_factory, convergence_factory):
        self.swarm_factory, self.convergence_factory = swarm_factory, convergence_factory

    @staticmethod
    def _directory(path):
        node = Path(path).parent
        # Every new descendant receives the same private-directory checks.
        for directory in (node.parent.parent, node.parent, node):
            private_directory(directory, tighten=True)

    async def __call__(self, id, step, invocation):
        self._directory(invocation.report_path)
        with independent_invocation():
            if step.action is not None:
                return await self.convergence_factory(step.action, invocation.options).run_to_file(
                    invocation.hosts, invocation.report_path, invocation.format, spool_dir=invocation.spool_dir)
            return await self.swarm_factory(invocation.options).run_to_file(
                invocation.hosts, invocation.command, invocation.report_path,
                invocation.format, spool_dir=invocation.spool_dir)

    async def reconcile(self, id, step, invocation, report_path):
        """Execute only a separately declared verifier, never an opaque action."""
        if step.verifier is None:
            raise WorkflowError('this opaque command has no read-only reconciliation check; automatic replay is refused')
        self._directory(report_path)
        with independent_invocation():
            if step.action is not None:
                return await self.convergence_factory(step.action, invocation.options).verify_to_file(
                    invocation.hosts, report_path, 'json', spool_dir=invocation.spool_dir)
            return await self.swarm_factory(invocation.options).run_to_file(
                invocation.hosts, step.verifier, report_path, 'json', spool_dir=invocation.spool_dir)
