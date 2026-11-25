"""Composition root: concrete system adapters are wired only at this boundary."""

from dataclasses import dataclass

from .application.options import Options
from .application.ports import (
    AuditFactory,
    InvocationFactory,
    ProgressSink,
    ReporterFactory,
    ReportFactory,
    ResourcePlanner,
    Transport,
    TransportFactory,
)
from .infrastructure.audit import AuditTrail
from .infrastructure.process_reporter import ProcessReportWriter
from .infrastructure.report import Report
from .infrastructure.resources import resource_plan
from .infrastructure.ssh import SSHTransport
from .infrastructure.native_budget import native_invocation_budget as invocation_budget
from .infrastructure.progress import progress


@dataclass(frozen=True, slots=True)
class Dependencies:
    transport_factory: TransportFactory
    audit_factory: AuditFactory
    planner: ResourcePlanner
    reporter_factory: ReporterFactory
    report_factory: ReportFactory
    invocation_factory: InvocationFactory | None = None
    progress_sink: ProgressSink | None = None


def dependencies(transport: Transport | None = None, *, options: Options | None = None,
                 transport_factory: TransportFactory | None = None) -> Dependencies:
    if transport is not None and transport_factory is not None:
        raise ValueError('choose transport or transport_factory, not both')
    if transport_factory is not None and not callable(transport_factory):
        raise TypeError('transport_factory must be callable')
    adapter = transport_factory if transport_factory is not None else transport
    guarded = adapter is None or getattr(adapter, '_native_guarded', False)
    return Dependencies(
        transport_factory if transport_factory is not None else (SSHTransport if transport is None else lambda _: transport),
        AuditTrail,
        lambda settings: resource_plan(settings, guarded=guarded,
            persistent_master=getattr(adapter, '_persistent_master', False)),
        ProcessReportWriter if options is None else lambda directory, budget: ProcessReportWriter(
            directory, budget, operation_timeout=options.report_timeout, options=options if guarded else None),
        Report,
        invocation_budget if guarded else None,
        progress,
    )


def file_transport_factory():
    from .infrastructure.transfers import NativeFileTransport
    return NativeFileTransport


def scheduler_dependencies(state_dir):
    from .application.swarm import Swarm as ExecutionService
    from .infrastructure.schedule_store import SQLiteScheduleStore
    from .infrastructure.scheduled_execution import SwarmScheduledExecutor

    store = SQLiteScheduleStore(state_dir)
    def swarm_factory(options):
        runtime = dependencies(options=options)
        return ExecutionService(options, transport_factory=runtime.transport_factory,
            audit_factory=runtime.audit_factory, planner=runtime.planner,
            reporter_factory=runtime.reporter_factory, report_factory=runtime.report_factory,
            invocation_factory=runtime.invocation_factory, progress_sink=runtime.progress_sink)
    return store, SwarmScheduledExecutor(store.directory, swarm_factory), AuditTrail


def workflow_dependencies(state_dir):
    from .application.swarm import Swarm as ExecutionService
    from .infrastructure.workflow_store import SQLiteWorkflowStore
    from .infrastructure.workflow_execution import NativeWorkflowExecutor
    def swarm_factory(options):
        runtime = dependencies(options=options)
        return ExecutionService(options, transport_factory=runtime.transport_factory,
            audit_factory=runtime.audit_factory, planner=runtime.planner,
            reporter_factory=runtime.reporter_factory, report_factory=runtime.report_factory,
            invocation_factory=runtime.invocation_factory, progress_sink=runtime.progress_sink)
    def convergence_factory(action, options):
        # Keep the infrastructure adapter independent of interface imports.
        class DesiredFleet:
            async def run_to_file(self, hosts, path, format, *, spool_dir=None):
                return await execute(False, hosts, path, format, spool_dir)
            async def verify_to_file(self, hosts, path, format, *, spool_dir=None):
                return await execute(True, hosts, path, format, spool_dir)
        async def execute(verify, hosts, path, format, spool):
            factory = ConvergenceFactory(action, verify_only=verify)
            runtime = dependencies(options=options, transport_factory=factory)
            service = ExecutionService(options, transport_factory=factory,
                audit_factory=runtime.audit_factory, planner=runtime.planner,
                reporter_factory=runtime.reporter_factory, report_factory=runtime.report_factory,
                invocation_factory=runtime.invocation_factory, progress_sink=runtime.progress_sink)
            return await service.run_to_file(hosts, action.descriptor, path, format, spool_dir=spool)
        return DesiredFleet()
    store = SQLiteWorkflowStore(state_dir)
    return store, NativeWorkflowExecutor(swarm_factory, convergence_factory), AuditTrail


class InteractionFactory:
    """Native interactive transport preserving planner and admission guards."""
    _native_guarded = True

    def __init__(self, handler_factory):
        if not callable(handler_factory):
            raise TypeError('handler_factory must be callable')
        self.handler_factory = handler_factory

    def __call__(self, options):
        return SSHTransport(options, interaction_factory=self.handler_factory)


class ConvergenceFactory:
    """Compose durable desired-state guards with the selected trusted transport."""

    def __init__(self, action, transport_factory=None, journal_factory=None, *, verify_only=False):
        self.action = action
        self.transport_factory = SSHTransport if transport_factory is None else transport_factory
        self.journal_factory = journal_factory
        self.verify_only = verify_only
        self._native_guarded = transport_factory is None or getattr(transport_factory, '_native_guarded', False)

    def __call__(self, options):
        from .application.convergence import ConvergentTransport
        from .infrastructure.convergence import SQLiteConvergenceJournal
        journal_factory = SQLiteConvergenceJournal if self.journal_factory is None else self.journal_factory
        journal = journal_factory(options)
        return ConvergentTransport(self.transport_factory(options), self.action, journal,
                                   verify_only=self.verify_only)
