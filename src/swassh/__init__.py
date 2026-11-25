"""SWASSH stable public API; exports are loaded without coupling the domain."""

from importlib import import_module

__version__ = "2.0.0"

_EXPORTS = {
    "SSHChannel": "interfaces.channels",
    "SSHTunnel": "interfaces.channels",
    "LocalForward": "domain.channels",
    "ChannelCapture": "domain.channels",
    "Workflow": "domain.workflows",
    "WorkflowStep": "domain.workflows",
    "WorkflowState": "domain.workflows",
    "WorkflowError": "domain.workflows",
    "WorkflowRunner": "interfaces.workflows",
    "WorkflowInfo": "application.workflow_contracts",
    "DesiredState": "domain.convergence",
    "ConvergentSwarm": "interfaces.convergence",
    "OutputEvent": "domain.interaction",
    "CommandInput": "infrastructure.interaction",
    "Client": "interfaces.client",
    "AsyncClient": "interfaces.client",
    "ResultStream": "interfaces.client",
    "Transport": "application.ports",
    "CommandError": "domain.errors",
    "ExecutionError": "domain.errors",
    "OutputDecodeError": "domain.errors",
    "NetworkSwarm": "interfaces.network",
    "NetworkProcedure": "domain.network",
    "NetworkStep": "domain.network",
    "ReconnectPolicy": "domain.network",
    "Session": "interfaces.session",
    "Scheduler": "interfaces.scheduling",
    "JobInfo": "domain.scheduling",
    "JobState": "domain.scheduling",
    "ScheduleError": "domain.scheduling",
    "parse_schedule_time": "domain.scheduling",
    "FileSwarm": "interfaces.transfers",
    "push_to_file": "interfaces.transfers",
    "pull_to_file": "interfaces.transfers",
    "FileTransfer": "domain.transfers",
    "TransferDirection": "domain.transfers",
    "TransferReceipt": "domain.models",
    "TransferSettings": "application.transfer_settings",
    "Host": "domain.models",
    "Result": "domain.models",
    "Status": "domain.models",
    "InventoryError": "domain.inventory",
    "normalize_hosts": "domain.inventory",
    "parse_host": "domain.inventory",
    "Options": "application.options",
    "HostProfile": "application.profiles",
    "ResourcePlan": "application.contracts",
    "RunSummary": "application.contracts",
    "Swarm": "interfaces.api",
    "execute": "interfaces.api",
    "execute_to_file": "interfaces.api",
    "load_inventory": "infrastructure.inventory",
    "Report": "infrastructure.report",
}

__all__ = [*_EXPORTS, "__version__"]


def __getattr__(name: str):
    module = _EXPORTS.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module("." + module, __name__), name)
    globals()[name] = value
    return value


def __dir__():
    return sorted(set(globals()) | set(__all__))
