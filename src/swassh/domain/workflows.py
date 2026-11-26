"""Bounded acyclic dependency plans and durable workflow state metadata."""
from __future__ import annotations

from collections import deque
from dataclasses import asdict, dataclass, field
from enum import StrEnum
import hashlib
import json
import re

from .commands import validate_command
from .convergence import DesiredState
from .inventory import normalize_hosts
from .models import Host

MAX_STEPS = 256
MAX_EDGES = 4096


class WorkflowError(ValueError):
    """A controlled workflow validation or lifecycle error without command text."""


def _identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', value):
        raise WorkflowError('workflow names must contain 1..64 safe identifier characters')
    return value


class WorkflowState(StrEnum):
    PENDING = 'pending'
    RUNNING = 'running'
    SUCCEEDED = 'succeeded'
    FAILED = 'failed'
    BLOCKED = 'blocked'
    INTERRUPTED = 'interrupted'
    CANCELLED = 'cancelled'


@dataclass(frozen=True, slots=True)
class WorkflowStep:
    """One fleet command or DesiredState, gated by named successful predecessors.

    ``reconcile_check`` is an optional trusted read-only check for an interrupted
    opaque command. It is never the interrupted command itself and never grants
    permission to replay it. DesiredState uses its own verification command.
    """

    id: str
    hosts: tuple[Host | str, ...]
    command: str | None = field(default=None, repr=False)
    action: DesiredState | None = field(default=None, repr=False)
    needs: tuple[str, ...] = ()
    reconcile_check: str | None = field(default=None, repr=False)

    def __post_init__(self):
        _identifier(self.id)
        if not isinstance(self.hosts, tuple) or not 1 <= len(self.hosts) <= 100000:
            raise WorkflowError('each workflow step needs a tuple of 1..100000 targets')
        try:
            object.__setattr__(self, 'hosts', normalize_hosts(self.hosts))
        except ValueError:
            raise WorkflowError('invalid workflow target inventory') from None
        if (self.command is None) == (self.action is None):
            raise WorkflowError('choose exactly one opaque command or DesiredState per step')
        if self.command is not None:
            validate_command(self.command)
        if self.action is not None and not isinstance(self.action, DesiredState):
            raise WorkflowError('workflow action must be a DesiredState')
        if not isinstance(self.needs, tuple) or len(self.needs) > MAX_STEPS:
            raise WorkflowError('workflow dependencies must be a bounded tuple')
        for dependency in self.needs:
            _identifier(dependency)
        if len(set(self.needs)) != len(self.needs) or self.id in self.needs:
            raise WorkflowError('duplicate or self-dependent workflow edge')
        if self.reconcile_check is not None:
            validate_command(self.reconcile_check)
            if self.action is not None or self.reconcile_check == self.command:
                raise WorkflowError('use a separate read-only reconciliation check for an opaque command')

    @property
    def descriptor(self):
        return self.action.descriptor if self.action is not None else self.command

    @property
    def verifier(self):
        return self.action.verification if self.action is not None else self.reconcile_check

    def to_dict(self):
        return {'id': self.id, 'hosts': [asdict(host) for host in self.hosts],
                'command': self.command, 'action': self.action.to_dict() if self.action else None,
                'needs': list(self.needs), 'reconcile_check': self.reconcile_check}

    @classmethod
    def from_dict(cls, value):
        if (not isinstance(value, dict) or not {'id', 'hosts'} <= set(value)
                or set(value) - {'id', 'hosts', 'command', 'action', 'needs', 'reconcile_check'}
                or not isinstance(value['hosts'], list) or not isinstance(value.get('needs', []), list)):
            raise WorkflowError('invalid workflow step schema')
        hosts = []
        if not 1 <= len(value['hosts']) <= 100000:
            raise WorkflowError('invalid workflow target count')
        for host in value['hosts']:
            if isinstance(host, dict):
                if 'hostname' not in host or set(host) - set(Host.__dataclass_fields__):
                    raise WorkflowError('invalid workflow host schema')
                host = Host(**host)
            hosts.append(host)
        return cls(value['id'], tuple(hosts), value.get('command'),
                   DesiredState.from_dict(value['action']) if value.get('action') is not None else None,
                   tuple(value.get('needs', [])), value.get('reconcile_check'))


@dataclass(frozen=True, slots=True)
class Workflow:
    """At most 256 steps, 4096 edges and 100000 total step-target records."""

    name: str
    steps: tuple[WorkflowStep, ...]
    _order: tuple[str, ...] = field(init=False, repr=False)
    _digest: str = field(init=False, repr=False)

    def __post_init__(self):
        _identifier(self.name)
        if (not isinstance(self.steps, tuple) or not 1 <= len(self.steps) <= MAX_STEPS
                or any(not isinstance(step, WorkflowStep) for step in self.steps)):
            raise WorkflowError('workflow requires 1..256 immutable steps')
        by_id = {step.id: step for step in self.steps}
        if len(by_id) != len(self.steps):
            raise WorkflowError('workflow step identifiers must be unique')
        if sum(len(step.hosts) for step in self.steps) > 100000 or sum(len(step.needs) for step in self.steps) > MAX_EDGES:
            raise WorkflowError('workflow target or dependency budget exceeded')
        if any(dependency not in by_id for step in self.steps for dependency in step.needs):
            raise WorkflowError('workflow dependency does not exist')
        remaining = {step.id: len(step.needs) for step in self.steps}
        followers = {step.id: [] for step in self.steps}
        for step in self.steps:
            for dependency in step.needs:
                followers[dependency].append(step.id)
        ready = deque(name for name, count in remaining.items() if not count)
        order = []
        while ready:
            name = ready.popleft()
            order.append(name)
            for follower in followers[name]:
                remaining[follower] -= 1
                if remaining[follower] == 0:
                    ready.append(follower)
        if len(order) != len(self.steps):
            raise WorkflowError('cyclic workflow dependencies are forbidden')
        object.__setattr__(self, '_order', tuple(order))
        serialized = json.dumps(self.to_dict(), sort_keys=True, ensure_ascii=True, separators=(',', ':'))
        object.__setattr__(self, '_digest', hashlib.sha256(serialized.encode()).hexdigest())

    @property
    def ordered_steps(self):
        by_id = {step.id: step for step in self.steps}
        return tuple(by_id[name] for name in self._order)

    @property
    def digest(self):
        return self._digest

    def to_dict(self):
        return {'schema_version': 1, 'name': self.name, 'steps': [step.to_dict() for step in self.steps]}

    @classmethod
    def from_dict(cls, value):
        if (not isinstance(value, dict) or set(value) != {'schema_version', 'name', 'steps'}
                or type(value['schema_version']) is not int or value['schema_version'] != 1
                or not isinstance(value['steps'], list) or not 1 <= len(value['steps']) <= MAX_STEPS):
            raise WorkflowError('unsupported workflow specification')
        return cls(value['name'], tuple(WorkflowStep.from_dict(step) for step in value['steps']))
