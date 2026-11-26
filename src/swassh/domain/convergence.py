"""Explicit desired-state checks and opaque actions; no inferred shell semantics."""
from dataclasses import dataclass, field
import hashlib
import json
import re

from .commands import validate_command


@dataclass(frozen=True, slots=True)
class DesiredState:
    """A trusted read-only check, action and read-only postcondition.

    Check exit 0 means desired state; exit 1 means action needed. Every other
    outcome blocks mutation. A successful action must pass verification (exit
    0). The operator owns the truth and side-effect freedom of the probes.
    Commands are excluded from repr; the descriptor binds all three commands.
    """

    name: str
    check: str = field(repr=False)
    apply: str = field(repr=False)
    verify: str | None = field(default=None, repr=False)
    _digest: str = field(init=False, repr=False)

    def __post_init__(self):
        if not isinstance(self.name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', self.name):
            raise ValueError('desired-state name must contain 1..64 safe identifier characters')
        for command in (self.check, self.apply, self.verify if self.verify is not None else self.check):
            validate_command(command)
        payload = json.dumps(self.to_dict(), sort_keys=True, ensure_ascii=True, separators=(',', ':'))
        object.__setattr__(self, '_digest', hashlib.sha256(payload.encode()).hexdigest())

    @property
    def verification(self) -> str:
        """Use the check as postcondition unless an explicit verifier is supplied."""
        return self.verify if self.verify is not None else self.check

    @property
    def descriptor(self) -> str:
        """A nonsecret report/audit identifier, never a command to execute."""
        return 'converge:' + self.name + ':' + self._digest

    @property
    def digest(self) -> str:
        return self._digest

    def to_dict(self) -> dict:
        """Serialize the trusted specification, which may contain sensitive code."""
        return {'schema_version': 1, 'name': self.name, 'check': self.check,
                'apply': self.apply, 'verify': self.verify}

    @classmethod
    def from_dict(cls, value):
        """Reject unknown fields and ambiguous versions before any remote I/O."""
        if (not isinstance(value, dict) or set(value) - {'schema_version', 'name', 'check', 'apply', 'verify'}
                or not {'schema_version', 'name', 'check', 'apply'} <= set(value)
                or type(value['schema_version']) is not int or value['schema_version'] != 1):
            raise ValueError('unsupported desired-state specification')
        return cls(value['name'], value['check'], value['apply'], value.get('verify'))
