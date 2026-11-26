"""Structured local checks; no remote authentication guarantee is implied."""
from dataclasses import asdict, dataclass


@dataclass(frozen=True, slots=True)
class CheckIssue:
    """Stable local condition code, severity and non-sensitive explanation."""
    code: str
    level: str
    message: str


@dataclass(frozen=True, slots=True)
class CheckReport:
    """Immutable observations; success does not imply remote readiness."""
    issues: tuple[CheckIssue, ...]

    @property
    def ok(self):
        """Whether no fatal local condition was observed."""
        return not any(issue.level == 'error' for issue in self.issues)

    def to_dict(self):
        """Return the public local-only diagnostic representation."""
        return {'ok': self.ok, 'scope': 'local_only',
                'checks': [asdict(issue) for issue in self.issues]}


class PreflightError(ValueError):
    """Carry controlled messages instead of exposing filesystem exceptions."""
    def __init__(self, report):
        self.report = report
        super().__init__('local prerequisite check failed')
