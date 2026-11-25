"""Opt-in application errors retaining structured outcomes, never output in messages."""
from __future__ import annotations


class InventoryError(ValueError):
    """An invalid or ambiguous inventory."""


InventoryError.__module__='swassh.domain.inventory'

class CommandError(RuntimeError):
    """A host did not succeed; inspect ``result`` for the bounded full outcome."""
    def __init__(self, result):
        self.result = result
        super().__init__(f'SSH command did not succeed: {result.status.value}')


class ExecutionError(RuntimeError):
    """A completed fleet report contains failures or skipped hosts."""
    def __init__(self, report):
        self.report = report
        count = sum(not result.ok for result in report.results)
        super().__init__(f'SSH execution did not succeed on {count} of {len(report.results)} hosts')


class OutputDecodeError(ValueError):
    """Successful output is truncated or is not strict JSON; inspect ``result``."""
    def __init__(self, result):
        self.result = result
        super().__init__('remote output is truncated or is not valid strict JSON')
