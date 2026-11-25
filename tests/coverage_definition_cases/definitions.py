"""Typed declarations and actual implementations are deliberately different."""
from typing import Protocol


class Contract(Protocol):
    def required(self) -> int: ...

    def provided(self) -> int:
        return 7


class Concrete(Contract):
    def required(self) -> int:
        return 9
