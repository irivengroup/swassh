"""Conservative prepaid rights inside one shared, fixed-size token bucket."""
from dataclasses import dataclass

from .credit_state import _CreditState
from .bandwidth import ByteWindow,NANOSECOND  # Retain the existing module aliases.


@dataclass(frozen=True,slots=True)
class CreditPool(_CreditState):
    """Unreported rights reduce refill capacity; they never create a new burst.

    ``outstanding`` includes unused rights, in-flight writes and completed
    writes not yet published. Returning only never-issued rights is safe;
    uncertain rights of a dead owner are forfeited without a credit refund.
    """
    rate: int
    credits: int
    observed: int
    outstanding: int=0

    def _spawn(self,*values):
        """Retain the established public CreditPool return type and metadata."""
        return CreditPool(*values)

