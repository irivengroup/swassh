"""Integer token accounting for a shared bidirectional encrypted-byte budget."""
from dataclasses import dataclass
from .credit_state import NANOSECOND,_validate_window


@dataclass(frozen=True,slots=True)
class ByteWindow:
    """One global burst, with no reservation of future capacity by dead clients."""
    rate: int
    credits: int
    observed: int

    @property
    def chunk_size(self):
        return min(16384,self.rate)

    def __post_init__(self):
        _validate_window(self.rate,self.credits,self.observed)

    def reserve(self,count,now):
        """Return a new window and a wait in nanoseconds; zero means admitted.

        Clock regression resets credits to zero, never to a free burst. A
        rejected attempt accrues only real elapsed time; it reserves no debt.
        """
        if type(count) is not int or not 1 <= count <= self.chunk_size:
            raise ValueError('invalid encrypted-byte chunk size')
        if type(now) is not int or not 0 <= now < 2**63:
            raise ValueError('invalid encrypted-byte clock sample')
        credits=(0 if now < self.observed else
                 min(self.chunk_size*NANOSECOND,self.credits+(now-self.observed)*self.rate))
        required=count*NANOSECOND
        wait=max(0,(required-credits+self.rate-1)//self.rate)
        return ByteWindow(self.rate,credits-required if not wait else credits,now),wait
