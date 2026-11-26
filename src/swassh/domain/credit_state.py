"""Lightweight immutable credit arithmetic shared with the public dataclasses.

The native guardian imports this module without constructing dataclass/type
metadata. Public ByteWindow/CreditPool retain their established representations.
"""
NANOSECOND=1000000000


def _validate_window(rate,credits,observed):
    """Apply the same bounded integer invariants without a temporary window."""
    if type(rate) is not int or not 1024<=rate<=2147483647*1024:
        raise ValueError('invalid encrypted-byte rate')
    if (type(credits) is not int or not 0<=credits<=min(16384,rate)*NANOSECOND
            or type(observed) is not int or not 0<=observed<2**63):
        raise ValueError('invalid encrypted-byte window counters')


class _CreditState:
    """Validated prepaid rights; methods preserve the concrete caller's type."""
    __slots__=('rate','credits','observed','outstanding')

    def __init__(self,rate,credits,observed,outstanding=0):
        object.__setattr__(self,'rate',rate)
        object.__setattr__(self,'credits',credits)
        object.__setattr__(self,'observed',observed)
        object.__setattr__(self,'outstanding',outstanding)
        self.__post_init__()

    def __setattr__(self,name,value):
        raise AttributeError('encrypted-byte credit state is immutable')

    def __delattr__(self,name):
        raise AttributeError('encrypted-byte credit state is immutable')

    def _spawn(self,*values):
        """Construct a fresh validated internal state, never mutate this one."""
        return _CreditState(*values)

    def __post_init__(self):
        _validate_window(self.rate,self.credits,self.observed)
        if (type(self.outstanding) is not int or not 0<=self.outstanding<=self.burst
                or self.credits+self.outstanding*NANOSECOND>self.burst*NANOSECOND):
            raise ValueError('invalid outstanding encrypted-byte rights')

    @property
    def burst(self):
        return min(16384,self.rate)

    def refill(self,now):
        """Refill under the old outstanding ceiling, including before recovery."""
        if type(now) is not int or not 0<=now<2**63:
            raise ValueError('invalid encrypted-byte clock sample')
        credits=0 if now<self.observed else min((self.burst-self.outstanding)*NANOSECOND,
                                               self.credits+(now-self.observed)*self.rate)
        return self._spawn(self.rate,credits,now,self.outstanding)

    def settle(self,*,consumed=0,returned=0,granted=0):
        """Publish completed/forfeited rights and optionally issue durable rights.

        Call refill first. Consumption frees capacity without adding credits.
        Only never-issued returned bytes add their original prepaid credits.
        """
        if (any(type(value) is not int or value<0 for value in (consumed,returned,granted))
                or consumed+returned>self.outstanding
                or granted*NANOSECOND>self.credits+returned*NANOSECOND):
            raise ValueError('invalid encrypted-byte credit settlement')
        return self._spawn(self.rate,self.credits+(returned-granted)*NANOSECOND,self.observed,
                          self.outstanding-consumed-returned+granted)

    def debit(self,count):
        """Charge an immediate chunk without reserving future rights."""
        if type(count) is not int or not 1<=count<=self.burst:
            raise ValueError('invalid encrypted-byte chunk size')
        wait=max(0,(count*NANOSECOND-self.credits+self.rate-1)//self.rate)
        if count>self.burst-self.outstanding:
            wait=max(wait,NANOSECOND//100)
        credits=self.credits if wait else self.credits-count*NANOSECOND
        return self._spawn(self.rate,credits,self.observed,self.outstanding),wait
