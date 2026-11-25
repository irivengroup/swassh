"""Immutable live SSH events; byte fragments do not imply line boundaries."""
from dataclasses import dataclass
from .models import Host


@dataclass(frozen=True, slots=True)
class OutputEvent:
    """A host-scoped start/stdout/stderr event; EOF closes only its stream.

    Data is bounded to 4096 bytes. Keep a bounded incremental decoder when
    interpreting text: UTF-8 characters and prompts may span several events.
    """
    host: Host
    stream: str
    data: bytes = b''
    eof: bool = False
