"""Streaming rsync itemisation: constant memory, no remote filenames displayed."""
from .ssh import _Buffer


class PreviewBuffer(_Buffer):
    def __init__(self, maximum):
        super().__init__(maximum)
        self.added = self.changed = self.deleted = 0
        self.pending = b''
        self.invalid = False

    async def consume(self, stream):
        while chunk := await stream.read(65536):
            # Itemisations are fixed-size records; overflow is rejected rather
            # than retaining arbitrary native output or silently undercounting.
            for piece in chunk.splitlines(keepends=True):
                self.pending += piece
                if len(self.pending) > 128:
                    self.invalid = True
                    self.pending = b''
                elif self.pending.endswith(b'\n'):
                    self._line(self.pending.rstrip(b'\r\n'))
                    self.pending = b''
        if self.pending:
            self._line(self.pending)
        self.pending = b''

    def _line(self, line):
        if line == b'SWASSH:*deleting  ':
            self.deleted += 1
        elif line.startswith(b'SWASSH:') and len(line) == 18:
            item = line[7:]
            if item[0:1] not in (b'<', b'>', b'c', b'h', b'.') or item[1:2] not in (b'f', b'd', b'L', b'D', b'S'):
                self.invalid = True
            elif item[2:] == b'+++++++++':
                self.added += 1
            elif item != b'.f.........' and item != b'.d.........':
                self.changed += 1
        elif line.strip():
            # --quiet + fixed out-format should leave only itemisation records.
            self.invalid = True

    @property
    def text(self):
        return f'preview only: added={self.added} changed={self.changed} deleted={self.deleted}'
