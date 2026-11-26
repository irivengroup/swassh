"""Account guardian admission separately from active SSH time.

The receipt lives beside the private guardian request. Remote output never
participates in clock accounting. Both queue credit and active time are bounded
by the caller's original command timeout. Creating the guardian remains charged;
only its subsequent local admission phase receives a separate finite allowance.
"""
import json
import math
import os
from pathlib import Path


def publish_admission(directory, state, seconds):
    """Atomically replace a small local receipt before launching native SSH."""
    path = Path(directory) / 'admission.json'
    temporary = path.with_suffix('.initializing')
    with temporary.open('x', encoding='ascii') as stream:
        temporary.chmod(0o600)
        import time
        json.dump({'schema_version': 1, 'state': state, 'seconds': seconds,
                   'completed_at': time.monotonic()},
                  stream, allow_nan=False)
    if os.name == 'nt':
        from .windows import replace_atomic_receipt
        replace_atomic_receipt(temporary, path)
    else:
        os.replace(temporary, path)


class AdmissionDeadline:
    """Observe the guardian without granting more active command lifetime."""

    def __init__(self, directory, deadline, budget, started):
        self.path = Path(directory) / 'admission.json'
        self.deadline = deadline
        self.original = deadline.when()
        self.budget = budget
        self.started = started

    def _read(self):
        try:
            if os.name == 'nt':
                from .windows import open_file_without_reparse
                # The guardian replaces this private file atomically. A live
                # reader must permit deletion of the previous complete version,
                # just as POSIX readers do; read rights and link checks remain.
                descriptor = open_file_without_reparse(self.path, os.O_RDONLY, share_delete=True)
                try:
                    stream = os.fdopen(descriptor, 'rb')
                except BaseException:
                    # Ownership transfers only after successful stream creation.
                    os.close(descriptor)
                    raise
            else:
                stream = self.path.open('rb')
            with stream:
                raw = stream.read(1025)
        except FileNotFoundError:
            return None
        try:
            value = json.loads(raw)
            if (len(raw) > 1024 or not isinstance(value, dict)
                    or set(value) != {'schema_version', 'state', 'seconds', 'completed_at'}
                    or type(value['schema_version']) is not int or value['schema_version'] != 1
                    or value['state'] not in ('queued', 'admitted', 'expired')
                    or type(value['seconds']) not in (float, int)
                    or not math.isfinite(value['seconds'])
                    or not 0 <= value['seconds'] <= self.budget
                    or type(value['completed_at']) not in (float, int)
                    or value['completed_at'] < 0
                    or not math.isfinite(value['completed_at'])):
                raise ValueError
        except (ValueError, TypeError, OverflowError):
            raise ValueError('invalid private admission receipt') from None
        return value

    async def observe(self, process):
        """Restore exact local admission credit as soon as it completes or fails."""
        import asyncio
        loop = asyncio.get_running_loop()
        # The real guardian exists before this allowance starts. A stalled
        # create_subprocess_exec never reaches here and keeps the original cap.
        if self.original is not None:
            if loop.time() >= self.original:
                raise TimeoutError('guardian creation deadline exceeded')
            extended = self.original + self.budget
            if not math.isfinite(extended):
                raise ValueError('guardian deadline exceeds supported clock range')
            self.deadline.reschedule(extended)
        while True:
            receipt = self._read()
            if receipt is not None:
                state = receipt['state']
                if state == 'expired':
                    raise TimeoutError('guardian queue deadline exceeded')
                if state == 'admitted':
                    credit = max(0., receipt['completed_at'] - self.started)
                    if credit > self.budget or receipt['completed_at'] > loop.time():
                        raise TimeoutError('guardian admission deadline exceeded')
                    if self.original is not None:
                        end = self.original + credit
                        if loop.time() >= end:
                            raise TimeoutError('active SSH deadline exceeded')
                        self.deadline.reschedule(end)
                    return
            if process.returncode is not None:
                raise ValueError('guardian ended before admission receipt')
            await asyncio.sleep(0.005)
