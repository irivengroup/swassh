"""Pacing protects elapsed intervals even when the event-loop clock jumps."""
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch

from swassh.application import pacing


class PacingClockTests(unittest.IsolatedAsyncioTestCase):
    async def test_coarse_loop_tick_cannot_admit_before_elapsed_interval(self):
        # GetTickCount64 can jump a whole tick while only four milliseconds
        # elapsed. Admission must still wait the remaining six milliseconds.
        clock = Mock(side_effect=[0.0, 0.0, 0.0, 0.0, 0.004, 0.01, 0.01])
        real_loop = pacing.asyncio.get_running_loop()
        # Keep the coarse timer independent, while modeling a real loop's queue.
        loop = SimpleNamespace(time=Mock(side_effect=[0.0, 0.0, 0.0, 0.015625, 0.015625]),
                               call_soon=real_loop.call_soon)
        sleeper = AsyncMock()
        pacer = pacing.ConnectionPacer(100)
        with patch.object(pacing, 'time', SimpleNamespace(perf_counter=clock), create=True), \
                patch.object(pacing.asyncio, 'get_running_loop', return_value=loop), \
                patch.object(pacing.asyncio, 'sleep', sleeper):
            await pacer.acquire()
            await pacer.acquire()
        self.assertEqual(sleeper.await_count, 2)
        self.assertAlmostEqual(sleeper.await_args_list[0].args[0], .01)
        self.assertAlmostEqual(sleeper.await_args_list[1].args[0], .006)
        self.assertAlmostEqual(pacer._next, .02)
        loop.time.assert_not_called()


if __name__ == '__main__':
    unittest.main()
