"""Live-output wire bounds and failed-writer cleanup are observable."""
import io
import json
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock,Mock,patch

from swassh import Options
from swassh.infrastructure import live_output


class LiveProtocolTests(unittest.TestCase):
    def test_child_protocol_copies_only_complete_bounded_lines(self):
        for data in (b'{"text":"synthetic"}\n',b'x'*16383+b'\n',b''):
            output=io.BytesIO()
            with patch.object(live_output.sys,'stdin',SimpleNamespace(buffer=io.BytesIO(data))),\
                    patch.object(live_output.sys,'stderr',SimpleNamespace(buffer=output)):
                live_output.main()
            self.assertEqual(output.getvalue(),data)
        for data in (b'x'*16384+b'\n',b'incomplete'):
            output=io.BytesIO()
            with patch.object(live_output.sys,'stdin',SimpleNamespace(buffer=io.BytesIO(data))),\
                    patch.object(live_output.sys,'stderr',SimpleNamespace(buffer=output)):
                with self.assertRaisesRegex(ValueError,'protocol budget'):live_output.main()
            self.assertEqual(output.getvalue(),b'')


class LiveCleanupTests(unittest.IsolatedAsyncioTestCase):
    async def test_start_is_idempotent_and_nonzero_writer_exit_is_not_success(self):
        sink = live_output.LiveOutput(Options())
        process = Mock(returncode=None)
        process.stdin.drain = AsyncMock()
        async def wait():
            process.returncode = 7
            return 7
        process.wait = AsyncMock(side_effect=wait)
        with patch.object(live_output, 'launch_native', new_callable=AsyncMock, return_value=process) as launch, \
                patch.object(live_output, 'release_guardian') as release:
            await sink.start()
            await sink.start()
            launch.assert_awaited_once()
            with self.assertRaisesRegex(OSError, 'live output writer failed'):
                await sink.close()
            release.assert_called_once_with(process)
        process.terminate.assert_not_called()
        process.kill.assert_not_called()
        self.assertIsNone(sink.process)

    async def test_unavailable_writer_is_an_error_and_close_without_start_is_idempotent(self):
        sink=live_output.LiveOutput(Options())
        with self.assertRaisesRegex(OSError,'unavailable'):await sink._write({'text':'synthetic'})
        await sink.close();await sink.close()
        sink.process=SimpleNamespace(returncode=1)
        with self.assertRaisesRegex(OSError,'unavailable'):await sink._write({'text':'synthetic'})

    async def test_failed_flush_terminates_kills_reaps_and_releases_guardian(self):
        sink=live_output.LiveOutput(Options())
        process=Mock(returncode=None);process.stdin.drain=AsyncMock()
        process.wait=AsyncMock(side_effect=[TimeoutError,TimeoutError,0]);sink.process=process
        with patch.object(live_output,'release_guardian') as release:
            with self.assertRaises(TimeoutError):await sink.close()
        process.terminate.assert_called_once_with();process.kill.assert_called_once_with()
        self.assertEqual(process.wait.await_count,3);release.assert_called_once_with(process)
        self.assertIsNone(sink.process)
        final=json.loads(process.stdin.write.call_args.args[0])
        self.assertEqual(final,{'event':'stream_finished','dropped_events':0})


if __name__=='__main__':unittest.main()
