"""Native staging waits only for bounded Win32 sharing-handle teardown."""
import asyncio
import os
from pathlib import Path
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

from swassh.infrastructure import lifecycle


def sharing_error(code):
    error=PermissionError('synthetic file sharing violation');error.winerror=code;return error


class StagingLifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def test_missing_windows_proactor_is_refused_before_native_creation(self):
        platform = SimpleNamespace(platform='win32')
        with patch.object(lifecycle, 'sys', platform), \
                patch.object(lifecycle.asyncio, 'ProactorEventLoop', None, create=True):
            with self.assertRaisesRegex(ValueError, 'default ProactorEventLoop'):
                lifecycle.ensure_subprocess_loop()

    def staging(self, cleanup):
        directory=SimpleNamespace(name='synthetic-private-directory',cleanup=cleanup)
        with patch.object(lifecycle.tempfile,'TemporaryDirectory',return_value=directory):
            return lifecycle.NativeStagingDirectory(prefix='synthetic-')

    async def test_only_windows_sharing_violations_are_retried(self):
        for code in (32,33):
            cleanup=Mock(side_effect=[sharing_error(code),sharing_error(code),None])
            staging=self.staging(cleanup)
            with patch.object(lifecycle,'os',SimpleNamespace(name='nt')):
                async with staging as path:self.assertEqual(path,'synthetic-private-directory')
            self.assertEqual(cleanup.call_count,3)
        for platform,error in (('nt',sharing_error(5)),('posix',sharing_error(32)),('nt',OSError('synthetic disk fault'))):
            cleanup=Mock(side_effect=error);staging=self.staging(cleanup)
            with patch.object(lifecycle,'os',SimpleNamespace(name=platform)):
                with self.assertRaises(type(error)) as observed:await staging.__aexit__(None,None,None)
            self.assertIs(observed.exception,error);self.assertEqual(cleanup.call_count,1)

    async def test_persistent_file_lock_remains_a_failure_after_the_retry_deadline(self):
        error=sharing_error(32);cleanup=Mock(side_effect=error);staging=self.staging(cleanup)
        start=time.monotonic()
        with patch.object(lifecycle,'os',SimpleNamespace(name='nt')):
            with self.assertRaises(PermissionError) as observed:await staging.__aexit__(None,None,None)
        self.assertIs(observed.exception,error)
        self.assertGreaterEqual(time.monotonic()-start,1.9)
        self.assertLess(time.monotonic()-start,3)
        self.assertGreater(cleanup.call_count,1)

    async def test_repeated_caller_cancellation_waits_for_the_single_cleanup_thread(self):
        entered,release=threading.Event(),threading.Event();finished=[]
        def cleanup():
            entered.set()
            if not release.wait(3):raise TimeoutError('synthetic test release was not delivered')
            finished.append(True)
        staging=self.staging(cleanup)
        task=asyncio.create_task(staging.__aexit__(None,None,None))
        try:
            self.assertTrue(await asyncio.to_thread(entered.wait,3))
            task.cancel();await asyncio.sleep(0);task.cancel();await asyncio.sleep(0)
            self.assertFalse(task.done());self.assertEqual(finished,[])
            release.set()
            with self.assertRaises(asyncio.CancelledError):await task
            self.assertEqual(finished,[True])
        finally:
            release.set();await asyncio.gather(task,return_exceptions=True)

    @unittest.skipUnless(os.name=='nt','native Windows sharing semantics required')
    async def test_real_win32_diagnostic_handle_is_closed_before_directory_removal(self):
        from swassh.infrastructure.windows import open_file_without_reparse
        # Independent reproduction of TemporaryDirectory's original failure.
        old=tempfile.TemporaryDirectory(prefix='swassh-old-sharing-');path=Path(old.name)/'diagnostic'
        path.write_bytes(b'synthetic diagnostic');fd=open_file_without_reparse(path,os.O_RDONLY)
        try:
            with self.assertRaises(PermissionError) as observed:old.cleanup()
            self.assertEqual(observed.exception.winerror,32)
        finally:os.close(fd);old.cleanup()
        staging=lifecycle.NativeStagingDirectory(prefix='swassh-sharing-');held=[];closer=None
        try:
            async with staging as name:
                path=Path(name)/'diagnostic';path.write_bytes(b'synthetic diagnostic')
                held.append(open_file_without_reparse(path,os.O_RDONLY))
                async def release():
                    await asyncio.sleep(0.05);os.close(held.pop())
                closer=asyncio.create_task(release())
            self.assertFalse(Path(name).exists());self.assertTrue(closer.done())
        finally:
            if closer is not None:await asyncio.gather(closer,return_exceptions=True)
            if held:os.close(held.pop())
            await staging.__aexit__(None,None,None)


if __name__=='__main__':unittest.main()
