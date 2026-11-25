"""Readiness remains unconfirmed while a private acknowledgement is locked."""
import asyncio
import ctypes
from ctypes import wintypes
import os
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch

from swassh import Host, LocalForward, Options
from swassh.infrastructure import channels, ssh
from swassh.infrastructure.native_ready import NativeReady


class ScopeReadinessSharingTests(unittest.IsolatedAsyncioTestCase):
    """Exercise only local startup policy; no SSH trust is mocked as verified."""

    def scope(self):
        options=Options()
        transport=SimpleNamespace(executable='synthetic-ssh',profiles=SimpleNamespace(for_host=lambda host:options),
            _pacer=SimpleNamespace(acquire=AsyncMock()),aclose=AsyncMock())
        with patch.object(channels,'SSHTransport',return_value=transport):
            return channels.NativeSSHScope(Host('synthetic'),options,5,forward=LocalForward(8080,'internal',443))

    async def watch(self):
        await asyncio.Future()

    async def test_only_transient_windows_sharing_retries_the_same_acknowledgement(self):
        for code in (32,33,5,None):
            with self.subTest(winerror=code):
                scope=self.scope()
                process=SimpleNamespace(returncode=None)
                error=PermissionError('synthetic acknowledgement access refusal')
                error.winerror=code
                observed=Mock(side_effect=[error,True])
                async def launch(*args,**kwargs):
                    return process
                port=SimpleNamespace(**vars(os))
                port.name='nt'
                with patch.object(channels,'os',SimpleNamespace(name='nt')), \
                        patch.object(ssh,'os',port), \
                        patch.object(channels,'launch_native',side_effect=launch) as launcher, \
                        patch.object(scope,'_watch',side_effect=self.watch), \
                        patch.object(NativeReady,'observed',observed), \
                        patch.object(channels,'_cleanup_process',new_callable=AsyncMock) as cleanup:
                    try:
                        if code in (32,33):
                            self.assertIs(await scope.open(),scope)
                            self.assertEqual(observed.call_count,2)
                            self.assertIsNotNone(scope.active_at)
                        else:
                            with self.assertRaises(PermissionError) as raised:
                                await scope.open()
                            self.assertIs(raised.exception,error)
                            self.assertEqual(observed.call_count,1)
                            self.assertIsNone(scope.active_at)
                        launcher.assert_awaited_once()
                    finally:
                        await scope.aclose()
                    cleanup.assert_awaited_once_with(process,[])
                    self.assertIsNone(scope.directory)

    async def test_persistent_sharing_keeps_the_original_startup_deadline_and_closes(self):
        scope=self.scope()
        scope.startup_timeout=0.05
        process=SimpleNamespace(returncode=None)
        error=PermissionError('synthetic persistent acknowledgement lock')
        error.winerror=32
        port=SimpleNamespace(**vars(os))
        port.name='nt'
        with patch.object(channels,'os',SimpleNamespace(name='nt')),patch.object(ssh,'os',port), \
                patch.object(channels,'launch_native',new_callable=AsyncMock,return_value=process) as launcher, \
                patch.object(scope,'_watch',side_effect=self.watch), \
                patch.object(NativeReady,'observed',side_effect=error), \
                patch.object(channels,'_cleanup_process',new_callable=AsyncMock) as cleanup:
            try:
                with self.assertRaises(TimeoutError):
                    await scope.open()
                self.assertIsNone(scope.active_at)
                self.assertIsNone(scope.directory)
                launcher.assert_awaited_once()
                cleanup.assert_awaited_once_with(process,[])
            finally:
                await scope.aclose()

    async def test_malformed_acknowledgement_still_fails_immediately(self):
        scope=self.scope()
        process=SimpleNamespace(returncode=None)
        with patch.object(channels,'os',SimpleNamespace(name='nt')), \
                patch.object(channels,'launch_native',new_callable=AsyncMock,return_value=process) as launcher, \
                patch.object(scope,'_watch',side_effect=self.watch), \
                patch.object(NativeReady,'observed',side_effect=ValueError('acknowledgement mismatch')) as observed, \
                patch.object(channels,'_cleanup_process',new_callable=AsyncMock) as cleanup:
            try:
                with self.assertRaisesRegex(ValueError,'acknowledgement mismatch'):
                    await scope.open()
                observed.assert_called_once_with()
                launcher.assert_awaited_once()
                cleanup.assert_awaited_once_with(process,[])
                self.assertIsNone(scope.active_at)
            finally:
                await scope.aclose()

    @unittest.skipUnless(os.name=='nt','Win32 exclusive acknowledgement handle')
    async def test_real_locked_exact_token_is_read_only_after_the_owned_handle_closes(self):
        scope=self.scope()
        process=SimpleNamespace(returncode=None)
        kernel=ctypes.WinDLL('kernel32',use_last_error=True)
        kernel.CreateFileW.argtypes=[wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,wintypes.LPVOID,wintypes.DWORD,wintypes.DWORD,wintypes.HANDLE]
        kernel.CreateFileW.restype=wintypes.HANDLE
        kernel.CloseHandle.argtypes=[wintypes.HANDLE]
        kernel.CloseHandle.restype=wintypes.BOOL
        release=threading.Event()
        workers,failures,errors=[],[],[]
        original=NativeReady.observed
        async def launch(*argv,**kwargs):
            request=next(arg for arg in argv if arg.startswith('LocalCommand=')).rsplit(' ',1)[-1]
            NativeReady.record(request)
            handle=kernel.CreateFileW(str(scope.readiness.path),0x80000000,0,None,3,0x80,None)
            self.assertNotEqual(handle,ctypes.c_void_p(-1).value)
            def close_after_failed_read():
                release.wait()
                if not kernel.CloseHandle(handle):
                    failures.append(ctypes.get_last_error())
            worker=threading.Thread(target=close_after_failed_read)
            workers.append(worker)
            worker.start()
            return process
        def observed(ready):
            try:
                return original(ready)
            except PermissionError as error:
                errors.append(getattr(error,'winerror',None))
                # The native holder releases after a real failed read, never a
                # guessed sleep; the token is not fabricated by the observer.
                release.set()
                raise
        with patch.object(channels,'launch_native',side_effect=launch) as launcher, \
                patch.object(scope,'_watch',side_effect=self.watch), \
                patch.object(NativeReady,'observed',observed), \
                patch.object(channels,'_cleanup_process',new_callable=AsyncMock) as cleanup:
            try:
                self.assertIs(await scope.open(),scope)
                self.assertTrue(scope.readiness.observed())
                self.assertEqual(scope.readiness.path.read_bytes(),scope.readiness.token.encode('ascii'))
                self.assertTrue(errors)
                self.assertTrue(all(error==32 for error in errors),errors)
                launcher.assert_awaited_once()
            finally:
                release.set()
                for worker in workers:
                    worker.join(timeout=5)
                    self.assertFalse(worker.is_alive())
                await scope.aclose()
            self.assertEqual(failures,[])
            self.assertIsNone(scope.directory)
            cleanup.assert_awaited_once_with(process,[])


if __name__=='__main__':
    unittest.main()
