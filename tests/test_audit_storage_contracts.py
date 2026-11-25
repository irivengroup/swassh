"""Audit storage failures propagate and release the writer without erasing inputs."""
import gzip
import os
from pathlib import Path
import stat
from types import SimpleNamespace
import tempfile
import sys
import unittest
from unittest.mock import Mock,patch

from swassh import Options
from swassh.infrastructure import audit,authentication


class AuditRotationIntegrationTests(unittest.TestCase):
    def test_posix_writer_lock_uses_nonblocking_exclusive_lock_and_releases_descriptor(self):
        for conflict in (False, True):
            stream = Mock()
            stream.fileno.return_value = 31
            kernel = SimpleNamespace(LOCK_EX=2, LOCK_NB=4,
                                     flock=Mock(side_effect=OSError('busy') if conflict else None))
            port = SimpleNamespace(**vars(os))
            port.name = 'posix'
            port.fstat = Mock(return_value=SimpleNamespace(st_size=1))
            with patch.object(audit, 'os', port), patch.object(audit, '_private_open', return_value=stream), \
                    patch.dict(sys.modules, {'fcntl': kernel}):
                if conflict:
                    with self.assertRaisesRegex(OSError, 'active writer'):
                        audit._WriterLock(Path('synthetic-log'))
                else:
                    audit._WriterLock(Path('synthetic-log')).close()
            kernel.flock.assert_called_once_with(31, 6)
            stream.close.assert_called_once_with()
            stream.write.assert_not_called()

    def test_rotation_failure_order_preserves_the_only_copy_and_cleans_temporary(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for failure in ('none','fsync','replace','unlink','not-regular','hardlink'):
                source=root/('source-'+failure);destination=root/('destination-'+failure+'.gz')
                payload=b'synthetic audit record\n';source.write_bytes(payload)
                port=SimpleNamespace(**vars(os))
                if failure in ('fsync','replace'):setattr(port,failure,Mock(side_effect=OSError('synthetic storage failure')))
                if failure=='unlink':
                    port.unlink=lambda path:(_ for _ in ()).throw(OSError('synthetic unlink failure')) if Path(path)==source else os.unlink(path)
                if failure in ('not-regular','hardlink'):
                    real=os.fstat
                    def metadata(fd):
                        info=real(fd)
                        return SimpleNamespace(st_mode=stat.S_IFDIR if failure=='not-regular' else info.st_mode,
                                               st_nlink=2 if failure=='hardlink' else 1)
                    port.fstat=metadata
                with patch.object(audit,'os',port):
                    if failure=='none':audit._compress(str(source),str(destination))
                    else:
                        with self.assertRaises((OSError,ValueError)):audit._compress(str(source),str(destination))
                self.assertEqual(source.exists(),failure!='none')
                self.assertEqual(destination.exists(),failure in ('none','unlink'))
                if destination.exists():self.assertEqual(gzip.decompress(destination.read_bytes()),payload)
                self.assertEqual(list(root.glob('.swassh-gzip-*')),[])

    def test_provider_uses_a_pinned_regular_executable_without_running_or_reading_it(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'provider';path.write_bytes(b'synthetic provider');path.chmod(0o700)
            options=Options(auth_method='password',askpass_executable='synthetic-provider')
            with patch.object(authentication.shutil,'which',return_value=str(path)):
                self.assertEqual(authentication.Authentication.provider(options),str(path.absolute()))
                info=path.stat();port=SimpleNamespace(**vars(os));port.name='posix'
                for mode in (stat.S_IFREG|0o722,stat.S_IFDIR|0o700):
                    port.fstat=lambda fd:SimpleNamespace(st_mode=mode)
                    with patch.object(authentication,'os',port),self.assertRaisesRegex(ValueError,'regular executable'):
                        authentication.Authentication.provider(options)
            with patch.object(authentication.shutil,'which',return_value=None),self.assertRaisesRegex(ValueError,'unavailable'):
                authentication.Authentication.provider(options)
            with patch.object(authentication.Authentication,'provider',return_value=str(path)):
                for global_method,target_method in (('publickey','password'),('password','publickey')):
                    env=authentication.Authentication.environment(Options(auth_method=global_method,askpass_executable='synthetic-provider'),
                        Options(auth_method=target_method,askpass_executable='synthetic-provider'))
                    self.assertEqual(env['SSH_ASKPASS_REQUIRE'],'force');self.assertEqual(env['SSH_ASKPASS'],str(path))
                    self.assertIn('DISPLAY',env)


class AuditLifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def test_handler_construction_and_close_failures_always_release_writer_lock(self):
        for failure in ('construct','flush','close'):
            lock,handler=Mock(),Mock()
            if failure=='construct':handler_factory=Mock(side_effect=OSError('synthetic'))
            else:handler_factory=Mock(return_value=handler)
            if failure=='flush':handler.handle.side_effect=OSError('synthetic')
            if failure=='close':handler.close.side_effect=OSError('synthetic')
            with patch.object(audit,'private_directory'),patch.object(audit,'_WriterLock',return_value=lock),patch.object(audit,'AuditHandler',handler_factory):
                with self.assertRaises(OSError):
                    async with audit.AuditTrail('synthetic-log','a'*32) as trail:await trail.emit('synthetic',{'value':1})
            lock.close.assert_called_once_with()
            if failure!='construct':handler.close.assert_called_once_with()

    async def test_disabled_audit_and_bounded_batch_flush_have_explicit_behavior(self):
        async with audit.AuditTrail(None,'a'*32) as disabled:
            await disabled.emit('synthetic',{});await disabled.flush()
        self.assertEqual(disabled._batch,[])
        handler,lock=Mock(),Mock()
        with patch.object(audit,'private_directory'),patch.object(audit,'_WriterLock',return_value=lock),patch.object(audit,'AuditHandler',return_value=handler):
            async with audit.AuditTrail('synthetic-log','a'*32) as trail:
                for index in range(63):await trail.emit('synthetic',{'index':index})
                handler.handle.assert_not_called();self.assertEqual(len(trail._batch),63)
                await trail.emit('synthetic',{'index':63})
                self.assertEqual(len(trail._batch),0);self.assertEqual(handler.handle.call_count,64)
                handler.synchronize.assert_called_once_with()
        lock.close.assert_called_once_with()


if __name__=='__main__':unittest.main()
