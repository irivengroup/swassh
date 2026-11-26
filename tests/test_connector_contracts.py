"""Portable discovery contracts and real bounded POSIX special-file inspection."""
from contextlib import ExitStack
from pathlib import PurePosixPath
from types import SimpleNamespace
import os
import socket
import stat
import unittest
from unittest.mock import MagicMock,patch

from swassh.infrastructure.relay_connect import NativeConnector,main


HELP=b'OpenBSD netcat\n -F Pass connected socket\n -I receive buffer\n -O send buffer\n'


class ConnectorDiscoveryContracts(unittest.TestCase):
    def test_unsupported_platform_never_searches_or_executes_a_tool(self):
        with patch('os.name','nt'),patch('shutil.which') as which:
            self.assertIsNone(NativeConnector.find())
        which.assert_not_called()

    def test_capability_cache_is_identity_bound_and_bounded(self):
        info=SimpleNamespace(st_dev=1,st_ino=2,st_size=3,st_mtime_ns=4,st_ctime_ns=5)
        with patch('os.name','posix'),patch('shutil.which',return_value='/candidate/nc'), \
                patch('pathlib.Path') as path,patch.object(NativeConnector,'_trusted_info',return_value=info),patch.object(NativeConnector,'_supports',return_value=True) as probe, \
                patch.object(NativeConnector,'_nodelay',return_value=True) as descriptor_probe, \
                patch.dict(NativeConnector._cache,clear=True):
            path.return_value.resolve.return_value=PurePosixPath('/trusted/nc')
            path.return_value.stat.return_value=info
            self.assertEqual(NativeConnector.find(),'/trusted/nc')
            self.assertEqual(NativeConnector.find(),'/trusted/nc')
            self.assertEqual(probe.call_count,1)
            self.assertEqual(descriptor_probe.call_count,1)
            info.st_mtime_ns=5
            self.assertEqual(NativeConnector.find(),'/trusted/nc')
            self.assertEqual(probe.call_count,2)
            self.assertEqual(descriptor_probe.call_count,2)
            NativeConnector._cache.update({('synthetic',number):False for number in range(64)})
            info.st_mtime_ns=6
            self.assertEqual(NativeConnector.find(),'/trusted/nc')
            self.assertEqual(len(NativeConnector._cache),1)

    def test_help_compatible_but_delayed_socket_is_rejected_before_target_launch(self):
        with patch('os.name','posix'),patch('shutil.which',return_value='/candidate/nc'), \
                patch('pathlib.Path') as path,patch.object(NativeConnector,'_trusted_info',return_value=SimpleNamespace(st_dev=1,st_ino=2,st_size=3,st_mtime_ns=4,st_ctime_ns=5)),patch.object(NativeConnector,'_supports',return_value=True), \
                patch.object(NativeConnector,'_nodelay',return_value=False) as descriptor_probe, \
                patch.dict(NativeConnector._cache,clear=True):
            path.return_value.resolve.return_value=PurePosixPath('/trusted/nc')
            path.return_value.stat.return_value=SimpleNamespace(st_dev=1,st_ino=2,st_size=3,st_mtime_ns=4,st_ctime_ns=5)
            self.assertIsNone(NativeConnector.find())
            self.assertIsNone(NativeConnector.find())
            descriptor_probe.assert_called_once_with('/trusted/nc')

    def test_absent_or_unsupported_tools_select_the_python_connector(self):
        with patch('os.name','posix'),patch('shutil.which',return_value=None):
            self.assertIsNone(NativeConnector.find())
        with patch('os.name','posix'),patch('shutil.which',return_value='/candidate/nc'), \
                patch('pathlib.Path') as path,patch.object(NativeConnector,'_trusted_info',return_value=SimpleNamespace(st_dev=1,st_ino=2,st_size=3,st_mtime_ns=4,st_ctime_ns=5)),patch.object(NativeConnector,'_supports',return_value=False), \
                patch.dict(NativeConnector._cache,clear=True):
            path.return_value.resolve.return_value=PurePosixPath('/trusted/nc')
            path.return_value.stat.return_value=SimpleNamespace(st_dev=1,st_ino=2,st_size=3,st_mtime_ns=4,st_ctime_ns=5)
            self.assertIsNone(NativeConnector.find())

    def probe_boundaries(self,stack,*,mode=stat.S_IFREG|0o755,uid=42):
        directory=stack.enter_context(patch('swassh.infrastructure.filesystem.PinnedDirectory'))
        directory.return_value.__enter__.return_value.open.return_value=7
        stack.enter_context(patch('os.fstat',return_value=SimpleNamespace(st_mode=mode,st_uid=uid)))
        closing=stack.enter_context(patch('os.close'))
        stack.enter_context(patch('os.geteuid',return_value=42,create=True))
        process=MagicMock()
        process.pid=1073741824
        process.stdout.fileno.return_value=8
        process.poll.return_value=0
        opening=stack.enter_context(patch('subprocess.Popen',return_value=process))
        ready=stack.enter_context(patch('select.select',return_value=([process.stdout],[],[])))
        reading=stack.enter_context(patch('os.read',side_effect=[HELP,b'']))
        # The native probe now owns a process group. Unit doubles must never
        # send a real signal; descendant behavior is checked with real helpers.
        stack.enter_context(patch('os.killpg',create=True))
        stack.enter_context(patch('signal.SIGKILL',9,create=True))
        return process,opening,ready,reading,closing

    def test_help_probe_requires_all_capabilities_and_always_closes_resources(self):
        for output,expected in ((HELP,True),(HELP.replace(b'-F',b'-Z'),False),(b'Busybox nc\n',False)):
            with self.subTest(output=output),ExitStack() as stack:
                process,opening,_,reading,closing=self.probe_boundaries(stack)
                reading.side_effect=[output,b'']
                self.assertEqual(NativeConnector._supports('/trusted/nc'),expected)
                opening.assert_called_once()
                self.assertEqual(opening.call_args.args[0],['/trusted/nc','-h'])
                closing.assert_called_once_with(7)
                process.stdout.close.assert_called_once_with()
                process.wait.assert_called_once_with(timeout=2)

    def test_unsafe_owner_permissions_or_file_type_never_execute_the_tool(self):
        for mode,uid in ((stat.S_IFREG|0o777,42),(stat.S_IFREG|0o755,99),(stat.S_IFDIR|0o755,42)):
            with self.subTest(mode=mode,uid=uid),ExitStack() as stack:
                process,opening,_,_,closing=self.probe_boundaries(stack,mode=mode,uid=uid)
                with self.assertRaises(ValueError):NativeConnector._supports('/trusted/nc')
                opening.assert_not_called()
                closing.assert_called_once_with(7)

    def test_probe_timeout_and_excess_output_kill_the_process_without_fallback(self):
        for scenario in ('expired','not-readable','too-much-output'):
            with self.subTest(scenario=scenario),ExitStack() as stack:
                process,_,ready,reading,_=self.probe_boundaries(stack)
                process.poll.return_value=None
                if scenario=='expired':stack.enter_context(patch('time.monotonic',side_effect=[0,2]))
                if scenario=='not-readable':ready.return_value=([],[],[])
                if scenario=='too-much-output':reading.side_effect=[b'x'*4096,b'x'*4096,b'x']
                self.assertFalse(NativeConnector._supports('/trusted/nc'))
                process.kill.assert_called_once_with()
                process.wait.assert_called_once_with(timeout=2)
                process.stdout.close.assert_called_once_with()


class DescriptorProtocolContracts(unittest.TestCase):
    def test_descriptor_delivery_and_failed_send_have_the_same_cleanup(self):
        for written in (1,0):
            with self.subTest(written=written),patch('socket.create_connection') as connection, \
                    patch('socket.socket') as control,patch('socket.SCM_RIGHTS',1,create=True):
                peer=connection.return_value.__enter__.return_value
                peer.fileno.return_value=9
                stream=control.return_value.__enter__.return_value
                stream.sendmsg.return_value=written
                if written:
                    self.assertEqual(main(['2222']),0)
                else:
                    with self.assertRaises(OSError):main(['2222'])
                connection.assert_called_once_with(('127.0.0.1',2222),timeout=3)
                peer.setsockopt.assert_any_call(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
                peer.settimeout.assert_called_once_with(None)
                control.assert_called_once_with(fileno=1)
                stream.sendmsg.assert_called_once()
                control.return_value.__exit__.assert_called_once()
                connection.return_value.__exit__.assert_called_once()


class ConnectorSpecialFileTests(unittest.TestCase):
    @unittest.skipUnless(os.name == 'posix', 'POSIX FIFO validation')
    def test_fifo_is_refused_without_waiting_for_a_writer(self):
        """A special file must be rejected before an external tool can run."""
        import tempfile
        import threading
        from pathlib import Path
        from swassh.infrastructure.filesystem import PinnedDirectory

        with tempfile.TemporaryDirectory(prefix='swassh-connector-fifo-') as temporary:
            fifo = Path(temporary) / 'nc'
            os.mkfifo(fifo, 0o700)
            attempted, finished = threading.Event(), threading.Event()
            outcomes = []
            original = PinnedDirectory.open

            def opening(directory, name, flags, mode=0o600):
                attempted.set()
                return original(directory, name, flags, mode)

            def inspect():
                try:
                    NativeConnector._supports(str(fifo))
                except ValueError as error:
                    outcomes.append(str(error))
                except BaseException as error:
                    outcomes.append(type(error).__name__)
                else:
                    outcomes.append('incorrectly accepted')
                finally:
                    finished.set()

            worker = threading.Thread(target=inspect, daemon=True)
            with patch.object(PinnedDirectory, 'open', opening), patch('subprocess.Popen') as launch:
                worker.start()
                try:
                    self.assertTrue(attempted.wait(5), 'descriptor inspection never started')
                    self.assertTrue(finished.wait(5), 'connector inspection waited for a FIFO writer')
                finally:
                    # Release an old blocking reader before checking ownership;
                    # this cleanup never supplies a writer to a passing probe.
                    if worker.is_alive():
                        descriptor = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
                        os.close(descriptor)
                    worker.join(5)
                self.assertFalse(worker.is_alive(), 'connector inspection thread leaked')
                launch.assert_not_called()
            self.assertEqual(outcomes, ['native relay connector must be a trusted executable'])
            self.assertTrue(fifo.exists())


@unittest.skipUnless(os.name=='posix' and hasattr(socket,'SCM_RIGHTS'),'POSIX connector cache trust integration')
class ConnectorCacheTrustIntegrationTests(unittest.TestCase):
    """Capability caching must never cache a permission/ancestry authorization."""

    def fixture(self):
        import contextlib
        import shlex
        import sys
        import tempfile
        from pathlib import Path

        @contextlib.contextmanager
        def owned():
            source="""import array, socket, sys
if sys.argv[1:]==['-h']:
    sys.stdout.buffer.write(HELP_DATA)
else:
    with socket.create_connection((sys.argv[-2],int(sys.argv[-1])),timeout=1) as peer:
        peer.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
        with socket.socket(fileno=1) as channel:
            channel.sendmsg([b'\\0'],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[peer.fileno()]))])
""".replace('HELP_DATA',repr(HELP))
            with tempfile.TemporaryDirectory(prefix='swassh-connector-cache-') as temporary:
                # Discovery returns the canonical trusted path (macOS /var is
                # a system alias); the permission assertions use that same path.
                root=Path(temporary).resolve();program=root/'nc.openbsd'
                program.write_text('#!/bin/sh\nexec '+shlex.join([sys.executable,'-I','-B','-c',source])+' "$@"\n',encoding='utf-8')
                program.chmod(0o700)
                with patch.dict(os.environ,{'PATH':str(root)}),patch.dict(NativeConnector._cache,clear=True):
                    yield root,program
        return owned()

    def test_cached_capability_never_accepts_new_shared_write_permissions(self):
        for mode in (0o720,0o702):
            with self.subTest(mode=mode),self.fixture() as (_,program):
                self.assertEqual(NativeConnector.find(),str(program))
                before=program.stat()
                program.chmod(mode)
                after=program.stat()
                # Reproduce exactly what the old identity omitted: chmod does
                # not replace the inode, content length or modification time.
                identity=lambda value:(value.st_dev,value.st_ino,value.st_size,value.st_mtime_ns)
                self.assertEqual(identity(before),identity(after))
                try:
                    with self.assertRaisesRegex(ValueError,'trusted executable'):
                        NativeConnector.find()
                finally:program.chmod(0o700)

    def test_cached_capability_never_bypasses_changed_parent_directory_trust(self):
        with self.fixture() as (root,program):
            self.assertEqual(NativeConnector.find(),str(program))
            before=program.stat()
            root.chmod(0o777)
            try:
                self.assertEqual(program.stat().st_mtime_ns,before.st_mtime_ns)
                with self.assertRaisesRegex(ValueError,'shared writable'):
                    NativeConnector.find()
            finally:root.chmod(0o700)


class ConnectorCacheMetadataContracts(unittest.TestCase):
    def test_changed_ctime_rechecks_capability_without_discarding_an_unchanged_hit(self):
        info=SimpleNamespace(st_dev=1,st_ino=2,st_size=3,st_mtime_ns=4,st_ctime_ns=5)
        with patch('os.name','posix'),patch('shutil.which',return_value='/trusted/nc'), \
                patch('pathlib.Path') as path,patch.object(NativeConnector,'_trusted_info',return_value=info,create=True), \
                patch.object(NativeConnector,'_supports',return_value=True) as help_probe, \
                patch.object(NativeConnector,'_nodelay',side_effect=[True,False]) as socket_probe, \
                patch.dict(NativeConnector._cache,clear=True):
            path.return_value.resolve.return_value=PurePosixPath('/trusted/nc')
            path.return_value.stat.return_value=info
            self.assertEqual(NativeConnector.find(),'/trusted/nc')
            self.assertEqual(NativeConnector.find(),'/trusted/nc')
            self.assertEqual(help_probe.call_count,1)
            self.assertEqual(socket_probe.call_count,1)
            info.st_ctime_ns=6
            self.assertIsNone(NativeConnector.find())
            self.assertEqual(help_probe.call_count,2)
            self.assertEqual(socket_probe.call_count,2)


class ConnectorCleanupFailureTests(unittest.TestCase):
    probe_boundaries = ConnectorDiscoveryContracts.probe_boundaries

    def test_group_cleanup_failure_still_closes_the_real_help_pipe(self):
        reader, writer = os.pipe()
        stream = os.fdopen(reader, 'rb')
        failure = PermissionError('controlled group cleanup failure')
        try:
            with ExitStack() as stack:
                process, opening, _, _, closing = self.probe_boundaries(stack)
                process.stdout = stream
                stack.enter_context(patch('os.killpg', side_effect=failure, create=True))
                with self.assertRaises(PermissionError) as raised:
                    NativeConnector._supports('/trusted/nc')
                self.assertIs(raised.exception, failure)
                self.assertIs(opening.call_args.kwargs['start_new_session'], True)
                process.wait.assert_called_once_with(timeout=2)
                closing.assert_called_once_with(7)
            self.assertTrue(stream.closed)
            with self.assertRaises(OSError):
                os.fstat(reader)
        finally:
            stream.close()
            os.close(writer)

    def test_probe_cleanup_failure_closes_the_real_pipe_and_preserves_the_error(self):
        import subprocess
        for stage in ('kill', 'wait-os-error', 'wait-timeout'):
            with self.subTest(stage=stage):
                reader, writer = os.pipe()
                stream = os.fdopen(reader, 'rb')
                failure = (subprocess.TimeoutExpired('fixture-connector', 2)
                           if stage == 'wait-timeout' else OSError('controlled cleanup failure'))
                try:
                    with ExitStack() as stack:
                        process, _, ready, _, closing = self.probe_boundaries(stack)
                        process.stdout = stream
                        ready.return_value = ([stream], [], [])
                        process.poll.return_value = None
                        if stage == 'kill':
                            process.kill.side_effect = failure
                        else:
                            process.wait.side_effect = failure
                        with self.assertRaises(type(failure)) as raised:
                            NativeConnector._supports('/trusted/nc')
                        self.assertIs(raised.exception, failure)
                        process.kill.assert_called_once_with()
                        if stage == 'kill':
                            process.wait.assert_not_called()
                        else:
                            process.wait.assert_called_once_with(timeout=2)
                        closing.assert_called_once_with(7)
                    self.assertTrue(stream.closed, 'cleanup failure retained the connector output descriptor')
                    with self.assertRaises(OSError):
                        os.fstat(reader)
                finally:
                    stream.close()
                    os.close(writer)
