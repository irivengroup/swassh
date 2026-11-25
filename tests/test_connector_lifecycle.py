"""Capability probes own their session, leader and ordinary descendant group."""
import json
import os
from pathlib import Path
import secrets
import select
import shlex
import signal
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from swassh.infrastructure.relay_connect import NativeConnector


class ProbeGroupCleanupContracts(unittest.TestCase):
    """Cleanup retains the original error and the existing two-second join."""

    def test_reaped_leader_still_requires_group_cleanup(self):
        process = Mock(pid=1073741824)
        process.poll.return_value = 0
        with patch('os.killpg', create=True) as grouping, patch('signal.SIGKILL', 9, create=True):
            NativeConnector._stop_probe(process)
        process.kill.assert_not_called()
        process.wait.assert_called_once_with(timeout=2)
        grouping.assert_called_once_with(process.pid, 9)

    def test_already_gone_group_is_a_successful_cleanup(self):
        process = Mock(pid=1073741824)
        process.poll.return_value = 0
        with patch('os.killpg', side_effect=ProcessLookupError, create=True) as grouping, \
                patch('signal.SIGKILL', 9, create=True):
            NativeConnector._stop_probe(process)
        process.wait.assert_called_once_with(timeout=2)
        grouping.assert_called_once_with(process.pid, 9)

    def test_leader_cleanup_errors_do_not_skip_group_cleanup(self):
        for stage in ('kill', 'wait'):
            with self.subTest(stage=stage):
                process = Mock(pid=1073741824)
                process.poll.return_value = None
                failure = OSError('controlled leader cleanup error')
                getattr(process, stage).side_effect = failure
                with patch('os.killpg', create=True) as grouping, patch('signal.SIGKILL', 9, create=True), \
                        self.assertRaises(OSError) as raised:
                    NativeConnector._stop_probe(process)
                self.assertIs(raised.exception, failure)
                process.kill.assert_called_once_with()
                if stage == 'kill':
                    process.wait.assert_not_called()
                else:
                    process.wait.assert_called_once_with(timeout=2)
                grouping.assert_called_once_with(process.pid, 9)

    def test_group_cleanup_error_is_visible(self):
        process = Mock(pid=1073741824)
        process.poll.return_value = 0
        failure = PermissionError('controlled group cleanup error')
        with patch('os.killpg', side_effect=failure, create=True), patch('signal.SIGKILL', 9, create=True), \
                self.assertRaises(PermissionError) as raised:
            NativeConnector._stop_probe(process)
        self.assertIs(raised.exception, failure)
        process.wait.assert_called_once_with(timeout=2)


@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux /proc descendant ownership integration')
class RealProbeDescendantIntegration(unittest.TestCase):
    """Real helpers never open an SSH target; fdpass uses source-owned loopback."""

    @staticmethod
    def process_info(pid):
        try:
            fields = Path('/proc', str(pid), 'stat').read_text().rpartition(') ')[2].split()
            return fields[0], fields[19]
        except (FileNotFoundError, ProcessLookupError):
            return None

    def owned_running(self, child, token):
        self.assertEqual(child['token'], token)
        try:
            descriptor = os.pidfd_open(child['pid'])
        except ProcessLookupError:
            return False
        try:
            if select.select([descriptor], [], [], 0)[0]:
                return False
            current = self.process_info(child['pid'])
            if current is None:
                return not select.select([descriptor], [], [], 0)[0]
            self.assertEqual(current[1], child['start'], 'child PID identity changed')
            # /proc state and cmdline are separate, non-atomic reads during
            # exit. Kernel pidfd readiness observes completed thread exit.
            return not select.select([descriptor], [], [], 0)[0]
        finally:
            os.close(descriptor)

    def stop_owned(self, child, token):
        self.assertEqual(child['token'], token)
        try:
            descriptor = os.pidfd_open(child['pid'])
        except ProcessLookupError:
            return
        try:
            if not select.select([descriptor], [], [], 0)[0]:
                current = self.process_info(child['pid'])
                if current is None:
                    # /proc may disappear during final exit. A pidfd remains
                    # stable; require kernel completion before accepting it.
                    self.assertTrue(select.select([descriptor], [], [], 1)[0],
                                    'process identity disappeared before kernel exit')
                    return
                self.assertEqual(current[1], child['start'], 'refuse signal to a reused PID')
                signal.pidfd_send_signal(descriptor, signal.SIGKILL)
        finally:
            os.close(descriptor)

    def exercise(self, mode, expected):
        token = secrets.token_hex(16)
        child = None
        with tempfile.TemporaryDirectory(prefix='swassh-probe-descendant-') as temporary:
            root = Path(temporary)
            marker = root/'child.json'
            child_code = """import json,os,pathlib,sys,time
fields=pathlib.Path('/proc/self/stat').read_text().rpartition(') ')[2].split()
pathlib.Path(sys.argv[1]).write_text(json.dumps({'pid':os.getpid(),'start':fields[19],'token':sys.argv[2]}))
time.sleep(30)
"""
            helper_code = """import array,pathlib,socket,subprocess,sys,time
mode=MODE
arguments=CHILD_COMMAND
if mode=='help-eof':
    subprocess.Popen(arguments,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
else:
    subprocess.Popen(arguments)
deadline=time.monotonic()+2
while not pathlib.Path(MARKER).exists():
    if time.monotonic()>=deadline:raise RuntimeError('owned child did not start')
    time.sleep(.005)
if mode.startswith('help'):
    sys.stdout.write('OpenBSD netcat\\n -F pass descriptor\\n -I input buffer\\n -O output buffer\\n')
    sys.stdout.flush()
    if mode=='help-live':time.sleep(30)
elif mode=='fd-valid':
    with socket.create_connection((sys.argv[-2],int(sys.argv[-1])),timeout=1) as peer:
        peer.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
        with socket.socket(fileno=1) as control:
            control.sendmsg([b'\\0'],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[peer.fileno()]))])
""".replace('MODE', repr(mode)).replace('CHILD_COMMAND', repr(
                [sys.executable, '-I', '-B', '-c', child_code, str(marker), token])).replace('MARKER', repr(str(marker)))
            program = root/'nc.openbsd'
            program.write_text('#!/bin/sh\nexec '+shlex.join([sys.executable, '-I', '-B', '-c', helper_code])+' "$@"\n', encoding='utf-8')
            program.chmod(0o700)
            try:
                if mode == 'help-held-pipe':
                    with patch.dict(os.environ, {'PATH': str(root)}):
                        actual = NativeConnector.find()
                elif mode.startswith('help'):
                    actual = NativeConnector._supports(str(program))
                else:
                    actual = NativeConnector._nodelay(str(program))
                self.assertIs(actual, expected)
                self.assertTrue(marker.is_file(), 'helper did not reach the owned descendant scenario')
                child = json.loads(marker.read_bytes())
                self.assertEqual(child['token'], token)
                # Signal delivery is asynchronous. The same finite observation
                # is used before/after; the fixture child otherwise sleeps 30s.
                end = time.monotonic()+1
                while self.owned_running(child, token) and time.monotonic() < end:
                    time.sleep(.005)
                self.assertFalse(self.owned_running(child, token),
                                 'capability probe returned with its descendant still running')
            finally:
                if child is None and marker.exists():
                    child = json.loads(marker.read_bytes())
                if child is not None and self.owned_running(child, token):
                    self.stop_owned(child, token)
                    end = time.monotonic()+3
                    while self.owned_running(child, token) and time.monotonic() < end:
                        time.sleep(.005)
                    self.assertFalse(self.owned_running(child, token), 'fixture descendant cleanup failed')

    def test_rejected_discovery_with_held_pipe_stops_the_descendant(self):
        self.exercise('help-held-pipe', None)

    def test_successful_help_after_leader_exit_stops_the_descendant(self):
        self.exercise('help-eof', True)

    def test_timed_out_live_help_stops_the_leader_and_descendant(self):
        self.exercise('help-live', False)

    def test_valid_real_fdpass_stops_the_descendant(self):
        self.exercise('fd-valid', True)

    def test_missing_real_fdpass_stops_the_descendant(self):
        self.exercise('fd-missing', False)


class ProcObserverContracts(unittest.TestCase):
    """Disappearance never proves exit while the stable descriptor is live."""

    def test_proc_missing_errors_are_distinct_from_permission_failure(self):
        for error in (FileNotFoundError(), ProcessLookupError()):
            with self.subTest(error=type(error).__name__), patch.object(Path, 'read_text', side_effect=error):
                self.assertIsNone(RealProbeDescendantIntegration.process_info(1073741824))
        with patch.object(Path, 'read_text', side_effect=PermissionError()), self.assertRaises(PermissionError):
            RealProbeDescendantIntegration.process_info(1073741824)

    def test_missing_stat_needs_kernel_exit_readiness(self):
        observer = RealProbeDescendantIntegration()
        token = secrets.token_hex(16)
        child = {'pid': 1073741824, 'start': '1', 'token': token}
        for readiness, expected in (([], True), ([42], False)):
            with self.subTest(readiness=readiness), patch('os.pidfd_open', return_value=42, create=True), \
                    patch('os.close') as close, patch.object(observer, 'process_info', return_value=None), \
                    patch('select.select', side_effect=[([], [], []), (readiness, [], [])]):
                self.assertIs(observer.owned_running(child, token), expected)
            close.assert_called_once_with(42)

    def test_cleanup_disappearance_accepts_only_completed_kernel_exit(self):
        observer = RealProbeDescendantIntegration()
        token = secrets.token_hex(16)
        child = {'pid': 1073741824, 'start': '1', 'token': token}
        with patch('os.pidfd_open', return_value=42, create=True), patch('os.close') as close, \
                patch.object(observer, 'process_info', return_value=None), \
                patch('signal.pidfd_send_signal', create=True) as send, \
                patch('select.select', side_effect=[([], [], []), ([42], [], [])]) as readiness:
            observer.stop_owned(child, token)
        readiness.assert_called_with([42], [], [], 1)
        send.assert_not_called()
        close.assert_called_once_with(42)

    def test_cleanup_ambiguous_identity_remains_an_error(self):
        observer = RealProbeDescendantIntegration()
        token = secrets.token_hex(16)
        child = {'pid': 1073741824, 'start': '1', 'token': token}
        with patch('os.pidfd_open', return_value=42, create=True), patch('os.close') as close, \
                patch.object(observer, 'process_info', return_value=None), \
                patch('signal.pidfd_send_signal', create=True) as send, \
                patch('select.select', return_value=([], [], [])), self.assertRaises(AssertionError):
            observer.stop_owned(child, token)
        send.assert_not_called()
        close.assert_called_once_with(42)


if __name__ == '__main__':
    unittest.main()
