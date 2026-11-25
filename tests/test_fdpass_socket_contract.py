"""A selected fdpass helper must preserve the socket's short-record contract.

The integration case inspects a real loopback descriptor, without SSH payload,
keys or a remote target. Help text alone cannot prove TCP_NODELAY on that fd.
"""
import array
import os
import shutil
import socket
import subprocess
import sys
import unittest
from unittest.mock import MagicMock, patch

from swassh.infrastructure.relay_connect import NativeConnector


class DescriptorOptionProbeTests(unittest.TestCase):
    def test_module_entrypoint_rejects_invalid_port_before_opening_a_connection(self):
        result = subprocess.run([sys.executable, '-m', 'swassh.infrastructure.relay_connect', '0'],
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 125)
        self.assertEqual(result.stdout, '')
        self.assertEqual(result.stderr, 'swassh: guardian relay connection failed\n')

    def probe(self, *, nodelay=1, data=b'\0', fds=(37,), flags=0,
              recv_error=None, socket_error=None, wait_error=False, exit_code=0, unrelated_ancillary=()):
        listener,parent,child,connection=(MagicMock() for _ in range(4))
        for stream in (listener,parent,child,connection):stream.__enter__.return_value=stream
        listener.getsockname.return_value=('127.0.0.1',2222)
        rights=getattr(socket,'SCM_RIGHTS',1)
        parent.recvmsg.return_value=(data,[*unrelated_ancillary,(socket.SOL_SOCKET,rights,array.array('i',fds).tobytes())],flags,None)
        parent.recvmsg.side_effect=recv_error
        connection.getsockopt.return_value=nodelay
        process=MagicMock(returncode=exit_code)
        process.pid=1073741824
        process.poll.return_value=None if recv_error or wait_error else exit_code
        if wait_error:process.wait.side_effect=[subprocess.TimeoutExpired('synthetic',1),0]
        opening=MagicMock(side_effect=[listener,socket_error if socket_error else connection])
        if socket_error:
            def create(*args,**kwargs):
                if 'fileno' in kwargs:raise socket_error
                return listener
            opening.side_effect=create
        with patch('socket.socket',opening),patch('socket.socketpair',return_value=(parent,child)),\
             patch('socket.CMSG_SPACE',side_effect=lambda size:size+16,create=True),\
             patch('socket.SCM_RIGHTS',rights,create=True),patch('subprocess.Popen',return_value=process) as launch,\
             patch('os.close') as close,patch('os.killpg',create=True),\
             patch('signal.SIGKILL',9,create=True):
            result=NativeConnector._nodelay('/trusted/connector')
        self.assertEqual(launch.call_args.args[0],['/trusted/connector','-F','-I','16384','-O','16384',
            '-w','1','127.0.0.1','2222'])
        listener.__exit__.assert_called_once();parent.__exit__.assert_called_once();child.__exit__.assert_called_once()
        child.close.assert_called_once()
        self.assertEqual(process.wait.call_args_list[-1].kwargs,{'timeout':2})
        return result,connection,close,process

    def test_only_successful_undelayed_socket_is_accepted_and_always_closed(self):
        for nodelay,code,expected in ((1,0,True),(0,0,False),(1,7,False)):
            with self.subTest(nodelay=nodelay,code=code):
                result,connection,close,process=self.probe(nodelay=nodelay,exit_code=code)
                self.assertIs(result,expected)
                connection.getsockopt.assert_called_once_with(socket.IPPROTO_TCP,socket.TCP_NODELAY)
                connection.__exit__.assert_called_once()
                close.assert_not_called();process.kill.assert_not_called()

    def test_unrelated_ancillary_messages_never_become_owned_file_descriptors(self):
        rights = getattr(socket, 'SCM_RIGHTS', 1)
        ancillary = ((socket.SOL_SOCKET + 999, rights, b'ignored'),
                     (socket.SOL_SOCKET, rights + 999, b'ignored'))
        accepted, connection, close, process = self.probe(unrelated_ancillary=ancillary)
        self.assertTrue(accepted)
        connection.__exit__.assert_called_once()
        close.assert_not_called()
        process.kill.assert_not_called()

    def test_missing_multiple_or_truncated_descriptors_are_refused_and_all_received_fds_closed(self):
        for data,fds,flags in ((b'',(37,),0),(b'x',(),0),(b'x',(37,38),0),(b'x',(37,),8)):
            with self.subTest(data=data,fds=fds,flags=flags):
                result,connection,close,_=self.probe(data=data,fds=fds,flags=flags)
                self.assertFalse(result);connection.getsockopt.assert_not_called()
                self.assertEqual([call.args[0] for call in close.call_args_list],list(fds))

    def test_failed_socket_constructor_does_not_lose_received_descriptor_ownership(self):
        result,_,close,_=self.probe(socket_error=OSError('synthetic non-socket descriptor'))
        self.assertFalse(result);close.assert_called_once_with(37)

    def test_probe_timeouts_reap_helper_and_never_accept_a_partial_observation(self):
        for change in ({'recv_error':TimeoutError()},{'wait_error':True}):
            result,_,_,process=self.probe(**change)
            self.assertFalse(result);process.kill.assert_called_once()


@unittest.skipUnless(os.name=='posix' and hasattr(socket,'SCM_RIGHTS'),'POSIX fdpass integration')
class NativeDescriptorIntegrationTests(unittest.TestCase):
    @staticmethod
    def descriptor_nodelay(path):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1',0));listener.listen(1)
            parent,child=socket.socketpair()
            with parent,child:
                parent.settimeout(2)
                process=subprocess.Popen([path,'-F','-I','16384','-O','16384','-w','1',
                    '127.0.0.1',str(listener.getsockname()[1])],stdin=subprocess.DEVNULL,
                    stdout=child,stderr=subprocess.DEVNULL)
                descriptors=array.array('i')
                try:
                    data,controls,flags,_=parent.recvmsg(1,socket.CMSG_SPACE(4*descriptors.itemsize))
                    for level,kind,value in controls:
                        if level==socket.SOL_SOCKET and kind==socket.SCM_RIGHTS:
                            descriptors.frombytes(value[:len(value)-len(value)%descriptors.itemsize])
                    if len(data)!=1 or len(descriptors)!=1 or flags:
                        raise AssertionError('invalid fdpass protocol from the trusted local fixture')
                    with socket.socket(fileno=descriptors.pop()) as connection:
                        nodelay=connection.getsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY)
                    process.wait(timeout=2)
                    if process.returncode!=0:raise AssertionError('fdpass helper failed')
                    return nodelay
                finally:
                    for descriptor in descriptors:os.close(descriptor)
                    if process.poll() is None:process.kill()
                    process.wait(timeout=2)

    def test_every_selected_native_helper_passes_a_socket_with_tcp_nodelay(self):
        with patch.dict(NativeConnector._cache,clear=True):
            chosen=NativeConnector.find()
        if chosen is not None:
            self.assertEqual(self.descriptor_nodelay(chosen),1,
                'a fast helper must not reintroduce Nagle delays on the socket passed to OpenSSH')
        # This is a capability test: an installed but incompatible nc remains
        # unsupported, with the Python connector selected before SSH starts.
        native=shutil.which('nc.openbsd') or shutil.which('nc')
        if native and NativeConnector._supports(native) and not self.descriptor_nodelay(native):
            self.assertIsNone(chosen)
