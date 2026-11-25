"""Literal endpoints, real guardian sockets and OpenSSH descriptor handoff."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
import array
import os
import pickle
import socket
import subprocess
import sys
import tempfile
import time
import unittest

from swassh import Host,Options
from swassh.domain.endpoints import Endpoint
from swassh.infrastructure.bastion import SharedBudget,specification
from swassh.infrastructure.relay_connect import main as connect_descriptor
from swassh.infrastructure.socket_relay import GuardianRelay
from test_bandwidth import EchoServer


class EndpointTests(unittest.TestCase):
    def test_shared_endpoint_normalization_and_public_host_identity(self):
        for name,expected in (('EXAMPLE.ORG','example.org'),('2001:0db8::1','2001:db8::1'),
                              ('fe80::1%eth0','fe80::1%eth0'),('café.example','xn--caf-dma.example')):
            with self.subTest(name=name):
                endpoint=Endpoint(name,2222)
                host=Host(name,2222,'operator','synthetic')
                self.assertEqual(endpoint.hostname,expected)
                self.assertEqual(host.hostname,endpoint.hostname)
                self.assertEqual(endpoint.port,host.port)
                with self.assertRaises(AttributeError):endpoint.port=22
                self.assertEqual(pickle.loads(pickle.dumps(host)),host)
                self.assertEqual(asdict(host),dict(hostname=expected,port=2222,username='operator',label='synthetic'))
                self.assertEqual(type(host).__module__,'swassh.domain.models')

    def test_invalid_endpoint_and_descriptor_inputs_never_open_a_socket(self):
        for hostname,port in ((None,22),('',22),('bad name',22),('::bad::',22),
                              ('fe80::1%',22),('fe80::1%bad scope',22),('a'*254,22),
                              ('one',True),('one',0),('one',65536),('one',22.0),('\ud800',22)):
            with self.subTest(hostname=repr(hostname),port=port),self.assertRaises(ValueError):
                Endpoint(hostname,port)
        for args in ([],['1','2'],['0'],['65536'],['-1'],['True'],['１２'],['1.5']):
            with self.subTest(args=args),self.assertRaises(ValueError):connect_descriptor(args)


class GuardianRelayIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.pool=SharedBudget(specification(Options(budget_dir=self.temporary.name,bastion_bandwidth_kib=32)))
        self.addCleanup(self.pool.close)
        self.relays=[]
        self.addCleanup(self.close_relays)

    def close_relays(self):
        for relay in self.relays:relay.close()

    def relay(self,port):
        relay=GuardianRelay({'host':'127.0.0.1','port':port,'connect_timeout':2},self.pool)
        self.relays.append(relay)
        return relay

    def test_two_embedded_relays_keep_the_shared_bidirectional_byte_ceiling(self):
        server=EchoServer(2)
        try:
            relays=[self.relay(server.port) for _ in range(2)]
            clients=[socket.create_connection(('127.0.0.1',relay.port),timeout=5) for relay in relays]
            self.assertTrue(server.ready.wait(5))
            payload=bytes(range(256))*64
            def exchange(client):
                with client:
                    client.sendall(payload);client.shutdown(socket.SHUT_WR)
                    received=bytearray()
                    while data:=client.recv(16384):received.extend(data)
                    return bytes(received)
            started=time.monotonic()
            with ThreadPoolExecutor(max_workers=2) as workers:
                futures=[workers.submit(exchange,client) for client in clients]
                results=[future.result(timeout=8) for future in futures]
            self.assertEqual(results,[payload,payload])
            self.assertGreaterEqual(time.monotonic()-started,1.4)
            self.assertTrue(all(not relay.failed.is_set() for relay in relays))
            self.assertEqual(server.errors,[])
        finally:server.close()

    def test_connection_failure_is_observed_and_no_direct_fallback_exists(self):
        with socket.socket() as free:
            free.bind(('127.0.0.1',0));port=free.getsockname()[1]
        relay=self.relay(port)
        with socket.create_connection(('127.0.0.1',relay.port),timeout=2):
            self.assertTrue(relay.failed.wait(3))
        relay.close()
        self.assertTrue(all(not worker.is_alive() for worker in relay.workers))

    def test_closing_before_a_client_arrives_never_opens_the_target(self):
        with socket.socket() as target:
            target.bind(('127.0.0.1',0));target.listen(1);target.settimeout(0.05)
            relay=self.relay(target.getsockname()[1])
            relay.close()
            with self.assertRaises(TimeoutError):target.accept()
            self.assertFalse(relay.failed.is_set())
            self.assertTrue(all(not worker.is_alive() for worker in relay.workers))


@unittest.skipUnless(os.name=='posix' and hasattr(socket,'SCM_RIGHTS'),'POSIX descriptor passing only')
class DescriptorHandoffIntegrationTests(unittest.TestCase):
    def test_helper_passes_a_live_socket_and_preserves_raw_binary_bytes(self):
        with socket.socket() as server:
            server.bind(('127.0.0.1',0));server.listen(1);server.settimeout(5)
            control,output=socket.socketpair()
            with control,output:
                control.settimeout(5)
                child=subprocess.Popen([sys.executable,'-m','swassh.infrastructure.relay_connect',
                    str(server.getsockname()[1])],stdin=subprocess.DEVNULL,stdout=output,stderr=subprocess.PIPE)
                try:
                    remote,_=server.accept()
                    with remote:
                        remote.settimeout(3)
                        raw,ancillary,flags,_=control.recvmsg(1,socket.CMSG_SPACE(array.array('i').itemsize))
                        self.assertEqual(raw,b'\0');self.assertEqual(flags,0)
                        self.assertEqual(len(ancillary),1)
                        level,kind,contents=ancillary[0]
                        self.assertEqual((level,kind),(socket.SOL_SOCKET,socket.SCM_RIGHTS))
                        handles=array.array('i');handles.frombytes(contents)
                        self.assertEqual(len(handles),1)
                        with socket.socket(fileno=handles[0]) as handed:
                            self.assertEqual(handed.getsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY),1)
                            handed.sendall(b'\x00\xffout')
                            self.assertEqual(remote.recv(5),b'\x00\xffout')
                            remote.sendall(b'\xff\x00back')
                            self.assertEqual(handed.recv(6),b'\xff\x00back')
                    _,error=child.communicate(timeout=5)
                    self.assertEqual(child.returncode,0,error.decode())
                    self.assertEqual(error,b'')
                finally:
                    if child.poll() is None:child.kill();child.communicate(timeout=5)
