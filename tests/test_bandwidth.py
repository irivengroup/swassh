"""Integer shaping contracts and bounded real loopback byte-relay integration."""
from concurrent.futures import ThreadPoolExecutor
import asyncio
import base64
import json
from dataclasses import replace
import os
from pathlib import Path
import random
import sqlite3
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from test_native_ssh import NativeTools

from swassh import Host, Options, Swarm
from swassh.domain.bandwidth import ByteWindow, NANOSECOND
from swassh.infrastructure.bandwidth import SQLiteByteBudget
from swassh.infrastructure.bastion import SharedBudget, specification
from swassh.infrastructure.ssh import _config
from swassh.infrastructure.tcp_proxy import proxy_command, request_arguments


class WindowTests(unittest.TestCase):
    def test_exact_combined_budget_and_clock_regression_never_grant_credit(self):
        window=ByteWindow(1024,1024*NANOSECOND,0)
        window,wait=window.reserve(1024,0)
        self.assertEqual((window.credits,wait),(0,0))
        window,wait=window.reserve(1024,0)
        self.assertEqual(wait,NANOSECOND)
        window,wait=window.reserve(1024,NANOSECOND//2)
        self.assertEqual(wait,NANOSECOND//2)
        window,wait=window.reserve(1024,NANOSECOND)
        self.assertEqual(wait,0)
        window,wait=window.reserve(1024,0)
        self.assertEqual((window.credits,wait),(0,NANOSECOND))

    def test_randomized_sequence_stays_below_independent_byte_allowance(self):
        generator=random.Random(84723)
        rate=32000
        window=ByteWindow(rate,16384*NANOSECOND,0)
        admitted=now=0
        for _ in range(2000):
            now+=generator.randrange(10000000)
            count=generator.randrange(1,16385)
            window,wait=window.reserve(count,now)
            if not wait: admitted+=count
            self.assertLessEqual(admitted,16384+now*rate//NANOSECOND)
            self.assertGreaterEqual(window.credits,0)

    def test_invalid_counters_and_chunks(self):
        for values in ((True,0,0),(0,0,0),(1024,-1,0),(1024,1024*NANOSECOND+1,0),(1024,0,-1)):
            with self.assertRaises(ValueError): ByteWindow(*values)
        window=ByteWindow(1024,0,0)
        for count,now in ((0,0),(True,0),(1025,0),(1,-1),(1,True)):
            with self.assertRaises(ValueError): window.reserve(count,now)

    def test_proxy_quotes_literal_arguments_and_rejects_cmd_expansions(self):
        spec={'directory':"/private root/with'quote",'policy':[32,20,512*1024**2,10240]}
        with patch('swassh.infrastructure.tcp_proxy.specification',return_value=spec), \
                patch('swassh.infrastructure.tcp_proxy.os.name','posix'), \
                patch('swassh.infrastructure.tcp_proxy.sys.executable','/trusted python'):
            arguments=shlex.split(proxy_command(Host('::1'),Options()))
            self.assertEqual(arguments[0],'/trusted python')
            arguments=request_arguments(arguments[3:])
            self.assertEqual(arguments[arguments.index('--budget-root')+1],os.path.abspath(spec['directory']))
        with patch('swassh.infrastructure.tcp_proxy.specification',return_value=spec), \
                patch('swassh.infrastructure.tcp_proxy.os.name','nt'), \
                patch('swassh.infrastructure.tcp_proxy.sys.executable','C:/bad & path/python.exe'):
            with self.assertRaises(ValueError): proxy_command(Host('one'),Options())

    def test_scoped_ipv6_and_literal_percent_paths_survive_windows_shell_boundary(self):
        spec={'directory':'C:/literal %h & root','policy':[32,20,512*1024**2,10240]}
        with patch('swassh.infrastructure.tcp_proxy.specification',return_value=spec), \
                patch('swassh.infrastructure.tcp_proxy.os.name','nt'), \
                patch('swassh.infrastructure.tcp_proxy.sys.executable','C:/Python/python.exe'):
            arguments=shlex.split(proxy_command(Host('fe80::1%eth0'),Options()))
        plain=request_arguments(arguments[3:])
        self.assertEqual(plain[plain.index('--host')+1],'fe80::1%eth0')
        self.assertEqual(plain[plain.index('--budget-root')+1],os.path.abspath(spec['directory']))
        self.assertNotIn('%',arguments[-1]); self.assertNotIn('&',arguments[-1])

    def test_malformed_request_versions_duplicates_and_types_are_refused(self):
        for raw in (b'{}',b'{"host":1,"host":2}',b'{"host":NaN}',b'x'*16385):
            with self.assertRaises(ValueError): request_arguments(['--request',base64.urlsafe_b64encode(raw).decode()])
        for arguments in (['--request','@@'],['--host','one','--request','data'],['--request','x'*32769]):
            with self.assertRaises(ValueError): request_arguments(arguments)
        with patch('swassh.infrastructure.tcp_proxy.specification',return_value={
                'directory':'/private','policy':[32,20,512*1024**2,10240]}):
            for value in (0,True,float('nan')):
                with self.assertRaises(ValueError): proxy_command(Host('one'),Options(),lifetime=value)
            generated=shlex.split(proxy_command(Host('one'),Options()))
        valid=json.loads(base64.urlsafe_b64decode(generated[-1]))
        for changes in ({'schema_version':True},{'schema_version':2},{'host':[]},
                        {'port':True},{'connect-rate':None},{'extra':'value'}):
            payload=base64.urlsafe_b64encode(json.dumps({**valid,**changes}).encode()).decode()
            with self.assertRaises(ValueError): request_arguments(['--request',payload])


class BudgetIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.options=Options(budget_dir=self.temporary.name,bastion_bandwidth_kib=1)
        self.clock=patch('swassh.infrastructure.bandwidth.time.monotonic_ns',return_value=0)
        self.clock.start(); self.addCleanup(self.clock.stop)
        self.budget=SQLiteByteBudget(specification(self.options))
        self.addCleanup(self.budget.close)

    def test_two_owners_and_both_directions_share_the_same_single_burst(self):
        other=SQLiteByteBudget(specification(self.options))
        self.addCleanup(other.close)
        self.assertEqual(self.budget.reserve(1024,now=0),0)
        self.assertEqual(other.reserve(1024,now=0),1)
        self.assertEqual(other.reserve(1024,now=NANOSECOND),0)
        self.assertEqual(self.budget.reserve(1024,now=NANOSECOND),1)
        self.assertEqual(self.budget.db.execute('PRAGMA synchronous').fetchone()[0],3)

    def test_invalid_state_schema_and_policy_fail_closed(self):
        self.budget.db.execute('UPDATE bucket SET credits=-1')
        with self.assertRaises(ValueError): self.budget.reserve(1,now=0)
        self.budget.db.execute('UPDATE bucket SET credits=0')
        self.budget.db.execute('CREATE TABLE unexpected (value)')
        with self.assertRaisesRegex(ValueError,'schema changed'): self.budget.reserve(1,now=0)

    def test_active_policy_cannot_change_and_old_idle_owner_is_invalidated(self):
        pool=SharedBudget(specification(self.options))
        lease=pool.ticket(memory=1)
        self.assertTrue(lease.poll())
        changed=specification(replace(self.options,bastion_bandwidth_kib=2))
        try:
            with self.assertRaisesRegex(ValueError,'policy differs'): SQLiteByteBudget(changed)
        finally:
            lease.close(); pool.close()
        other=SQLiteByteBudget(changed)
        try:
            with self.assertRaisesRegex(ValueError,'policy or counters changed'): self.budget.reserve(1,now=0)
            self.assertGreater(other.reserve(1,now=0),0)
        finally: other.close()

    def test_waiting_cancellation_reserves_no_future_debt(self):
        self.assertEqual(self.budget.reserve(1024,now=0),0)
        stop=threading.Event(); stop.set()
        self.assertFalse(self.budget.take(1024,stop))
        self.assertEqual(self.budget.reserve(1024,now=NANOSECOND),0)

    def test_checkpoint_bounds_disk_and_retains_extra_durability(self):
        for tick in range(80):
            self.assertEqual(self.budget.reserve(1,now=tick*NANOSECOND),0)
            wal=Path(str(self.budget.path)+'-wal')
            self.assertLess(wal.stat().st_size,80000)
        self.assertEqual(self.budget.db.execute('PRAGMA synchronous').fetchone()[0],3)
        self.assertEqual(self.budget.db.execute('PRAGMA journal_mode').fetchone()[0],'wal')
        self.assertEqual(self.budget.db.execute('PRAGMA wal_autocheckpoint').fetchone()[0],0)
        self.assertEqual(self.budget.db.execute('PRAGMA integrity_check').fetchone()[0],'ok')

    def test_pinned_reader_refuses_growth_instead_of_unbounded_wal(self):
        reader=sqlite3.connect(self.budget.path,isolation_level=None)
        self.addCleanup(reader.close)
        reader.execute('BEGIN')
        reader.execute('SELECT * FROM bucket').fetchall()
        self.budget.db.execute('PRAGMA busy_timeout=1')
        with self.assertRaisesRegex(ValueError,'checkpoint blocked'):
            for tick in range(32): self.budget.reserve(1,now=tick*NANOSECOND)
        size=Path(str(self.budget.path)+'-wal').stat().st_size
        with self.assertRaisesRegex(ValueError,'checkpoint blocked'):
            self.budget.reserve(1,now=100*NANOSECOND)
        self.assertEqual(Path(str(self.budget.path)+'-wal').stat().st_size,size)
        reader.rollback()
        self.assertEqual(self.budget.reserve(1,now=100*NANOSECOND),0)

    def test_process_death_retains_committed_debit_and_rolls_back_pending_debit(self):
        spec=specification(self.options)
        code='''import json,os,sys
from swassh.infrastructure.bandwidth import SQLiteByteBudget
budget=SQLiteByteBudget(json.loads(sys.argv[1]))
assert budget.reserve(1024,now=0)==0
with budget._serialized():
    budget.db.execute('BEGIN IMMEDIATE')
    budget.db.execute('UPDATE bucket SET credits=1024000000000')
    os._exit(37)
'''
        process=subprocess.run([sys.executable,'-c',code,json.dumps(spec)],
                               capture_output=True,timeout=10)
        self.assertEqual(process.returncode,37,process.stderr.decode())
        self.assertEqual(self.budget.reserve(1024,now=0),1)
        self.assertEqual(self.budget.db.execute('PRAGMA integrity_check').fetchone()[0],'ok')

    def test_file_mutex_serializes_distinct_owners_and_is_not_unlinked(self):
        other=SQLiteByteBudget(specification(self.options))
        self.addCleanup(other.close)
        acquired=threading.Event();entered=threading.Event()
        def contender():
            entered.set()
            with other._serialized(): acquired.set()
        with self.budget._serialized():
            worker=threading.Thread(target=contender)
            worker.start();self.assertTrue(entered.wait(2))
            self.assertFalse(acquired.wait(0.03))
        worker.join(2)
        self.assertFalse(worker.is_alive())
        self.assertTrue(acquired.is_set())
        self.assertTrue(self.budget.mutex.is_file())


class EchoServer:
    """A bounded ephemeral TCP echo fixture with an admission barrier."""
    def __init__(self,clients):
        self.clients=clients; self.ready=threading.Event(); self.stop=threading.Event()
        self.socket=socket.socket()
        self.socket.bind(('127.0.0.1',0)); self.socket.listen(clients); self.socket.settimeout(5)
        self.port=self.socket.getsockname()[1]
        self.connections=[]; self.threads=[]; self.errors=[]
        self.owner=threading.Thread(target=self._accept,daemon=True)
        self.owner.start()

    def _accept(self):
        try:
            for _ in range(self.clients):
                connection,_=self.socket.accept()
                connection.settimeout(5)
                self.connections.append(connection)
                worker=threading.Thread(target=self._echo,args=(connection,),daemon=True)
                self.threads.append(worker); worker.start()
            self.ready.set()
        except OSError as error:
            if not self.stop.is_set(): self.errors.append(error)

    def _echo(self,connection):
        try:
            while not self.stop.is_set():
                data=connection.recv(16384)
                if not data: break
                connection.sendall(data)
        except OSError as error:
            if not self.stop.is_set(): self.errors.append(error)
        finally: connection.close()

    def close(self):
        self.stop.set(); self.socket.close()
        for connection in self.connections:
            try: connection.shutdown(socket.SHUT_RDWR)
            except OSError: pass
            connection.close()
        self.owner.join(timeout=6)
        for worker in self.threads: worker.join(timeout=6)


class RelayIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.options=Options(budget_dir=self.temporary.name,bastion_bandwidth_kib=32)
        self.children=[]
        self.addCleanup(self.cleanup)
        # The real guardian initializes this policy before native spawn.
        # Keep that preparation outside a peer's accept/idle observation.
        coordinator = SharedBudget(specification(self.options))
        coordinator.close()

    def cleanup(self):
        for process in self.children:
            if process.poll() is None: process.kill()
            process.communicate(timeout=5)

    @staticmethod
    def _prepared_budget_program():
        """Prepare a real adapter before the idle-open phase, without a fake clock."""
        return """import sys
from pathlib import Path
from swassh.infrastructure import tcp_proxy
args=tcp_proxy._arguments(sys.argv[1:])
spec={'directory':args.budget_root,'policy':[
    args.connections,args.connect_rate,args.memory_bytes,args.bandwidth_kib]}
if not (Path(spec['directory'])/'budget.sqlite3').is_file():
    raise ValueError('idle fixture requires the guardian-prepared policy')
prepared=tcp_proxy.SQLiteByteBudget(spec)
def prepared_budget(requested):
    if requested!=spec:
        raise ValueError('idle fixture budget specification changed')
    return prepared
tcp_proxy.SQLiteByteBudget=prepared_budget
raise SystemExit(tcp_proxy.main())
"""

    def launch(self,port,*,lifetime=10,prepared_budget=False):
        spec=specification(self.options)
        args=[sys.executable,'-m','swassh.infrastructure.tcp_proxy','--host','127.0.0.1','--port',str(port),
            '--budget-root',spec['directory'],'--connections',str(spec['policy'][0]),'--connect-rate',str(spec['policy'][1]),
            '--memory-bytes',str(spec['policy'][2]),'--bandwidth-kib',str(spec['policy'][3]),
            '--connect-timeout','2','--lifetime',str(lifetime)]
        if prepared_budget:
            # The test below observes an already-open idle relay. Real adapter
            # construction belongs to its fixture, while the separate cold and
            # stalled bootstrap cases retain the original producer-wide timer.
            args=[sys.executable,'-c',self._prepared_budget_program(),*args[3:]]
        process=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        self.children.append(process)
        return process

    def test_two_processes_respect_combined_transmit_receive_ceiling(self):
        server=EchoServer(2)
        try:
            peers=[self.launch(server.port) for _ in range(2)]
            self.assertTrue(server.ready.wait(5),'both relays must connect before the measured byte flow')
            payload=bytes(range(256))*64
            start=time.monotonic()
            with ThreadPoolExecutor(max_workers=2) as workers:
                futures=[workers.submit(peer.communicate,payload,timeout=8) for peer in peers]
                receipts=[future.result(timeout=10) for future in futures]
            elapsed=time.monotonic()-start
            for peer,(output,error) in zip(peers,receipts):
                self.assertEqual(peer.returncode,0,error.decode('utf-8','replace'))
                self.assertEqual(output,payload)
            # 65536 encrypted bytes share 32768 B/s, with one 16384-byte
            # initial burst. Process startup is outside this measured interval.
            self.assertGreaterEqual(elapsed,1.4)
            self.assertEqual(server.errors,[])
        finally: server.close()

    def test_connection_failure_has_no_fallback_or_endpoint_leak(self):
        with socket.socket() as free:
            free.bind(('127.0.0.1',0)); port=free.getsockname()[1]
        peer=self.launch(port)
        output,error=peer.communicate(b'',timeout=5)
        self.assertEqual(peer.returncode,125)
        self.assertEqual(output,b'')
        self.assertEqual(error,b'swassh: encrypted-byte relay failed; no direct connection fallback\n')

    def test_independent_deadline_stops_an_idle_open_relay(self):
        server=EchoServer(1)
        try:
            peer=self.launch(server.port,lifetime=0.5,prepared_budget=True)
            self.assertTrue(server.ready.wait(4))
            self.assertEqual(peer.wait(timeout=4),124)
        finally: server.close()

    @unittest.skipUnless(shutil.which('ssh'),'OpenSSH client unavailable')
    def test_openssh_accepts_private_proxy_configuration_without_connecting(self):
        path=Path(self.temporary.name)/'config'
        for options in (self.options,replace(self.options,jump_host=Host('jump-host',2222))):
            config=_config(Host('target-host'),options)
            self.assertEqual(config.count('ProxyCommand '),1)
            path.write_text(config,encoding='utf-8')
            process=subprocess.run([NativeTools.require('ssh'),'-G','-F',str(path),'swassh-target'],
                capture_output=True,timeout=5,env=NativeTools.environment())
            self.assertEqual(process.returncode,0,process.stderr.decode('utf-8','replace'))
            if options.jump_host is None:
                self.assertIn('swassh.infrastructure.tcp_proxy',process.stdout.decode())
            else:
                self.assertGreater(config.index('ProxyCommand '),config.index('Host swassh-jump'))

    @unittest.skipUnless(shutil.which('ssh'),'OpenSSH client unavailable')
    def test_real_openssh_starts_quoted_relay_without_direct_fallback(self):
        server=socket.socket()
        server.bind(('127.0.0.1',0)); server.listen(1); server.settimeout(4)
        received=[]; errors=[]; readiness=[]; admitted=[]
        def banner():
            try:
                # Admission is local preparation, independently bounded by the
                # original producer. The peer's four-second accept window starts
                # only once the real guardian has admitted its native client.
                observer, process = readiness[0]
                until = time.monotonic() + 4
                while True:
                    receipt = observer._read()
                    if receipt is not None and receipt['state'] == 'admitted':
                        admitted.append(True)
                        break
                    if process.returncode is not None or time.monotonic() >= until:
                        raise TimeoutError('real native admission was not observed')
                    time.sleep(0.005)
                connection,_=server.accept()
                with connection:
                    connection.settimeout(3)
                    connection.sendall(b'SSH-2.0-synthetic-test-peer\r\n')
                    received.append(connection.recv(1024))
            except OSError as error: errors.append(error)
        worker=threading.Thread(target=banner,daemon=True)
        known=Path(self.temporary.name)/'known-hosts'
        try:
            # Fixture preparation precedes the peer's connection clock. File
            # creation and option validation are not an attempted SSH banner.
            known.write_text('')
            options=replace(self.options,known_hosts=str(known),command_timeout=4,connect_timeout=2)
            service=Swarm(options)
            host=Host('127.0.0.1',server.getsockname()[1])
            # The invocation prepares this database even without proxy traffic.
            # A stable baseline distinguishes creation from a real byte debit.
            accounting=SQLiteByteBudget(specification(options))
            try:
                initial_observed=accounting.db.execute('SELECT observed FROM bucket WHERE id=1').fetchone()[0]
            finally: accounting.close()
            from swassh.infrastructure import ssh as native_ssh
            launch = native_ssh.launch_native
            attempts = []
            async def connect(*args, **kwargs):
                # Every original connection/command deadline still covers spawn.
                # Config, audit and admission preparation have no peer yet.
                attempts.append(True)
                process = await launch(*args, **kwargs)
                from swassh.infrastructure.admission_deadline import AdmissionDeadline
                # Reuse the strict production reader, including Windows delete
                # sharing. This unentered timeout is only its inert constructor
                # dependency: the fixture never reschedules an application clock.
                readiness.append((AdmissionDeadline(process._swassh_guardian[1].name,
                    asyncio.timeout(None), 4, process._swassh_guardian_started), process))
                worker.start()
                return process
            with patch.object(native_ssh, 'launch_native', side_effect=connect):
                report=asyncio.run(service.run([host],'true'))
            self.assertEqual(len(attempts), 1)
            self.assertFalse(report.ok)
            worker.join(timeout=5)
            self.assertEqual(errors,[])
            self.assertEqual(admitted,[True])
            self.assertEqual(len(received),1)
            self.assertTrue(received[0].startswith(b'SSH-2.0-OpenSSH'))
            self.assertTrue((Path(specification(options)['directory'])/'encrypted-bytes.sqlite').is_file())
            accounting=SQLiteByteBudget(specification(options))
            try:
                observed=accounting.db.execute('SELECT observed FROM bucket WHERE id=1').fetchone()[0]
                self.assertGreater(observed,initial_observed,'relay must debit encrypted bytes')
            finally: accounting.close()
        finally:
            server.close()
            if worker.ident is not None: worker.join(timeout=5)



    @unittest.skipUnless(shutil.which('ssh'),'OpenSSH client unavailable')
    def test_fixture_preparation_delay_does_not_consume_peer_accept_window(self):
        """A slow fixture write cannot expire a peer before the client starts."""
        original = Path.write_text
        delays = []
        def prepare(path, data, *args, **kwargs):
            if path.name == 'known-hosts' and data == '':
                delays.append(time.monotonic())
                # Fault injection exceeds the unchanged four-second peer
                # accept window. No application or socket budget is extended.
                time.sleep(4.25)
            return original(path, data, *args, **kwargs)
        with patch.object(Path, 'write_text', prepare):
            self.test_real_openssh_starts_quoted_relay_without_direct_fallback()
        self.assertEqual(len(delays), 1)

    @unittest.skipUnless(shutil.which('ssh'),'OpenSSH client unavailable')
    def test_fixture_preparation_failure_closes_the_unstarted_peer(self):
        """A failed fixture write cannot leak a listening socket or join a new thread."""
        original_socket, original_write = socket.socket, Path.write_text
        opened = []
        def allocate(*args, **kwargs):
            value = original_socket(*args, **kwargs)
            opened.append(value)
            return value
        def prepare(path, data, *args, **kwargs):
            if path.name == 'known-hosts' and data == '':
                raise OSError('synthetic fixture preparation failure')
            return original_write(path, data, *args, **kwargs)
        with patch.object(socket, 'socket', allocate), patch.object(Path, 'write_text', prepare):
            with self.assertRaisesRegex(OSError, '^synthetic fixture preparation failure$'):
                self.test_real_openssh_starts_quoted_relay_without_direct_fallback()
        self.assertEqual(len(opened), 1)
        self.assertEqual(opened[0].fileno(), -1)


    def _delayed_budget_child(self, mode):
        """Delay cold policy creation, every bootstrap, or the real byte adapter."""
        create = subprocess.Popen
        program = """import sys,time
from pathlib import Path
from swassh.infrastructure import bandwidth,tcp_proxy
original=bandwidth.SharedBudget
mode=sys.argv.pop(1)
class DelayedBudget(original):
    def __init__(self,spec):
        if mode=='stall' or not (Path(spec['directory'])/'budget.sqlite3').exists():
            time.sleep(30 if mode=='stall' else 0.75)
        super().__init__(spec)
bandwidth.SharedBudget=DelayedBudget
if mode=='bytes':
    original_bytes=tcp_proxy.SQLiteByteBudget
    class DelayedByteBudget(original_bytes):
        def __init__(self,spec):
            time.sleep(0.75)
            super().__init__(spec)
    tcp_proxy.SQLiteByteBudget=DelayedByteBudget
raise SystemExit(tcp_proxy.main())
"""
        def launch(arguments, *args, **kwargs):
            if arguments[:3] == [sys.executable, '-m', 'swassh.infrastructure.tcp_proxy']:
                arguments = [sys.executable, '-c', program, mode, *arguments[3:]]
            elif arguments[:2] == [sys.executable, '-c'] and arguments[2] == self._prepared_budget_program():
                # Apply the identical dependency fault before the prepared
                # adapter, rather than silently bypassing this child fixture.
                prefix=program.removesuffix('raise SystemExit(tcp_proxy.main())\n')
                arguments = [sys.executable, '-c', prefix+arguments[2], mode, *arguments[3:]]
            return create(arguments, *args, **kwargs)
        return patch.object(subprocess, 'Popen', side_effect=launch)

    def test_idle_deadline_uses_the_guardian_prepared_policy(self):
        """An idle-open test needs the policy the real guardian prepares first."""
        with self._delayed_budget_child('cold'):
            self.test_independent_deadline_stops_an_idle_open_relay()

    def test_idle_deadline_is_independent_of_slow_byte_adapter_preparation(self):
        """A 0.75-second real adapter setup cannot consume the 0.5-second idle phase."""
        with self._delayed_budget_child('bytes'):
            self.test_independent_deadline_stops_an_idle_open_relay()

    def test_idle_fixture_refuses_a_missing_guardian_policy(self):
        """Idle preparation must not manufacture the policy its guardian owns."""
        (Path(specification(self.options)['directory'])/'budget.sqlite3').unlink()
        with socket.socket() as server:
            server.bind(('127.0.0.1',0))
            server.listen(1)
            peer=self.launch(server.getsockname()[1],lifetime=0.5,prepared_budget=True)
            output,error=peer.communicate(timeout=4)
            self.assertNotEqual(peer.returncode,0)
            self.assertEqual(output,b'')
            self.assertIn(b'idle fixture requires the guardian-prepared policy',error)
            server.settimeout(0.1)
            with self.assertRaises(socket.timeout):
                server.accept()

    def test_independent_deadline_also_caps_slow_byte_adapter_bootstrap(self):
        """The real cold entry point retains its timer before adapter creation."""
        with socket.socket() as server:
            server.bind(('127.0.0.1',0))
            server.listen(1)
            with self._delayed_budget_child('bytes'):
                peer=self.launch(server.getsockname()[1],lifetime=0.5)
            try:
                output,error=peer.communicate(timeout=4)
            except subprocess.TimeoutExpired:
                self.fail('the unchanged relay lifetime did not stop byte adapter initialization')
            self.assertEqual(peer.returncode,124)
            self.assertEqual(output,b'')
            self.assertEqual(error,b'')
            server.settimeout(0.1)
            with self.assertRaises(socket.timeout):
                server.accept()

    def test_independent_deadline_also_caps_a_stalled_budget_bootstrap(self):
        """Preparation of a fixture must never defer the producer's hard timer."""
        with socket.socket() as server:
            server.bind(('127.0.0.1', 0))
            server.listen(1)
            with self._delayed_budget_child('stall'):
                peer = self.launch(server.getsockname()[1], lifetime=0.5)
            try:
                output, error = peer.communicate(timeout=4)
            except subprocess.TimeoutExpired:
                self.fail('the unchanged relay lifetime did not stop budget initialization')
            self.assertEqual(peer.returncode, 124)
            self.assertEqual(output, b'')
            self.assertEqual(error, b'')
            server.settimeout(0.1)
            with self.assertRaises(socket.timeout):
                server.accept()

    @unittest.skipUnless(shutil.which('ssh'), 'OpenSSH client unavailable')
    def test_client_preparation_delay_does_not_consume_peer_accept_window(self):
        """Only an attempted native connection starts the peer accept clock."""
        from swassh.infrastructure.authentication import Authentication
        original = Authentication.environment
        delays = []
        def prepare(*args, **kwargs):
            delays.append(time.monotonic())
            time.sleep(4.25)
            return original(*args, **kwargs)
        with patch.object(Authentication, 'environment', side_effect=prepare):
            self.test_real_openssh_starts_quoted_relay_without_direct_fallback()
        self.assertEqual(len(delays), 1)


if __name__=='__main__': unittest.main()
