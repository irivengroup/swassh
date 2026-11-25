"""Encrypted relay ports charge before delivery and retain uploader ownership."""
import os
import base64
import socket
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

from swassh import Host, Options
from swassh.infrastructure import tcp_proxy


class RelayWireBoundaryTests(unittest.TestCase):
    def test_upload_failure_stops_download_and_returns_failure_with_closed_peer(self):
        connection = Mock()
        connection.shutdown.side_effect = OSError('synthetic peer already closed')
        budget = Mock(chunk_size=1024)
        relay = tcp_proxy.TCPRelay(connection, budget)
        port = SimpleNamespace(**vars(os))
        port.read = Mock(side_effect=OSError('synthetic input failed'))
        class ImmediateThread:
            def __init__(self, *, target, **kwargs):
                self.target = target
            def start(self):
                self.target()
        with patch.object(tcp_proxy, 'os', port), patch.object(tcp_proxy.threading, 'Thread', ImmediateThread):
            self.assertEqual(relay.run(), 1)
            relay._upload()  # A stopped relay must not read another byte.
        self.assertTrue(relay.failed)
        port.read.assert_called_once()
        connection.recv.assert_not_called()
        connection.close.assert_called_once()
        budget.take.assert_not_called()

    def test_upload_eof_denied_credit_and_io_failure_never_deliver_unpaid_bytes(self):
        for failure in ('none','credit','read','shutdown'):
            events=[];connection=Mock();budget=Mock(chunk_size=1024)
            budget.take.side_effect=lambda count,stop:events.append(('charged',count)) or failure!='credit'
            connection.sendall.side_effect=lambda data:events.append(('sent',data))
            if failure=='shutdown':connection.shutdown.side_effect=OSError('synthetic closed peer')
            port=SimpleNamespace(**vars(os));port.read=Mock(side_effect=OSError('synthetic read') if failure=='read' else [b'abc',b''])
            relay=tcp_proxy.TCPRelay(connection,budget)
            with patch.object(tcp_proxy,'os',port):relay._upload()
            self.assertEqual(relay.failed,failure in ('read','shutdown'))
            self.assertEqual(relay.stop.is_set(),relay.failed)
            self.assertEqual(connection.sendall.call_count,int(failure in ('none','shutdown')))
            if failure in ('none','shutdown'):self.assertEqual(events[:2],[('charged',3),('sent',b'abc')])
            if failure=='none':connection.shutdown.assert_called_once_with(socket.SHUT_WR)
            if failure=='credit':connection.shutdown.assert_not_called()

    def test_download_partial_writes_are_charged_once_and_cleanup_on_output_failure(self):
        for failure in ('none','credit','write'):
            for quick_ack in (False,True):
                events=[];connection=Mock();connection.recv.side_effect=[b'abc',b'']
                budget=Mock(chunk_size=1024);budget.take.side_effect=lambda count,stop:events.append(('charged',count)) or failure!='credit'
                port=SimpleNamespace(**vars(os))
                def write(fd,data):events.append(('write',data));return 0 if failure=='write' else min(2,len(data))
                port.write=write
                sockets=SimpleNamespace(**vars(socket))
                if quick_ack:sockets.TCP_QUICKACK=12
                elif hasattr(sockets,'TCP_QUICKACK'):del sockets.TCP_QUICKACK
                relay=tcp_proxy.TCPRelay(connection,budget)
                with patch.object(tcp_proxy,'os',port),patch.object(tcp_proxy,'socket',sockets),patch.object(tcp_proxy.threading,'Thread') as thread:
                    if failure=='write':
                        with self.assertRaisesRegex(OSError,'output closed'):relay.run()
                    else:self.assertEqual(relay.run(),0)
                thread.return_value.start.assert_called_once_with()
                self.assertTrue(relay.stop.is_set());connection.close.assert_called_once_with()
                if failure!='credit':self.assertEqual(events[0],('charged',3))
                if failure=='none':self.assertEqual(events,[('charged',3),('write',b'abc'),('write',b'c')])
                self.assertEqual(connection.setsockopt.call_count,int(quick_ack))


class RelayProgramBoundaryTests(unittest.TestCase):
    def test_produced_literal_request_preserves_all_typed_fields_without_legacy_parser(self):
        # The same wire contract must be exercised without a Linux-only SSH
        # fixture: a real encoded ProxyCommand still uses the bounded parser.
        options = Options(budget_dir=os.path.abspath('synthetic path%'),
                          bastion_concurrency=7, bastion_connect_rate=3.25,
                          bastion_memory_mib=96, bastion_bandwidth_kib=128,
                          connect_timeout=2.5, command_timeout=12)
        command = tcp_proxy.proxy_command(Host('one', port=2222), options, lifetime=7.25)
        encoded = command.rsplit(' ', 1)[-1]
        with patch.object(tcp_proxy, '_legacy_arguments', side_effect=AssertionError('unexpected legacy parser')):
            args = tcp_proxy._arguments(['--request', encoded])
        self.assertEqual(set(vars(args)), {'host', 'port', 'budget_root', 'connections', 'connect_rate',
                                          'memory_bytes', 'bandwidth_kib', 'connect_timeout', 'lifetime'})
        self.assertEqual(args.host, 'one')
        self.assertEqual(args.port, 2222)
        self.assertEqual(args.connections, 7)
        self.assertEqual(args.connect_rate, 3.25)
        self.assertEqual(args.memory_bytes, 96 * 1024**2)
        self.assertEqual(args.bandwidth_kib, 128)
        self.assertEqual(args.connect_timeout, 2.5)
        self.assertEqual(args.lifetime, 7.25)
        self.assertEqual(os.path.dirname(args.budget_root), options.budget_dir)
        self.assertRegex(os.path.basename(args.budget_root), r'^[0-9a-f]{32}$')
        for field in ('port', 'connections', 'memory_bytes', 'bandwidth_kib'):
            self.assertIs(type(getattr(args, field)), int)
        for field in ('connect_rate', 'connect_timeout', 'lifetime'):
            self.assertIs(type(getattr(args, field)), float)

    def test_utf8_configuration_limit_preserves_bounded_wire_and_rejects_excess(self):
        # Exercise a valid 4096-byte UTF-8 path and the existing refusal above
        # that boundary; do not bypass Options to manufacture an impossible input.
        options = Options(budget_dir='\u00e9' * 2048)
        command = tcp_proxy.proxy_command(Host('one'), options)
        encoded = command.rsplit(' ', 1)[-1]
        self.assertLessEqual(len(encoded), 32768)
        self.assertLessEqual(len(base64.urlsafe_b64decode(encoded)), 16384)
        args = tcp_proxy._arguments(['--request', encoded])
        self.assertEqual(os.path.dirname(args.budget_root), os.path.abspath(options.budget_dir))
        with self.assertRaisesRegex(ValueError, 'configuration paths must be literal and contain no controls'):
            Options(budget_dir='\u00e9' * 2049)

    def test_literal_legacy_arguments_and_wrong_request_container(self):
        arguments = ['--host', 'one']
        self.assertIs(tcp_proxy.request_arguments(arguments), arguments)
        for arguments in (['data', '--request'],
                          ['--request', base64.urlsafe_b64encode(b'[]').decode()]):
            with self.assertRaisesRegex(ValueError, 'invalid encrypted-byte request envelope'):
                tcp_proxy.request_arguments(arguments)

    def test_nonfinite_and_nonpositive_cli_deadlines_refuse_before_budget_or_connection(self):
        for field in ('connect_timeout', 'lifetime'):
            for duration in (float('nan'), float('inf'), 0, -1):
                args = SimpleNamespace(host='one', port=22, connect_timeout=1, lifetime=2)
                setattr(args, field, duration)
                with self.subTest(field=field, duration=duration), \
                        patch.object(tcp_proxy, '_arguments', return_value=args), \
                        patch.object(tcp_proxy, 'SQLiteByteBudget') as budget, \
                        patch.object(tcp_proxy.socket, 'create_connection') as connect, \
                        patch.object(tcp_proxy.os, 'write') as write:
                    self.assertEqual(tcp_proxy.main([]), 125)
                    budget.assert_not_called()
                    connect.assert_not_called()
                    self.assertEqual(write.call_args.args[0], 2)

    def test_main_initialization_failure_and_closed_stderr_preserve_nonzero_result(self):
        args=SimpleNamespace(host='one',port=22,connect_timeout=1,lifetime=2,budget_root='synthetic',
                             connections=1,connect_rate=1,memory_bytes=1024,bandwidth_kib=1)
        for failure in ('none','budget','connect','relay','run'):
            connection,budget,relay=Mock(),Mock(),Mock();relay.run.return_value=0
            if failure=='run':relay.run.side_effect=OSError('private relay error')
            port=SimpleNamespace(**vars(os));port.name='posix';port.write=Mock(side_effect=OSError('closed stderr'))
            with patch.object(tcp_proxy,'_arguments',return_value=args),patch.object(tcp_proxy,'os',port),\
                    patch.object(tcp_proxy,'SQLiteByteBudget',return_value=budget,side_effect=OSError('private') if failure=='budget' else None),\
                    patch.object(tcp_proxy.socket,'create_connection',return_value=connection,side_effect=OSError('private') if failure=='connect' else None),\
                    patch.object(tcp_proxy,'TCPRelay',return_value=relay,side_effect=OSError('private') if failure=='relay' else None),\
                    patch.object(tcp_proxy.threading,'Thread'):
                self.assertEqual(tcp_proxy.main([]),0 if failure=='none' else 125)
            self.assertEqual(connection.close.call_count,int(failure not in ('budget','connect')))
            self.assertEqual(budget.close.call_count,int(failure in ('connect','relay')))
            if failure!='none':
                self.assertEqual(port.write.call_args.args,(2,b'swassh: encrypted-byte relay failed; no direct connection fallback\n'))

    def test_windows_binary_mode_is_applied_only_through_an_injected_stdio_port(self):
        args=SimpleNamespace(host='one',port=22,connect_timeout=1,lifetime=2,budget_root='synthetic',
                             connections=1,connect_rate=1,memory_bytes=1024,bandwidth_kib=1)
        port=SimpleNamespace(**vars(os));port.name='nt';port.O_BINARY=0x8000
        stdio=SimpleNamespace(setmode=Mock());relay=Mock();relay.run.return_value=1
        with patch.object(tcp_proxy,'_arguments',return_value=args),patch.object(tcp_proxy,'os',port),\
                patch.dict(sys.modules,{'msvcrt':stdio}),patch.object(tcp_proxy,'SQLiteByteBudget'),\
                patch.object(tcp_proxy.socket,'create_connection'),patch.object(tcp_proxy,'TCPRelay',return_value=relay),\
                patch.object(tcp_proxy.threading,'Thread'):
            self.assertEqual(tcp_proxy.main([]),1)
        self.assertEqual([call.args for call in stdio.setmode.call_args_list],[(0,0x8000),(1,0x8000),(2,0x8000)])


if __name__=='__main__':unittest.main()
