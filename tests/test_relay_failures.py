"""Relay failures preserve byte order, pre-auth classification and ownership."""
import os
from pathlib import Path
import socket
import stat
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

from swassh.domain.endpoints import Endpoint
from swassh.infrastructure import socket_relay as relay_module
from swassh.infrastructure.socket_relay import GuardianRelay


class RelayBoundaryTests(unittest.TestCase):
    def test_safe_owned_connector_is_admitted_and_all_owned_resources_close(self):
        request = {'host': 'synthetic-target', 'port': 22, 'connect_timeout': 1,
                   'connector': str((Path.cwd() / 'synthetic-nc').absolute())}
        listener, budget, worker = Mock(), Mock(), Mock()
        listener.getsockname.return_value = ('127.0.0.1', 2222)
        worker.is_alive.return_value = False
        with patch.object(Path, 'stat', return_value=SimpleNamespace(st_mode=stat.S_IFREG | 0o700, st_uid=1000)), \
                patch.object(os, 'geteuid', return_value=1000, create=True), \
                patch.object(relay_module, 'SQLiteByteBudget', return_value=budget), \
                patch.object(relay_module.socket, 'socket', return_value=listener), \
                patch.object(relay_module.threading, 'Thread', return_value=worker):
            relay = GuardianRelay(request, object())
            self.assertEqual(relay.connector, request['connector'])
            relay.close()
        budget.close.assert_called_once()
        worker.start.assert_called_once()

    def test_stopping_during_forward_drops_remaining_bytes_without_claiming_a_wire_failure(self):
        for error in (False, True):
            relay = self.relay()
            source, destination = Mock(), Mock()
            source.recv.return_value = b'ab'
            sockets = SimpleNamespace(**vars(socket))
            sockets.__dict__.pop('TCP_QUICKACK', None)
            def send(data):
                relay.stop.set()
                if error:
                    raise OSError('synthetic stop race')
                return 1
            destination.send.side_effect = send
            with patch.object(relay_module, 'socket', sockets):
                relay._forward(source, destination)
            destination.send.assert_called_once_with(b'a')
            self.assertFalse(relay.failed.is_set())
            self.assertTrue(relay.stop.is_set())
            source.setsockopt.assert_not_called()

    @staticmethod
    def relay():
        relay=object.__new__(GuardianRelay)
        relay.stop=threading.Event();relay.failed=threading.Event();relay.connected=threading.Event()
        relay.connection_failure=None;relay.listener=Mock();relay.client=relay.remote=None
        relay.workers=[];relay.endpoint=Endpoint('synthetic-target',22);relay.timeout=1
        relay.budget=Mock(chunk_size=1024)
        relay.budget.chunks.side_effect=lambda data,stop:(data[:1],data[1:])
        return relay

    def test_request_schema_timeout_connector_and_listener_failures_are_explicit(self):
        valid={'host':'synthetic-target','port':22,'connect_timeout':1}
        invalid=(None,[],{}, {**valid,'extra':1}, {**valid,'connector':False},
                 {**valid,'connector':'relative'},*({**valid,'connect_timeout':v} for v in (True,'1',0,-1,float('nan'),float('inf'))))
        with patch.object(relay_module,'SQLiteByteBudget') as budget,patch.object(relay_module.socket,'socket') as create:
            for request in invalid:
                with self.subTest(request=request),self.assertRaises(ValueError):GuardianRelay(request,object())
            budget.assert_not_called();create.assert_not_called()
        for failure in ('socket','bind','listen','start'):
            listener=Mock();budget=Mock();worker=Mock()
            listener.getsockname.return_value=('127.0.0.1',12345)
            if failure in ('bind','listen'):getattr(listener,failure).side_effect=OSError(failure)
            if failure=='start':worker.start.side_effect=RuntimeError('start')
            with patch.object(relay_module,'SQLiteByteBudget',return_value=budget),patch.object(relay_module.socket,'socket',side_effect=OSError('socket') if failure=='socket' else None,return_value=listener),patch.object(relay_module.threading,'Thread',return_value=worker),self.assertRaises((OSError,RuntimeError)):
                GuardianRelay(valid,object())
            budget.close.assert_called_once()
            self.assertEqual(listener.close.call_count,int(failure!='socket'))
        for mode,uid in ((stat.S_IFDIR|0o700,0),(stat.S_IFREG|0o722,0),(stat.S_IFREG|0o700,2000)):
            with patch.object(Path,'stat',return_value=SimpleNamespace(st_mode=mode,st_uid=uid)),patch.object(os,'geteuid',return_value=1000,create=True),self.assertRaisesRegex(ValueError,'unsafe'):
                GuardianRelay({**valid,'connector':str((Path.cwd()/'synthetic-nc').absolute())},object())

    def test_accept_timeout_preconnect_classification_cancellation_and_upload_ownership(self):
        for failure in (TimeoutError('timeout'),ConnectionRefusedError('refused')):
            relay=self.relay();client=Mock();relay.listener.accept.side_effect=(TimeoutError(),(client,('127.0.0.1',1)))
            with patch.object(relay_module.socket,'create_connection',side_effect=failure):relay._accept()
            self.assertTrue(relay.failed.is_set());self.assertTrue(relay.stop.is_set())
            self.assertEqual(relay.connection_failure,'timeout' if isinstance(failure,TimeoutError) else 'unreachable')
            self.assertFalse(relay.connected.is_set());client.recv.assert_not_called()
        relay=self.relay();relay.stop.set()
        with patch.object(relay_module.socket,'create_connection') as connect:relay._accept()
        connect.assert_not_called();relay.listener.accept.assert_not_called()
        for cancel in (False,True):
            relay=self.relay();client=Mock();remote=Mock();worker=Mock()
            relay.listener.accept.return_value=(client,('127.0.0.1',1))
            def connect(*args,**kwargs):
                self.assertEqual(args,(('synthetic-target',22),));self.assertEqual(kwargs,{'timeout':1})
                if cancel:relay.stop.set()
                return remote
            with patch.object(relay_module.socket,'create_connection',side_effect=connect),patch.object(relay_module.threading,'Thread',return_value=worker),patch.object(relay,'_forward') as forward:
                relay._accept()
            self.assertEqual(relay.connected.is_set(),not cancel)
            if cancel:remote.close.assert_called_once();worker.start.assert_not_called();forward.assert_not_called()
            else:
                worker.start.assert_called_once();self.assertEqual(relay.workers,[worker]);forward.assert_called_once_with(remote,client)

    def test_forward_timeout_partial_write_eof_and_failure_never_reorder_or_replay_bytes(self):
        relay=self.relay();source=Mock();destination=Mock()
        source.recv.side_effect=(TimeoutError(),b'abc',b'')
        transmitted=bytearray();attempt=0
        def send(piece):
            nonlocal attempt
            attempt+=1
            if attempt==1:raise TimeoutError()
            transmitted.extend(piece[:1]);return 1
        destination.send.side_effect=send
        with patch.object(relay_module.socket,'TCP_QUICKACK',12,create=True):relay._forward(source,destination)
        self.assertEqual(bytes(transmitted),b'abc')
        relay.budget.idle.assert_called_once();destination.shutdown.assert_called_once_with(socket.SHUT_WR)
        self.assertFalse(relay.failed.is_set());source.setsockopt.assert_called_once_with(socket.IPPROTO_TCP,12,1)
        for error in (0,OSError('synthetic send error')):
            relay=self.relay();source=Mock();source.recv.return_value=b'x';destination=Mock()
            if isinstance(error,Exception):destination.send.side_effect=error
            else:destination.send.return_value=error
            relay._forward(source,destination)
            self.assertTrue(relay.failed.is_set());self.assertTrue(relay.stop.is_set())
        relay=self.relay();source=Mock();source.recv.side_effect=OSError('read')
        relay.stop.set();relay._forward(source,Mock());source.recv.assert_not_called()
        self.assertFalse(relay.failed.is_set())

    def test_close_bounds_join_and_retains_budget_if_any_worker_remains_alive(self):
        for alive in (False,True):
            relay=self.relay();relay.client=Mock();relay.remote=Mock();worker=Mock();worker.is_alive.return_value=alive;relay.workers=[worker]
            relay.client.shutdown.side_effect=OSError('already disconnected')
            if alive:
                with self.assertRaisesRegex(RuntimeError,'did not stop'):relay.close()
                relay.budget.close.assert_not_called()
            else:relay.close();relay.budget.close.assert_called_once()
            self.assertTrue(relay.stop.is_set());worker.join.assert_called_once_with(3.1)
            self.assertEqual(relay.client.close.call_count,1 if alive else 2)
            self.assertEqual(relay.remote.close.call_count,1 if alive else 2)
