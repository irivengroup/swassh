"""Independent byte-delivery oracle, durable rights and reversible migration."""
import json
import os
import random
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from swassh import Options
from swassh.domain.byte_credits import CreditPool
from swassh.infrastructure.bandwidth import SQLiteByteBudget
from swassh.infrastructure.bastion import specification
from swassh.infrastructure.database.migration.encrypted_bytes_v2 import EncryptedByteSchema,APPLICATION_ID

N=10**9


class CreditPoolTests(unittest.TestCase):
    def test_unreported_or_pending_rights_cannot_be_refilled_as_another_burst(self):
        pool=CreditPool(1024,1024*N,0).settle(granted=1024)
        later=pool.refill(100*N)
        self.assertEqual((later.credits,later.outstanding),(0,1024))
        forfeited=later.settle(consumed=1024)
        self.assertEqual((forfeited.credits,forfeited.outstanding),(0,0))
        _,wait=forfeited.debit(1)
        self.assertGreater(wait,0)
        returned=later.settle(returned=1024)
        self.assertEqual((returned.credits,returned.outstanding),(1024*N,0))
        regressed=returned.refill(0)
        self.assertEqual(regressed.credits,0)

    def test_invalid_state_time_and_settlement_are_refused(self):
        for changes in ({'outstanding':True},{'outstanding':-1},{'outstanding':1025},
                        {'credits':1024*N,'outstanding':1}):
            with self.subTest(changes=changes),self.assertRaises(ValueError):
                CreditPool(**dict({'rate':1024,'credits':0,'observed':0},**changes))
        pool=CreditPool(1024,512*N,0,512)
        for now in (True,-1,2**63,'0'):
            with self.subTest(now=now),self.assertRaises(ValueError):pool.refill(now)
        for changes in ({'consumed':True},{'returned':-1},{'granted':513},
                        {'consumed':513},{'consumed':500,'returned':13}):
            with self.subTest(changes=changes),self.assertRaises(ValueError):pool.settle(**changes)
        for count in (True,0,1025,'1'):
            with self.subTest(count=count),self.assertRaises(ValueError):pool.debit(count)
        debited,wait=CreditPool(1024,1024*N,0).debit(1024)
        self.assertEqual((debited.credits,wait),(0,0))

    def test_seeded_delayed_writes_refunds_and_dead_owners_obey_a_separate_oracle(self):
        for rate in (1024,32768,10485760):
            generator=random.Random(90210+rate)
            burst=min(16384,rate)
            pool=CreditPool(rate,burst*N,0)
            clients=[dict(remaining=0,pending=0,completed=0) for _ in range(8)]
            oracle=burst*N;oracle_time=now=delivered=0
            for event in range(5000):
                now+=generator.randrange(1000001)
                owner=generator.choice(clients);action=generator.randrange(5)
                if action==0 and owner['remaining']:
                    count=generator.randrange(1,owner['remaining']+1)
                    owner['remaining']-=count;owner['pending']+=count
                elif action==1 and owner['pending']:
                    count=generator.randrange(1,owner['pending']+1)
                    # The oracle observes ONLY actual delivery and elapsed
                    # time; it has no knowledge of credit grants or refunds.
                    oracle=min(burst*N,oracle+(now-oracle_time)*rate)
                    oracle_time=now
                    self.assertGreaterEqual(oracle,count*N,(rate,event))
                    oracle-=count*N;delivered+=count
                    owner['pending']-=count;owner['completed']+=count
                else:
                    pool=pool.refill(now)
                    consumed=owner['completed'];returned=owner['remaining'] if action==3 else 0
                    if action==4:
                        consumed=sum(owner.values());returned=0
                        owner.update(remaining=0,pending=0,completed=0)
                    else:
                        owner['completed']=0;owner['remaining']-=returned
                    pool=pool.settle(consumed=consumed,returned=returned)
                    desired=generator.randrange(1,burst+1) if action==2 else 0
                    granted=min(desired,pool.credits//N)
                    pool=pool.settle(granted=granted)
                    owner['remaining']+=granted
                self.assertEqual(pool.outstanding,sum(sum(client.values()) for client in clients))
                self.assertLessEqual(pool.credits+pool.outstanding*N,burst*N)
            self.assertGreater(delivered,0)


class CreditLedgerIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.options=Options(budget_dir=self.temporary.name,bastion_bandwidth_kib=1)
        self.clock=patch('swassh.infrastructure.bandwidth.time.monotonic_ns',return_value=0)
        self.clock.start();self.addCleanup(self.clock.stop)
        self.budget=SQLiteByteBudget(specification(self.options))
        self.addCleanup(self.budget.close)

    def test_pending_write_holds_capacity_and_idle_returns_only_never_issued_bytes(self):
        iterator=self.budget.chunks(b'0123456789',threading.Event())
        self.assertEqual(next(iterator),b'0123456789')
        self.assertEqual(self.budget.pending,10)
        with self.assertRaisesRegex(ValueError,'writes still pending'):self.budget.close()
        other=SQLiteByteBudget(specification(self.options));self.addCleanup(other.close)
        self.assertGreater(other.reserve(1024,now=0),0)
        with self.assertRaises(StopIteration):next(iterator)
        self.budget.idle()
        self.assertEqual((self.budget.pending,self.budget.remaining,self.budget.spent),(0,0,0))
        self.assertEqual(other.reserve(1014,now=0),0)
        self.assertGreater(other.reserve(1,now=0),0)

    def test_abandoned_write_is_fully_charged_and_unused_close_rights_are_forfeited(self):
        iterator=self.budget.chunks(b'0123456789',threading.Event())
        self.assertEqual(next(iterator),b'0123456789')
        iterator.close()
        self.assertEqual(self.budget.pending,0)
        self.budget.close();self.budget.close()
        other=SQLiteByteBudget(specification(self.options))
        try:
            self.assertGreater(other.reserve(1,now=0),0)
            self.assertEqual(other.reserve(1024,now=N),0)
        finally:other.close()

    def test_dead_process_rights_are_forfeited_without_recreating_a_free_burst(self):
        code='''import json,os,sys,threading
from swassh.infrastructure import bandwidth
bandwidth.time.monotonic_ns=lambda:0
budget=bandwidth.SQLiteByteBudget(json.loads(sys.argv[1]))
iterator=budget.chunks(b"uncertain",threading.Event())
assert next(iterator)==b"uncertain"
os._exit(37)
'''
        child=subprocess.run([sys.executable,'-c',code,json.dumps(specification(self.options))],
                             capture_output=True,timeout=10)
        self.assertEqual(child.returncode,37,child.stderr.decode())
        self.assertGreater(self.budget.reserve(1,now=0),0)
        self.assertEqual(self.budget.db.execute('SELECT COUNT(*) FROM byte_leases').fetchone()[0],0)
        self.assertEqual(self.budget.reserve(1024,now=N),0)

    def test_invalid_owner_or_changed_counters_stop_further_credit_use(self):
        iterator=self.budget.chunks(b'one',threading.Event())
        self.assertEqual(next(iterator),b'one')
        with self.assertRaises(StopIteration):next(iterator)
        identity=self.budget.credit_owner[0]
        self.budget.db.execute('UPDATE byte_leases SET amount=0 WHERE id=?',(identity,))
        with self.assertRaises(ValueError):self.budget.idle()
        with self.assertRaisesRegex(ValueError,'owner unavailable'):
            next(self.budget.chunks(b'two',threading.Event()))


class EncryptedByteMigrationIntegrationTests(unittest.TestCase):
    def test_upgrade_and_downgrade_preserve_old_committed_counters(self):
        db=sqlite3.connect(':memory:',isolation_level=None);self.addCleanup(db.close)
        db.execute('CREATE TABLE bucket (id INTEGER PRIMARY KEY,rate INTEGER,credits INTEGER,observed INTEGER)')
        db.execute('INSERT INTO bucket VALUES (1,1024,512000000000,17)')
        db.execute('PRAGMA application_id='+str(APPLICATION_ID));db.execute('PRAGMA user_version=1')
        before=db.execute('SELECT * FROM bucket').fetchall()
        db.execute('BEGIN');EncryptedByteSchema.up(db);db.commit()
        self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0],2)
        self.assertEqual(db.execute('SELECT * FROM bucket').fetchall(),before)
        db.execute('BEGIN');EncryptedByteSchema.down(db);db.commit()
        self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0],1)
        self.assertEqual(db.execute('SELECT * FROM bucket').fetchall(),before)

    def test_live_owner_and_unknown_schema_are_never_discarded(self):
        db=sqlite3.connect(':memory:',isolation_level=None);self.addCleanup(db.close)
        EncryptedByteSchema.up(db)
        db.execute('INSERT INTO byte_leases VALUES (?,1)',('a'*32,))
        with self.assertRaisesRegex(ValueError,'cannot downgrade'):EncryptedByteSchema.down(db)
        self.assertEqual(db.execute('SELECT amount FROM byte_leases').fetchone()[0],1)
        db.execute('CREATE TABLE unrecognized (value)')
        with self.assertRaisesRegex(ValueError,'invalid encrypted-byte'):EncryptedByteSchema.up(db)
