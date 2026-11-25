"""Rate eligibility hints never grant admission or bypass FIFO/capacity.

SQLite cases use isolated integration state. The guardian case uses only
memory ports: no signal, process, file or network operation reaches the host.
"""
import io
import json
import os
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import MagicMock, Mock, patch

from swassh import Options
from swassh.infrastructure import bastion,process_guard as guard


class AdmissionHintIntegrationTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.clock=patch.object(bastion.time,'monotonic',return_value=10.)
        self.now=self.clock.start();self.addCleanup(self.clock.stop)
        self.directory=temporary.name;self.leases=[]
    def pool(self,**settings):
        pool=bastion.SharedBudget(bastion.specification(Options(budget_dir=self.directory,**settings)))
        self.addCleanup(pool.close);self.addCleanup(self.close_leases)
        return pool
    def close_leases(self):
        while self.leases:self.leases.pop().close()
    def ticket(self,pool):
        lease=pool.ticket(connections=1,activate=True);self.leases.append(lease);return lease

    def test_head_waits_exact_remaining_rate_interval_without_admitting_early(self):
        pool=self.pool(bastion_connect_rate=20)
        first=self.ticket(pool);self.assertTrue(first.poll())
        self.now.return_value=10.029
        second=self.ticket(pool)
        self.assertFalse(second.poll());self.assertAlmostEqual(second.retry_after,.021)
        self.assertEqual(pool.db.execute('SELECT SUM(active) FROM leases').fetchone()[0],1)
        self.assertAlmostEqual(pool.db.execute('SELECT next FROM policy').fetchone()[0],10.05)
        self.now.return_value=10.049
        self.assertFalse(second.poll());self.assertAlmostEqual(second.retry_after,.001)
        self.now.return_value=10.05
        self.assertTrue(second.poll())
        self.assertEqual(pool.db.execute('SELECT SUM(active) FROM leases').fetchone()[0],2)
        self.assertAlmostEqual(pool.db.execute('SELECT next FROM policy').fetchone()[0],10.10)

    def test_capacity_and_fifo_blocked_owners_keep_conservative_poll_bound(self):
        pool=self.pool(bastion_concurrency=1,bastion_connect_rate=20)
        first=self.ticket(pool);second=self.ticket(pool);third=self.ticket(pool)
        self.assertFalse(second.poll());self.assertEqual(second.retry_after,.05)
        self.assertFalse(third.poll());self.assertEqual(third.retry_after,.05)
        first.close();self.leases.remove(first);self.now.return_value=10.05
        self.assertFalse(third.poll());self.assertEqual(third.retry_after,.05)
        self.assertTrue(second.poll());second.close();self.leases.remove(second)
        self.now.return_value=10.07
        self.assertFalse(third.poll());self.assertAlmostEqual(third.retry_after,.03)

    def test_long_or_expired_rate_hint_is_bounded_and_is_not_a_grant(self):
        pool=self.pool(bastion_connect_rate=.1)
        self.ticket(pool);second=self.ticket(pool)
        self.assertFalse(second.poll());self.assertEqual(second.retry_after,.05)
        self.now.return_value=21.
        self.assertEqual(second.retry_after,.001)
        self.assertEqual(pool.db.execute('SELECT active FROM leases WHERE id=?',(second.identity,)).fetchone()[0],0)
        self.assertTrue(second.poll())


class GuardianPollHintTests(unittest.TestCase):
    def test_guardian_uses_validated_remaining_interval_and_retains_cleanup(self):
        lease=Mock(retry_after=.021);lease.poll.side_effect=[False,False,True]
        pool=Mock();pool.ticket.return_value=lease
        process=Mock(returncode=0);process.poll.return_value=0
        request={'argv':['synthetic-client'],'budget':{},'connections':1,'bandwidth':1,
                 'parent_pid':123,'parent_token':None,'parent_fd':7,'invocation':None}
        filesystem=MagicMock();filesystem.return_value.parent.__truediv__.return_value.open.return_value=io.StringIO()
        kernel=SimpleNamespace(**vars(os));kernel.name='posix'
        with patch('builtins.open',return_value=io.BytesIO(json.dumps(request).encode())),\
             patch.object(guard,'Path',filesystem),patch.object(guard,'os',kernel),\
             patch.object(guard.signal,'SIGWINCH',28,create=True),\
             patch.object(guard.signal,'signal'),patch.object(guard.select,'select',return_value=([],[],[])),\
             patch.object(guard,'SharedBudget',return_value=pool),patch.object(guard.subprocess,'Popen',return_value=process),\
             patch.object(guard,'_stop_native') as stop,patch.object(guard.time,'sleep') as sleep:
            self.assertEqual(guard.main('memory-request'),0)
        self.assertEqual([call.args[0] for call in sleep.call_args_list],[.021,.021])
        stop.assert_called_once_with(process);lease.close.assert_called_once();pool.close.assert_called_once()
