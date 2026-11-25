"""Read-only resource probes against independent in-memory OS observations."""
import ctypes
import os
import sys
from pathlib import PurePosixPath
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

from swassh.infrastructure import resources,windows
from swassh import Host,HostProfile,Options


class LinuxObservationTests(unittest.TestCase):
    def test_descriptor_budget_uses_linux_live_count_through_readonly_ports(self):
        resource=SimpleNamespace(RLIMIT_NOFILE=7,RLIM_INFINITY=-1,getrlimit=Mock(return_value=(256,256)))
        system=SimpleNamespace(**vars(sys));system.platform='linux'
        kernel=SimpleNamespace(**vars(os));kernel.listdir=Mock(return_value=['0','1','2','3'])
        with patch.dict(sys.modules,{'resource':resource}),patch.object(resources,'sys',system),patch.object(resources,'os',kernel):
            self.assertEqual(resources._descriptor_workers(False),47)
        resource.getrlimit.assert_called_once_with(7);kernel.listdir.assert_called_once_with('/proc/self/fd')

    def test_jump_and_profile_key_memory_are_reserved_before_worker_count(self):
        direct=Options(memory_budget_mib=256,concurrency=1)
        jumped=Options(memory_budget_mib=256,concurrency=1,jump_host=Host('jump'))
        profiled=Options(host_profiles=(HostProfile('one',client_keys=('synthetic-key',)),))
        with patch.object(resources,'_available_memory',return_value=None),patch.object(resources,'_descriptor_workers',return_value=256):
            base=resources.resource_plan(direct,persistent_master=True)
            other=resources.resource_plan(jumped,persistent_master=True)
        self.assertEqual(other.estimated_worker_bytes-base.estimated_worker_bytes,8*1024**2)
        self.assertEqual(base.memory_budget_bytes-other.memory_budget_bytes,8*1024**2)
        self.assertEqual((base.workers,other.workers),(1,1))
        self.assertEqual(resources._profile_memory(profiled),4*1024**2)

    def probe(self,values):
        seen=[]
        class MemoryPath(PurePosixPath):
            def read_text(self):
                path=str(self);seen.append(path)
                value=values.get(path,OSError('unavailable observation'))
                if isinstance(value,Exception):raise value
                return value
        with patch.object(resources,'Path',MemoryPath):result=resources._linux_available_memory()
        return result,seen

    def test_meminfo_errors_are_unknown_and_never_use_total_memory(self):
        for content in (OSError('unavailable'),'not a key value','MemTotal: 123 kB','MemAvailable: invalid kB'):
            result,seen=self.probe({'/proc/meminfo':content})
            self.assertIsNone(result);self.assertEqual(seen,['/proc/meminfo'])

    def test_every_cgroup_ancestor_limits_available_memory_and_escape_is_never_read(self):
        basic={'/proc/meminfo':'MemTotal: 999999 kB\nMemAvailable: 100 kB',
               '/proc/self/cgroup':'2:cpu:/ignored\n0::/team/service',
               '/sys/fs/cgroup/team/service/memory.max':'10000','/sys/fs/cgroup/team/service/memory.current':'100',
               '/sys/fs/cgroup/team/memory.max':'9000','/sys/fs/cgroup/team/memory.current':'1000',
               '/sys/fs/cgroup/memory.max':'max','/sys/fs/cgroup/memory.current':'50000'}
        result,seen=self.probe(basic);self.assertEqual(result,8000)
        self.assertFalse(any(path.startswith('/sys/memory') or path.startswith('/memory') for path in seen))
        result,_=self.probe({**basic,'/sys/fs/cgroup/team/memory.current':'10000'});self.assertEqual(result,0)
        for member in ('0::/../escape','2:cpu:/unified-unavailable',OSError('membership unreadable')):
            result,seen=self.probe({**basic,'/proc/self/cgroup':member})
            self.assertEqual(result,102400)
            self.assertNotIn('/sys/fs/escape/memory.max',seen)
        for invalid in ('bad',OSError('denied')):
            result,_=self.probe({**basic,'/sys/fs/cgroup/team/memory.current':invalid})
            self.assertEqual(result,9900)

    def test_sysconf_rejects_each_noninteger_dimension_and_native_windows_loader_is_scoped(self):
        for values in ((1,True),(1,1.5),(1,'4096'),(True,4096),(-1,4096),(1,-1)):
            with patch.object(os,'sysconf',side_effect=values,create=True):self.assertIsNone(resources._sysconf_available_memory())
        library=object()
        with patch.object(windows,'os',SimpleNamespace(name='nt')),patch.object(ctypes,'WinDLL',return_value=library,create=True) as load:
            self.assertIs(windows.kernel32(),library)
        load.assert_called_once_with('kernel32',use_last_error=True)
        with patch.object(windows,'os',SimpleNamespace(name='posix')),self.assertRaises(OSError):windows.kernel32()
