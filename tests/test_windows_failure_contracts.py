"""Win32 failure contracts with memory-only ABI ports on every test host.

These ports never create a job, change a DACL, or open a process on the host.
Native Windows integration remains required separately for real ABI behavior.
"""
import contextlib
import ctypes
import os
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

from swassh.infrastructure import windows


@contextlib.contextmanager
def error_port():
    with patch.object(ctypes,'WinError',side_effect=lambda code:OSError(code,'synthetic Win32 error'),create=True),patch.object(ctypes,'get_last_error',return_value=5,create=True):
        yield


class Win32OwnershipUnitTests(unittest.TestCase):
    def test_parent_without_expected_identity_still_records_and_closes_the_real_query_result(self):
        kernel = Mock()
        kernel.OpenProcess.return_value = 24
        def times(handle, created, *others):
            created._obj.dwHighDateTime = 3
            created._obj.dwLowDateTime = 17
            return True
        kernel.GetProcessTimes.side_effect = times
        with patch.object(windows, 'kernel32', return_value=kernel), error_port():
            parent = windows.ParentProcess(123)
            self.assertEqual(parent.token, (3 << 32) | 17)
            parent.close()
        kernel.CloseHandle.assert_called_once_with(24)

    def test_job_configuration_fails_closed_and_never_enables_breakaway(self):
        for failure in (None,'create','limits','assign'):
            kernel=Mock();kernel.CreateJobObjectW.return_value=0 if failure=='create' else 24
            kernel.GetCurrentProcess.return_value=32
            limits=[]
            def set_limits(handle,kind,pointer,size):
                limits.append((handle,kind,pointer._obj.basic.flags,size));return failure!='limits'
            kernel.SetInformationJobObject.side_effect=set_limits
            kernel.AssignProcessToJobObject.return_value=failure!='assign'
            with patch.object(windows,'kernel32',return_value=kernel),error_port():
                if failure:
                    with self.assertRaises(OSError):windows.KillJob()
                else:
                    job=windows.KillJob()
                    self.assertEqual(job.handle,24)
                    kernel.CloseHandle.assert_not_called()
                    kernel.TerminateJobObject.return_value=0
                    with self.assertRaises(OSError):job.terminate(125)
                    kernel.TerminateJobObject.return_value=1
                    fake_os=SimpleNamespace(_exit=Mock())
                    with patch.object(windows,'os',fake_os):job.terminate(125)
                    fake_os._exit.assert_called_once_with(125)
                    kernel.CloseHandle.assert_not_called()
            kernel.CreateJobObjectW.assert_called_once_with(None,None)
            if failure!='create':self.assertEqual(limits[0][:3],(24,9,0x2000))
            self.assertEqual(kernel.CloseHandle.call_count,int(failure in ('limits','assign')))

    def test_parent_creation_identity_wait_states_and_failed_queries_release_handles(self):
        for failure in (None,'open','times','identity'):
            kernel=Mock();kernel.OpenProcess.return_value=0 if failure=='open' else 24
            def times(handle,created,*others):
                created._obj.dwHighDateTime=3;created._obj.dwLowDateTime=17
                return failure!='times'
            kernel.GetProcessTimes.side_effect=times
            with patch.object(windows,'kernel32',return_value=kernel),error_port():
                if failure:
                    with self.assertRaises(ValueError if failure=='identity' else OSError):windows.ParentProcess(123,0 if failure=='identity' else None)
                else:
                    parent=windows.ParentProcess(123,(3<<32)|17)
                    for state,expected in ((0x102,True),(0,False)):
                        kernel.WaitForSingleObject.return_value=state;self.assertIs(parent.alive(),expected)
                    kernel.WaitForSingleObject.return_value=0xFFFFFFFF
                    with self.assertRaises(OSError):parent.alive()
                    parent.close();parent.close();self.assertIsNone(parent.handle)
            self.assertEqual(kernel.CloseHandle.call_count,int(failure!='open'))
            kernel.OpenProcess.assert_called_once_with(0x101000,False,123)

    def test_directory_pinning_refuses_reparse_or_non_directory_and_denies_share_delete(self):
        for outcome in ('ready','create','query','file','reparse'):
            kernel=Mock();kernel.CreateFileW.return_value=ctypes.c_void_p(-1).value if outcome=='create' else 24
            def information(handle,pointer):
                pointer._obj.attributes=0 if outcome=='file' else 0x410 if outcome=='reparse' else 0x10
                return outcome!='query'
            kernel.GetFileInformationByHandle.side_effect=information
            with patch.object(windows,'kernel32',return_value=kernel),error_port():
                if outcome=='ready':directory=windows.DirectoryHandle('synthetic-path');directory.close();directory.close()
                else:
                    with self.assertRaises(ValueError if outcome in ('file','reparse') else OSError):windows.DirectoryHandle('synthetic-path')
            args=kernel.CreateFileW.call_args.args
            self.assertEqual((args[1],args[2],args[4],args[5]),(0x81,3,3,0x02200000))
            self.assertEqual(kernel.CloseHandle.call_count,int(outcome!='create'))


class Win32DACLUnitTests(unittest.TestCase):
    def test_every_acl_stage_releases_allocations_and_never_protects_a_foreign_owner(self):
        stages=(None,'token','information','owner','foreign','sid','descriptor','publish')
        for failure in stages:
            with self.subTest(failure=failure):
                kernel=Mock();kernel.GetCurrentProcess.return_value=32;advapi=Mock();sddl=[]
                def token(process,access,pointer):
                    if failure!='token':pointer._obj.value=24
                    return failure!='token'
                def information(handle,kind,buffer,size,out_size):
                    out_size._obj.value=32
                    if buffer is None:return 0
                    ctypes.cast(buffer,ctypes.POINTER(ctypes.c_void_p)).contents.value=101
                    return failure!='information'
                def owner(path,kind,flags,pointer,*others):
                    pointer._obj.value=101;others[-1]._obj.value=202
                    return 5 if failure=='owner' else 0
                def sid(value,pointer):
                    if failure!='sid':pointer._obj.value='S-1-5-21-synthetic'
                    return failure!='sid'
                def descriptor(value,version,pointer,reserved):
                    sddl.append(value)
                    if failure!='descriptor':pointer._obj.value=303
                    return failure!='descriptor'
                advapi.OpenProcessToken.side_effect=token
                advapi.GetTokenInformation.side_effect=information
                advapi.GetNamedSecurityInfoW.side_effect=owner
                advapi.EqualSid.return_value=failure!='foreign'
                advapi.ConvertSidToStringSidW.side_effect=sid
                advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.side_effect=descriptor
                advapi.SetFileSecurityW.return_value=failure!='publish'
                with patch.object(windows,'kernel32',return_value=kernel),patch.object(ctypes,'WinDLL',return_value=advapi,create=True),error_port():
                    if failure:
                        with self.assertRaises(ValueError if failure=='foreign' else OSError):windows.protect_directory('synthetic-path')
                    else:windows.protect_directory('synthetic-path')
                self.assertEqual(kernel.CloseHandle.call_count,int(failure!='token'))
                if failure in (None,'descriptor','publish'):
                    self.assertEqual(sddl,['D:P(A;OICI;FA;;;S-1-5-21-synthetic)(A;OICI;FA;;;SY)'])
                allocations=0 if failure in ('token','information') else 1 if failure in ('owner','foreign','sid') else 2 if failure=='descriptor' else 3
                self.assertEqual(kernel.LocalFree.call_count,allocations)
                if failure not in (None,'publish'):advapi.SetFileSecurityW.assert_not_called()
                else:self.assertEqual(advapi.SetFileSecurityW.call_args.args[1],0x80000004)


class Win32FileDescriptorUnitTests(unittest.TestCase):
    def test_live_file_metadata_keeps_link_and_type_refusals_without_read_access(self):
        for outcome in ('ready', 'create', 'query', 'non-disk', 'directory', 'reparse', 'hardlink'):
            kernel = Mock()
            kernel.CreateFileW.return_value = ctypes.c_void_p(-1).value if outcome == 'create' else 24
            kernel.GetFileType.return_value = 3 if outcome == 'non-disk' else 1
            def information(handle, pointer):
                self.assertEqual(ctypes.sizeof(pointer._obj), 52)
                pointer._obj.attributes = 0x10 if outcome == 'directory' else 0x400 if outcome == 'reparse' else 0x20
                pointer._obj.links = 2 if outcome == 'hardlink' else 1
                pointer._obj.size_high, pointer._obj.size_low = 1, 17
                return outcome != 'query'
            kernel.GetFileInformationByHandle.side_effect = information
            with self.subTest(outcome=outcome), patch.object(windows, 'kernel32', return_value=kernel), error_port():
                if outcome == 'ready':
                    self.assertEqual(windows.regular_file_size('synthetic'), (1 << 32) | 17)
                else:
                    with self.assertRaises(OSError if outcome in ('create', 'query') else ValueError):
                        windows.regular_file_size('synthetic')
            self.assertEqual(kernel.CreateFileW.call_args.args, ('synthetic', 0, 3, None, 3, 0x02200000, None))
            self.assertEqual(kernel.CloseHandle.call_count, int(outcome != 'create'))

    def test_handle_is_closed_on_failure_and_transferred_only_after_plain_file_validation(self):
        fake_os=SimpleNamespace(**vars(os));fake_os.O_BINARY=getattr(os,'O_BINARY',0x8000)
        for outcome in ('ready','create','query','directory','reparse','fd-transfer'):
            for flags,access,disposition in ((os.O_RDONLY,0x80000000,3),(os.O_WRONLY|os.O_CREAT|os.O_EXCL,0x40000000,1),(os.O_RDWR|os.O_CREAT,0xC0000000,4)):
                kernel=Mock();kernel.CreateFileW.return_value=ctypes.c_void_p(-1).value if outcome=='create' else 24
                def information(handle,buffer):
                    self.assertEqual(ctypes.sizeof(buffer),52)
                    ctypes.cast(buffer,ctypes.POINTER(windows.wintypes.DWORD)).contents.value=0x10 if outcome=='directory' else 0x400 if outcome=='reparse' else 0
                    return outcome!='query'
                kernel.GetFileInformationByHandle.side_effect=information
                crt=SimpleNamespace(open_osfhandle=Mock(side_effect=OSError('fd-transfer') if outcome=='fd-transfer' else None,return_value=42))
                with patch.object(windows,'kernel32',return_value=kernel),patch.object(windows,'os',fake_os),patch.dict(sys.modules,{'msvcrt':crt}),error_port():
                    if outcome=='ready':self.assertEqual(windows.open_file_without_reparse('synthetic-path',flags),42)
                    else:
                        with self.assertRaises(ValueError if outcome in ('directory','reparse') else OSError):windows.open_file_without_reparse('synthetic-path',flags)
                args=kernel.CreateFileW.call_args.args
                self.assertEqual((args[1],args[2],args[4],args[5]),(access,3,disposition,0x00200000))
                self.assertEqual(kernel.CloseHandle.call_count,int(outcome not in ('ready','create')))
                if outcome=='ready':crt.open_osfhandle.assert_called_once_with(24,flags|fake_os.O_BINARY)
