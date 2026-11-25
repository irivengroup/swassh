"""Windows filesystem policy on both runtimes through memory kernel ports.

Real Win32 handle/DACL integration remains in the native Windows suites. These
tests verify the shared filesystem layer's ordering, names and error cleanup.
"""
import io
import os
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

from swassh.infrastructure import filesystem as fs,windows
from test_filesystem_contracts import MemoryDirectories


class WindowsFilesystemBoundaryTests(unittest.TestCase):
    def test_existing_nonprivate_pin_checks_ancestry_without_rewriting_its_acl(self):
        memory, events, handles, Handle = self.model()
        with memory.installed(), patch.object(windows, 'DirectoryHandle', Handle), \
                patch.object(windows, 'protect_directory') as protect:
            fs._trusted_directory(memory.Path('/safe/leaf'))
            with fs.PinnedDirectory('/safe/leaf', private=False) as directory:
                self.assertIsNone(directory.fd)
            protect.assert_not_called()
        self.assertEqual([handle.path for handle in handles], ['/', '/safe', '/safe/leaf'])
        self.assertTrue(all(handle.closed for handle in handles))

    def model(self):
        memory=MemoryDirectories();memory.os.name='nt';events=[];handles=[]
        memory.Path.mkdir=lambda path,mode=0o700:memory.mkdir(str(path),mode)
        def unlink(path):
            if str(path) not in memory.nodes:raise FileNotFoundError(str(path))
            events.append(('unlink',str(path)));del memory.nodes[str(path)]
        memory.Path.unlink=unlink
        def replace(source,destination):
            memory.nodes[str(destination)]=memory.nodes.pop(str(source));events.append(('replace',str(source),str(destination)))
        memory.os.replace=replace
        class Handle:
            def __init__(self,path):
                self.path=str(path);self.closed=False
                node=memory.nodes.get(self.path)
                if node is None or not stat.S_ISDIR(node.st_mode):raise ValueError('not a plain directory')
                events.append(('pin',self.path));handles.append(self)
            def close(self):self.closed=True;events.append(('close',self.path))
        return memory,events,handles,Handle

    def test_create_pins_and_protects_each_parent_before_creating_its_child(self):
        for raced in (False,True):
            memory,events,handles,Handle=self.model();memory.mkdir_race=raced
            original=memory.mkdir
            def mkdir(path,mode):events.append(('mkdir',str(path)));return original(path,mode)
            memory.Path.mkdir=lambda path,mode=0o700:mkdir(str(path),mode)
            with memory.installed(),patch.object(windows,'DirectoryHandle',Handle),\
                    patch.object(windows,'protect_directory',side_effect=lambda path:events.append(('protect',str(path)))):
                with fs.PinnedDirectory('/created/leaf',create=True,private=True) as directory:
                    self.assertIsNone(directory.fd)
                    self.assertLess(events.index(('protect','/created')),events.index(('mkdir','/created/leaf')))
                    self.assertEqual(events[-1],('protect','/created/leaf'))
                directory.close()
            self.assertTrue(all(handle.closed for handle in handles))
            self.assertEqual([event for event in events if event[0]=='close'],
                             [('close','/created/leaf'),('close','/created'),('close','/')])

    def test_pin_or_acl_failure_closes_all_acquired_ancestry_handles(self):
        for failure in ('pin','acl'):
            memory,events,handles,Handle=self.model()
            if failure=='pin':memory.add('/safe/leaf',stat.S_IFLNK|0o777,1000,'/safe')
            protect=Mock(side_effect=PermissionError('synthetic owner mismatch') if failure=='acl' else None)
            with memory.installed(),patch.object(windows,'DirectoryHandle',Handle),patch.object(windows,'protect_directory',protect):
                with self.assertRaises(ValueError if failure=='pin' else PermissionError):fs.PinnedDirectory('/safe/leaf',private=True)
            self.assertTrue(handles);self.assertTrue(all(handle.closed for handle in handles))

    def test_literal_entry_operations_refuse_streams_devices_and_trailing_aliases(self):
        memory,events,handles,Handle=self.model();memory.add('/safe/leaf/input',stat.S_IFREG|0o600)
        with memory.installed(),patch.object(windows,'DirectoryHandle',Handle),patch.object(windows,'protect_directory'),\
                patch.object(windows,'open_file_without_reparse',return_value=41) as open_file:
            with fs.PinnedDirectory('/safe/leaf',private=True) as directory:
                self.assertEqual(directory.open('input',os.O_RDONLY),41)
                self.assertEqual(str(open_file.call_args.args[0]),'/safe/leaf/input')
                for name in ('CON','aux.txt','COM1','LPT9.txt','file:stream','trailing.','trailing '):
                    with self.subTest(name=name),self.assertRaises(ValueError):directory.open(name,os.O_RDONLY)
                directory.replace('input','output');directory.unlink('output');directory.unlink('absent')
                self.assertNotIn('/safe/leaf/output',memory.nodes)
                self.assertIn(('replace','/safe/leaf/input','/safe/leaf/output'),events)
        self.assertTrue(all(handle.closed for handle in handles))

    def test_file_dacl_failure_closes_new_stream_and_unlinks_before_releasing_pin(self):
        events=[];stream=io.StringIO();directory=Mock(path='/synthetic')
        # A normal Path is required for the file-DACL boundary's child path.
        from pathlib import Path
        directory.path=Path('/synthetic');directory.open.return_value=41
        directory.unlink.side_effect=lambda name:events.append('unlink')
        directory.close.side_effect=lambda:events.append('close-pin')
        port=SimpleNamespace(**vars(os));port.name='nt';port.fdopen=Mock(return_value=stream);port.close=Mock()
        with patch.object(fs,'PinnedDirectory',return_value=directory),patch.object(fs,'os',port),\
                patch.object(windows,'protect_directory',side_effect=PermissionError('synthetic DACL failure')):
            with self.assertRaises(PermissionError):fs.AtomicOutput('/synthetic/report')
        self.assertTrue(stream.closed);self.assertEqual(events,['unlink','close-pin']);port.close.assert_not_called()


if __name__=='__main__':unittest.main()


class DirectoryMetadataReuseTests(unittest.TestCase):
    def test_ancestry_pins_reuse_the_native_layout_and_keep_live_type_checks(self):
        types = []
        attributes = [0x10, 0x410]
        kernel = SimpleNamespace(CreateFileW=Mock(return_value=41), CloseHandle=Mock(),
                                 GetFileInformationByHandle=Mock())
        def inspect(handle, pointer):
            types.append(type(pointer._obj))
            pointer._obj.attributes = attributes.pop(0)
            return 1
        kernel.GetFileInformationByHandle.side_effect = inspect
        with patch.object(windows, 'kernel32', return_value=kernel):
            handle = windows.DirectoryHandle('first')
            handle.close()
            with self.assertRaisesRegex(ValueError, 'plain directory'):
                windows.DirectoryHandle('second')
        self.assertIs(types[0], types[1], 'native schema was rebuilt inside the locked path')
        self.assertEqual(kernel.CloseHandle.call_args_list, [unittest.mock.call(41), unittest.mock.call(41)])
        for call in kernel.CreateFileW.call_args_list:
            self.assertEqual(call.args[1:6], (0x81, 3, None, 3, 0x02200000))
