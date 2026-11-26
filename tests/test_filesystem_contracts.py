"""Descriptor-boundary unit contracts, including POSIX failures on Windows.

The memory OS implements descriptor identity independently of path text. Native
filesystem integration remains in the existing platform suites; these tests
inject races and kernel errors that cannot be scheduled reliably there.
"""
import contextlib
import errno
import io
import os
from pathlib import PurePosixPath
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import tempfile
import threading

from swassh.infrastructure import filesystem as fs


class DarwinCreationContractTests(unittest.TestCase):
    """Model the observed openat ENOENT while retaining every refusal boundary."""

    def setUp(self):
        self.directory = object.__new__(fs.PinnedDirectory)
        self.directory.fd = 41
        self.flags = os.O_CREAT | os.O_APPEND | os.O_WRONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)

    @contextlib.contextmanager
    def kernel(self, operation, platform='darwin'):
        port = SimpleNamespace(**vars(os))
        port.name = 'posix'
        port.open = Mock(side_effect=operation)
        # The saved predecessor has no sys import. Injecting this module port
        # there keeps its failure attributable to the actual open operation.
        with patch.object(fs, 'os', port), patch.object(fs, 'sys', SimpleNamespace(platform=platform), create=True):
            yield port.open

    def test_concurrent_creator_and_existing_opener_avoid_observed_enoent(self):
        for exists in (False, True):
            calls = []

            def operation(name, flags, mode, *, dir_fd):
                calls.append((name, flags, mode, dir_fd))
                if flags & os.O_CREAT:
                    if not flags & os.O_EXCL:
                        raise FileNotFoundError(errno.ENOENT, 'observed concurrent openat creation failure', name)
                    if exists:
                        raise FileExistsError(errno.EEXIST, 'another creator won', name)
                return 61

            with self.subTest(existing=exists), self.kernel(operation):
                self.assertEqual(self.directory.open('budget.sqlite3', self.flags), 61)
                expected = [('budget.sqlite3', self.flags | os.O_EXCL, 0o600, 41)]
                if exists:
                    expected.append(('budget.sqlite3', self.flags & ~os.O_CREAT, 0o600, 41))
                self.assertEqual(calls, expected)

    def test_explicit_exclusivity_is_preserved_with_no_existing_open(self):
        error = FileExistsError(errno.EEXIST, 'already exists')
        with self.kernel(error) as operation, self.assertRaises(FileExistsError) as caught:
            self.directory.open('entry', self.flags | os.O_EXCL, 0o640)
        self.assertIs(caught.exception, error)
        operation.assert_called_once_with('entry', self.flags | os.O_EXCL, 0o640, dir_fd=41)

    def test_other_platforms_and_non_creating_opens_remain_single_operations(self):
        for platform, flags in (('linux', self.flags), ('win32', self.flags), ('darwin', self.flags & ~os.O_CREAT)):
            with self.subTest(platform=platform, flags=flags), self.kernel(lambda *args, **kwargs: 62, platform) as operation:
                self.assertEqual(self.directory.open('entry', flags, 0o640), 62)
                operation.assert_called_once_with('entry', flags, 0o640, dir_fd=41)

    def test_creation_errors_are_not_retried_or_hidden(self):
        for error in (PermissionError(errno.EACCES, 'denied'), FileNotFoundError(errno.ENOENT, 'missing parent'), OSError(errno.EIO, 'storage failure')):
            with self.subTest(error=error), self.kernel(error) as operation, self.assertRaises(OSError) as caught:
                self.directory.open('entry', self.flags)
            self.assertIs(caught.exception, error)
            operation.assert_called_once_with('entry', self.flags | os.O_EXCL, 0o600, dir_fd=41)

    def test_existing_open_errors_never_recreate_or_follow_an_entry(self):
        for error in (OSError(errno.ELOOP, 'link'), PermissionError(errno.EACCES, 'denied'), FileNotFoundError(errno.ENOENT, 'removed'), OSError(errno.EIO, 'storage failure')):
            with self.subTest(error=error), self.kernel([FileExistsError(errno.EEXIST, 'exists'), error]) as operation, self.assertRaises(OSError) as caught:
                self.directory.open('entry', self.flags)
            self.assertIs(caught.exception, error)
            self.assertEqual(operation.call_args_list, [unittest.mock.call('entry', self.flags | os.O_EXCL, 0o600, dir_fd=41),
                                                       unittest.mock.call('entry', self.flags & ~os.O_CREAT, 0o600, dir_fd=41)])

    def test_invalid_names_are_rejected_before_any_syscall(self):
        for name in ('', '.', '..', 'outside/entry', 'outside\\entry', None):
            with self.subTest(name=name), self.kernel(None) as operation, self.assertRaisesRegex(ValueError, 'literal directory entry'):
                self.directory.open(name, self.flags)
            operation.assert_not_called()


@unittest.skipUnless(os.name == 'posix', 'Native descriptor and link semantics require POSIX')
class DarwinCreationFilesystemTests(unittest.TestCase):
    """Exercise the creation protocol with real private files and hostile entries."""

    def test_concurrent_appenders_share_one_private_inode(self):
        with tempfile.TemporaryDirectory(prefix='swassh-create-race-') as temporary, patch.object(fs, 'sys', SimpleNamespace(platform='darwin')):
            root = Path(temporary).resolve(strict=True)
            with fs.PinnedDirectory(root) as directory, ThreadPoolExecutor(max_workers=4) as pool:
                for index in range(16):
                    barrier = threading.Barrier(4)
                    destination = root / f'budget-{index}.sqlite3'

                    def append():
                        barrier.wait(timeout=5)
                        with fs.open_private_append(destination, directory=directory) as stream:
                            info = os.fstat(stream.fileno())
                            stream.write('x')
                            return info.st_dev, info.st_ino, info.st_uid, info.st_nlink, stat.S_IMODE(info.st_mode)

                    identities = [future.result(timeout=10) for future in [pool.submit(append) for _ in range(4)]]
                    self.assertEqual(len(set(identities)), 1)
                    self.assertEqual(identities[0][2:], (os.geteuid(), 1, 0o600))
                    self.assertEqual(destination.read_bytes(), b'xxxx')

    def test_links_and_special_files_still_refuse_without_modifying_targets(self):
        with tempfile.TemporaryDirectory(prefix='swassh-create-boundary-') as temporary, patch.object(fs, 'sys', SimpleNamespace(platform='darwin')):
            root = Path(temporary).resolve(strict=True)
            target = root / 'untouched'
            target.write_bytes(b'original')
            target.chmod(0o640)
            target_before = target.stat()
            (root / 'link').symlink_to(target)
            (root / 'dangling').symlink_to(root / 'absent')
            os.link(target, root / 'hardlink')
            os.mkfifo(root / 'fifo', 0o600)
            with fs.PinnedDirectory(root) as directory:
                for name in ('link', 'dangling', 'hardlink', 'fifo'):
                    with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'regular file'):
                        fs.open_private_append(root / name, directory=directory)
            self.assertEqual(target.read_bytes(), b'original')
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o640)
            self.assertEqual(target.stat().st_ino, target_before.st_ino)
            self.assertFalse((root / 'absent').exists())


class MemoryDirectories:
    def __init__(self):
        self.nodes={};self.descriptors={};self.closed=[];self.chmods=[];self.synced=[];self.next_fd=10
        self.after_open=None;self.after_stat=None;self.mkdir_race=False;self.sync_error=None
        self.add('/',stat.S_IFDIR|0o755,0)
        self.add('/safe',stat.S_IFDIR|0o700,1000)
        self.add('/safe/leaf',stat.S_IFDIR|0o700,1000)
        self.os=SimpleNamespace(**vars(os))
        self.os.__dict__.update(name='posix',geteuid=lambda:1000,open=self.open,close=self.close,
            fstat=self.fstat,stat=self.stat,mkdir=self.mkdir,readlink=self.readlink,fchmod=self.chmod,
            fsync=self.sync,O_DIRECTORY=0x10000,O_NOFOLLOW=0x20000)
        owner=self
        class MemoryPath:
            def __init__(self,value):self.value=PurePosixPath(str(value))
            def __str__(self):return str(self.value)
            def __fspath__(self):return str(self.value)
            def __eq__(self,other):return str(self)==str(other)
            def __truediv__(self,other):return MemoryPath(self.value/str(other))
            @property
            def parts(self):return self.value.parts
            @property
            def parent(self):return MemoryPath(self.value.parent)
            @property
            def parents(self):return tuple(MemoryPath(p) for p in self.value.parents)
            @property
            def name(self):return self.value.name
            def absolute(self):return self if self.value.is_absolute() else MemoryPath('/'+str(self))
            def is_absolute(self):return self.value.is_absolute()
            def exists(self):return str(self) in owner.nodes
            def is_symlink(self):return str(self) in owner.nodes and stat.S_ISLNK(owner.nodes[str(self)].st_mode)
            def lstat(self):return owner.nodes[str(self)]
            def resolve(self,strict=False):return self
        self.Path=MemoryPath

    def add(self,path,mode,uid=1000,target=None):
        self.nodes[path]=SimpleNamespace(st_mode=mode,st_uid=uid,st_dev=1,st_ino=len(self.nodes)+1,
                                         st_nlink=1,st_size=0,target=target)

    def path(self,name,dir_fd=None):
        return str(PurePosixPath(self.descriptors[dir_fd][0])/str(name)) if dir_fd is not None else str(name)

    def open(self,name,flags,mode=0o600,dir_fd=None):
        path=self.path(name,dir_fd)
        if path not in self.nodes:raise FileNotFoundError(path)
        value=self.nodes[path]
        if stat.S_ISLNK(value.st_mode):raise OSError(errno.ELOOP,'link')
        descriptor=self.next_fd;self.next_fd+=1
        self.descriptors[descriptor]=(path,value)
        if self.after_open:self.after_open(path,value)
        return descriptor

    def close(self,descriptor):
        if descriptor not in self.descriptors:raise AssertionError('descriptor closed twice')
        self.closed.append(descriptor);del self.descriptors[descriptor]

    def fstat(self,descriptor):return self.descriptors[descriptor][1]

    def stat(self,name,dir_fd=None,follow_symlinks=False):
        path=self.path(name,dir_fd)
        if path not in self.nodes:raise FileNotFoundError(path)
        result=self.nodes[path]
        if self.after_stat:self.after_stat(path,result)
        return result

    def mkdir(self,name,mode=0o700,dir_fd=None):
        path=self.path(name,dir_fd)
        self.add(path,stat.S_IFDIR|mode)
        if self.mkdir_race:raise FileExistsError(path)

    def readlink(self,name,dir_fd=None):return self.nodes[self.path(name,dir_fd)].target
    def chmod(self,descriptor,mode):self.chmods.append((descriptor,mode))
    def sync(self,descriptor):
        self.synced.append(descriptor)
        if self.sync_error:raise self.sync_error

    @contextlib.contextmanager
    def installed(self):
        with patch.object(fs,'os',self.os),patch.object(fs,'Path',self.Path):yield self


class DirectoryDescriptorContractTests(unittest.TestCase):
    def test_sticky_root_is_trusted_but_never_tightened_or_admitted_as_private_shared_staging(self):
        for sticky in (False, True):
            memory = MemoryDirectories()
            memory.add('/shared', stat.S_IFDIR | 0o777 | (stat.S_ISVTX if sticky else 0), 0)
            with memory.installed():
                if sticky:
                    with fs.PinnedDirectory('/shared') as directory:
                        self.assertIsNotNone(directory.fd)
                else:
                    with self.assertRaisesRegex(ValueError, 'shared writable'):
                        fs.PinnedDirectory('/shared')
            self.assertFalse(memory.descriptors)
        memory = MemoryDirectories()
        memory.add('/shared', stat.S_IFDIR | stat.S_ISVTX | 0o777, 0)
        memory.os.geteuid = lambda: 0
        with memory.installed():
            with self.assertRaisesRegex(ValueError, 'private directory'):
                fs.PinnedDirectory('/shared', private=True)
            with self.assertRaisesRegex(ValueError, 'cannot tighten root'):
                fs.PinnedDirectory('/', tighten=True)
        self.assertFalse(memory.descriptors)
        self.assertEqual(memory.chmods, [])

    def test_dangling_owned_ancestry_link_is_inspected_even_when_exists_is_false(self):
        memory = MemoryDirectories()
        memory.add('/safe/dangling', stat.S_IFLNK | 0o777, 1000, '/missing')
        original = memory.Path.exists
        # Path.exists follows a symlink; Path.is_symlink observes the entry.
        def exists(path):
            return False if str(path) == '/safe/dangling' else original(path)
        with memory.installed(), patch.object(memory.Path, 'exists', exists), \
                patch.object(fs, '_trusted_directory', wraps=fs._trusted_directory) as check:
            fs.trusted_parents('/safe/dangling/output')
        self.assertEqual(sum(str(call.args[0]) == '/safe/dangling' for call in check.call_args_list), 2)
        self.assertFalse(memory.descriptors)

    def test_private_pin_create_dot_parent_aliases_and_idempotent_cleanup(self):
        for path in ('/safe/leaf','/safe/./leaf','/safe/leaf/../leaf','/alias/leaf','/relative/leaf','/created/leaf'):
            memory=MemoryDirectories()
            memory.add('/alias',stat.S_IFLNK|0o777,0,'/safe')
            memory.add('/relative',stat.S_IFLNK|0o777,1000,'safe')
            memory.mkdir_race=True
            with memory.installed():
                with fs.PinnedDirectory(path,create=True,private=True,tighten=True) as directory:
                    self.assertEqual(str(directory.path),'/created/leaf' if path.startswith('/created') else '/safe/leaf')
                    self.assertEqual(memory.chmods[-1],(directory.fd,0o700))
                    self.assertIs(directory.__enter__(),directory)
                directory.close()
            self.assertFalse(memory.descriptors)

    def test_ownership_modes_links_and_entry_races_fail_closed(self):
        for mode,uid in ((stat.S_IFREG|0o600,1000),(stat.S_IFDIR|0o700,2000),(stat.S_IFDIR|0o777,1000)):
            memory=MemoryDirectories();memory.add('/safe/leaf',mode,uid)
            with memory.installed(),self.assertRaises(ValueError):fs.PinnedDirectory('/safe/leaf')
            self.assertFalse(memory.descriptors)
        for mutation in ('inode-on-open','inode-after-stat','link-after-stat'):
            memory=MemoryDirectories()
            if mutation=='inode-on-open':
                original=memory.fstat
                def fstat(fd):
                    value=original(fd)
                    return SimpleNamespace(**{**vars(value),'st_ino':999}) if memory.descriptors[fd][0]=='/safe/leaf' else value
                memory.os.fstat=fstat
            else:
                def change(path,node):
                    if path=='/safe/leaf':
                        memory.nodes[path]=SimpleNamespace(**{**vars(node),'st_ino':999,
                            'st_mode':stat.S_IFLNK|0o777 if mutation=='link-after-stat' else node.st_mode})
                memory.after_open=change
            with memory.installed(),self.assertRaisesRegex(ValueError,'changed'):fs.PinnedDirectory('/safe/leaf')
            self.assertFalse(memory.descriptors)

    def test_root_tightening_private_alias_and_untrusted_alias_are_refused(self):
        for path,private,tighten in (('/',True,True),('/safe/link',True,False),('/foreign/leaf',False,False),('/loop',False,False)):
            memory=MemoryDirectories()
            memory.add('/safe/link',stat.S_IFLNK|0o777,1000,'leaf')
            memory.add('/foreign',stat.S_IFLNK|0o777,2000,'/safe')
            memory.add('/loop',stat.S_IFLNK|0o777,0,'/loop')
            with memory.installed(),self.assertRaises(ValueError):fs.PinnedDirectory(path,private=private,tighten=tighten)
            self.assertFalse(memory.descriptors)
        memory=MemoryDirectories()
        with memory.installed(),self.assertRaises(FileNotFoundError):fs.PinnedDirectory('/missing')
        self.assertFalse(memory.descriptors)

    def test_directory_descriptor_type_sync_and_storage_failures(self):
        memory=MemoryDirectories();memory.add('/file',stat.S_IFREG|0o600)
        with memory.installed():
            with self.assertRaisesRegex(ValueError,'directory descriptor'):fs._open_directory('/file')
            self.assertTrue(fs.sync_directory('/safe'))
            for code in (errno.EINVAL,errno.ENOTSUP,errno.EOPNOTSUPP):
                memory.sync_error=OSError(code,'unsupported')
                self.assertFalse(fs.sync_directory('/safe'))
            memory.sync_error=OSError(errno.EIO,'durability failure')
            with self.assertRaises(OSError):fs.sync_directory('/safe')
        self.assertFalse(memory.descriptors)

    def test_ancestor_policy_distinguishes_sticky_root_user_links_and_reparse_points(self):
        cases=((stat.S_IFDIR|0o755,0,True),(stat.S_IFDIR|stat.S_ISVTX|0o777,0,True),
               (stat.S_IFDIR|0o700,1000,True),(stat.S_IFLNK|0o777,1000,True),
               (stat.S_IFLNK|0o777,2000,False),(stat.S_IFDIR|0o700,2000,False),
               (stat.S_IFDIR|0o777,1000,False),(stat.S_IFREG|0o600,1000,False))
        for mode,uid,allowed in cases:
            memory=MemoryDirectories();memory.add('/entry',mode,uid)
            with memory.installed():
                if allowed:fs._trusted_directory(memory.Path('/entry'))
                else:
                    with self.assertRaises(ValueError):fs._trusted_directory(memory.Path('/entry'))
                fs.trusted_parents('/safe/leaf/output')
        self.assertTrue(fs.is_link(SimpleNamespace(st_mode=stat.S_IFREG,st_file_attributes=0x400)))
        self.assertFalse(fs.is_link(SimpleNamespace(st_mode=stat.S_IFREG,st_file_attributes=0)))

    def test_relative_entry_operations_keep_the_directory_descriptor_and_refuse_devices(self):
        memory=MemoryDirectories()
        with memory.installed(),fs.PinnedDirectory('/safe/leaf') as directory:
            memory.add('/safe/leaf/input',stat.S_IFREG|0o600)
            fd=directory.open('input',os.O_RDONLY)
            self.assertEqual(memory.descriptors[fd][0],'/safe/leaf/input');memory.close(fd)
            with patch.object(memory.os,'replace',Mock()) as replace_file,patch.object(memory.os,'unlink',Mock()) as unlink:
                directory.replace('input','output')
                self.assertEqual(replace_file.call_args.kwargs,{'src_dir_fd':directory.fd,'dst_dir_fd':directory.fd})
                directory.unlink('output');self.assertEqual(unlink.call_args.kwargs,{'dir_fd':directory.fd})
                unlink.side_effect=FileNotFoundError();directory.unlink('absent')
            for value in (None,1,'','.','..','a/b','a\\b'):
                with self.assertRaises(ValueError):directory.open(value,0)
            for code in (errno.EINVAL,errno.EIO):
                memory.sync_error=OSError(code,'sync')
                if code==errno.EINVAL:directory.sync()
                else:
                    with self.assertRaises(OSError):directory.sync()
        self.assertFalse(memory.descriptors)


class PrivateAppendBoundaryTests(unittest.TestCase):
    """A returned stream owns one checked descriptor; every refusal closes it."""
    def test_private_append_rejects_links_owners_and_special_files_before_fd_transfer(self):
        for failure in ('none','not-regular','hardlink','foreign-owner','fdopen'):
            parent=Mock();parent.open.return_value=41
            port=SimpleNamespace(**vars(os));port.name='posix';port.geteuid=lambda:1000
            port.fstat=Mock(return_value=SimpleNamespace(st_mode=stat.S_IFREG|0o644 if failure!='not-regular' else stat.S_IFDIR|0o700,
                st_nlink=2 if failure=='hardlink' else 1,st_uid=2000 if failure=='foreign-owner' else 1000))
            port.fchmod=Mock();port.close=Mock();stream=io.StringIO()
            port.fdopen=Mock(side_effect=OSError('synthetic fdopen') if failure=='fdopen' else None,return_value=stream)
            with patch.object(fs,'os',port),patch.object(fs,'PinnedDirectory',return_value=contextlib.nullcontext(parent)):
                if failure=='none':
                    self.assertIs(fs.open_private_append('/synthetic/audit'),stream)
                    port.close.assert_not_called();port.fchmod.assert_called_once_with(41,0o600)
                else:
                    with self.assertRaises(OSError if failure=='fdopen' else ValueError):fs.open_private_append('/synthetic/audit')
                    port.close.assert_called_once_with(41)
                if failure not in ('none','fdopen'):port.fdopen.assert_not_called()
            stream.close()
        for code in (errno.ELOOP,errno.ENXIO,errno.EACCES):
            parent=Mock();parent.open.side_effect=OSError(code,'synthetic private path')
            with patch.object(fs,'PinnedDirectory',return_value=contextlib.nullcontext(parent)):
                with self.assertRaises(ValueError if code in (errno.ELOOP,errno.ENXIO) else OSError):
                    fs.open_private_append('/synthetic/audit')

    def test_private_owner_and_non_posix_alias_rules_cannot_be_bypassed(self):
        memory=MemoryDirectories();memory.add('/safe/leaf',stat.S_IFDIR|0o755,0)
        with memory.installed(),self.assertRaisesRegex(ValueError,'owned by this account'):
            fs.PinnedDirectory('/safe/leaf',private=True)
        self.assertFalse(memory.descriptors)
        memory=MemoryDirectories();memory.add('/safe/leaf',stat.S_IFDIR|0o755,0)
        with memory.installed(),self.assertRaisesRegex(ValueError,'another account'):
            fs.PinnedDirectory('/safe/leaf',tighten=True)
        self.assertFalse(memory.descriptors)
        memory=MemoryDirectories();memory.add('/alias',stat.S_IFLNK|0o777,1000,'/safe')
        with memory.installed(),patch.object(memory.os,'name','nt'):
            with self.assertRaisesRegex(ValueError,'untrusted link'):fs._trusted_directory(memory.Path('/alias'))
            self.assertFalse(fs.sync_directory('/safe'))
        memory=MemoryDirectories();memory.add('/safe/link',stat.S_IFLNK|0o777,1000,'leaf')
        with memory.installed(),self.assertRaises(ValueError):fs.private_directory(memory.Path('/safe/link'))


class AtomicOutputFailureTests(unittest.TestCase):
    def test_posix_publication_does_not_call_windows_acl_management(self):
        directory = Mock(path=PurePosixPath('/private'))
        directory.open.return_value = 41
        stream = io.StringIO()
        port = SimpleNamespace(**vars(os))
        port.name = 'posix'
        port.fdopen = Mock(return_value=stream)
        port.fsync = Mock()
        # StringIO has no descriptor; publication is still checked by the
        # existing native integration tests, while this case isolates setup.
        with patch.object(fs, 'os', port), patch.object(fs, 'PinnedDirectory', return_value=directory), \
                patch('swassh.infrastructure.windows.protect_directory') as protect:
            output = fs.AtomicOutput('output')
            output.__exit__(ValueError, ValueError('abort before publication'), None)
        protect.assert_not_called()
        directory.replace.assert_not_called()
        directory.close.assert_called_once()
        self.assertTrue(stream.closed)

    def test_every_failure_closes_the_pin_and_preserves_publication_order(self):
        for failure in (None,'open','fdopen','flush','fsync','replace','unlink'):
            events=[]
            directory=Mock(path=PurePosixPath('/private'))
            directory.open.return_value=41
            class Stream(io.StringIO):
                def fileno(self):return 41
                def flush(self):
                    events.append('flush')
                    if failure=='flush':raise OSError('flush')
                    return super().flush()
                def close(self):events.append('stream-close');return super().close()
            stream=Stream()
            directory.replace.side_effect=lambda *args:events.append('replace')
            directory.close.side_effect=lambda:events.append('pin-close')
            if failure=='open':directory.open.side_effect=OSError('open')
            if failure in ('replace','unlink'):getattr(directory,failure).side_effect=OSError(failure)
            def sync(fd):
                self.assertEqual(fd,41);events.append('fsync')
                if failure=='fsync':raise OSError('fsync')
            with patch.object(fs,'PinnedDirectory',return_value=directory),patch('swassh.infrastructure.windows.protect_directory'),patch.object(fs.os,'fdopen',side_effect=OSError('fdopen') if failure=='fdopen' else None,return_value=stream),patch.object(fs.os,'fsync',side_effect=sync),patch.object(fs.os,'close') as close:
                if failure is None:
                    with fs.AtomicOutput('output') as value:value.write('synthetic content')
                    self.assertLess(events.index('fsync'),events.index('replace'))
                    self.assertLess(events.index('stream-close'),events.index('replace'))
                else:
                    with self.assertRaisesRegex(OSError,failure):
                        with fs.AtomicOutput('output') as value:value.write('synthetic content')
                self.assertEqual(events[-1],'pin-close')
                directory.unlink.assert_called_once()
                if failure=='fdopen':close.assert_called_once_with(41)
                if failure in ('open','fdopen','flush','fsync'):directory.replace.assert_not_called()
            stream.close()

    def test_application_error_never_publishes_or_syncs_partial_content(self):
        directory=Mock(path=PurePosixPath('/private'));directory.open.return_value=42
        stream=io.StringIO()
        with patch.object(fs,'PinnedDirectory',return_value=directory),patch('swassh.infrastructure.windows.protect_directory'),patch.object(fs.os,'fdopen',return_value=stream),patch.object(fs.os,'fsync') as sync:
            with self.assertRaisesRegex(RuntimeError,'application'):
                with fs.AtomicOutput('output') as value:
                    value.write('partial');raise RuntimeError('application')
        sync.assert_not_called();directory.replace.assert_not_called()
        directory.unlink.assert_called_once();directory.close.assert_called_once()
        self.assertTrue(stream.closed)
