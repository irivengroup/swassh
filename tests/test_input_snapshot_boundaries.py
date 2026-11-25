"""Stable-input and persisted-path contracts through memory-only I/O ports.

The real descriptor/reparse adapters retain their separate integration tests.
Here a changed size, identity, or timestamp must invalidate the whole snapshot.
"""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from swassh import HostProfile, Options
from swassh.domain.scheduling import ScheduleError
from swassh.infrastructure import execution_input as inputs
from swassh.infrastructure import scheduled_execution as schedules


class MemoryInput(io.BytesIO):
    def fileno(self):
        return 41


class StableInputBoundaryTests(unittest.TestCase):
    def test_profile_objects_and_absolute_credential_paths_preserve_their_contract(self):
        for value in (None,1,'one',[],True):
            with self.subTest(value=value),self.assertRaisesRegex(ValueError,'profile schema'):
                inputs.decode_profiles([value])
        location=Path('/synthetic/profiles.json').absolute()
        key=Path('/synthetic/keys/identity').absolute();known=Path('/synthetic/trust').absolute()
        raw=json.dumps([{'hostname':'one','client_keys':[str(key)],'known_hosts':str(known)}]).encode()
        with patch.object(inputs.InputSnapshot,'read',return_value=raw) as read:
            profiles=inputs.load_profiles(location)
        read.assert_called_once_with(location,4*1024**2)
        self.assertEqual(profiles[0].client_keys,(str(key),));self.assertEqual(profiles[0].known_hosts,str(known))

    def read(self, data=b'abc', *, before=None, after=None, maximum=3):
        original=dict(st_mode=stat.S_IFREG | 0o600, st_size=3, st_dev=1,
                      st_ino=2, st_mtime_ns=3, st_ctime_ns=4)
        first=original | (before or {})
        last=first | (after or {})
        port=Mock();port.__enter__=Mock(return_value=port);port.__exit__=Mock(return_value=False)
        port.open.return_value=41
        stream=MemoryInput(data)
        kernel=SimpleNamespace(**vars(os))
        kernel.fdopen=Mock(return_value=stream)
        kernel.fstat=Mock(side_effect=(SimpleNamespace(**first),SimpleNamespace(**last)))
        with patch.object(inputs,'PinnedDirectory',return_value=port),patch.object(inputs,'os',kernel):
            try:
                return inputs.InputSnapshot.read('synthetic-input',maximum)
            finally:
                self.assertTrue(stream.closed)
                port.__exit__.assert_called_once()
                self.assertEqual(kernel.fdopen.call_args.args,(41,'rb'))

    def test_snapshot_rejects_growth_short_read_and_each_identity_or_clock_change(self):
        self.assertEqual(self.read(),b'abc')
        for change in ({'st_dev':2},{'st_ino':3},{'st_size':4},
                       {'st_mtime_ns':4},{'st_ctime_ns':5}):
            with self.subTest(change=change),self.assertRaisesRegex(ValueError,'changed'):
                self.read(after=change)
        for data in (b'ab',b'abcd'):
            with self.subTest(length=len(data)),self.assertRaisesRegex(ValueError,'changed'):
                self.read(data)
        for change in ({'st_mode':stat.S_IFIFO},{'st_size':4}):
            with self.assertRaisesRegex(ValueError,'regular file'):
                self.read(before=change)

    def test_profile_arrays_and_literal_path_resolution_refuse_ambiguous_input(self):
        self.assertEqual(inputs.decode_profiles([]),())
        for value in (None,(),[{}],[{'hostname':'one','unknown':1}],
                      [{'hostname':'one','client_keys':'key'}],[{}]*10001):
            with self.subTest(value_type=type(value)),self.assertRaises(ValueError):
                inputs.decode_profiles(value)
        rows=b'[{"hostname":"one","client_keys":["key"],"known_hosts":"trust"},'+\
             b'{"hostname":"two","client_keys":null,"known_hosts":null}]'
        location=Path('synthetic/config.json').absolute()
        with patch.object(inputs.InputSnapshot,'read',return_value=rows):
            one,two=inputs.load_profiles(location)
        self.assertEqual(one.client_keys,(str(location.parent/'key'),))
        self.assertEqual(one.known_hosts,str(location.parent/'trust'))
        self.assertEqual((two.client_keys,two.known_hosts),(None,None))
        for rows in (b'[{"hostname":"one","known_hosts":""}]',
                     b'[{"hostname":"one","known_hosts":1}]',
                     b'[{"hostname":"one","client_keys":[""]}]'):
            with patch.object(inputs.InputSnapshot,'read',return_value=rows),self.assertRaises(ValueError):
                inputs.load_profiles(location)

    def test_unexpected_dependency_errors_propagate_and_digest_is_checked_on_every_read(self):
        options=Options(stdin_file='input',stdin_sha256=hashlib.sha256(b'abc').hexdigest())
        with patch.object(inputs.InputSnapshot,'read',return_value=b'abc') as read:
            self.assertEqual(inputs.InputSnapshot.stdin(options),b'abc')
            self.assertEqual(inputs.InputSnapshot.stdin(options),b'abc')
            self.assertEqual(read.call_count,2)
        with patch.object(inputs.InputSnapshot,'read',return_value=b'abd'),self.assertRaisesRegex(ValueError,'register a new'):
            inputs.InputSnapshot.stdin(options)


class ScheduledPathBoundaryTests(unittest.TestCase):
    @contextlib.contextmanager
    def ports(self, *, exists=True):
        with patch.object(schedules.LocalPreflight,'require_credentials') as credentials,\
             patch.object(schedules.shutil,'which',side_effect=lambda value:str(Path('resolved')/value)),\
             patch.object(schedules.InputSnapshot,'stdin',side_effect=lambda options:b'abc' if options.stdin_file else None),\
             patch.object(schedules.Path,'is_dir',return_value=exists):
            yield credentials

    def test_registration_pins_all_explicit_overrides_and_report_spool_paths(self):
        profile=HostProfile('one',client_keys=('profile-key',),known_hosts='profile-trust')
        options=Options(auth_method='password',askpass_executable='provider',stdin_file='input',
                        client_keys=('key',),known_hosts='trust',budget_dir='budgets',log_file='audit',
                        host_profiles=(profile,HostProfile('two')))
        with self.ports() as credentials:
            invocation=schedules.prepare_invocation('a'*32,'state',['one'],'read',options,
                                      report_path='reports/result.json',spool_dir='spools')
        pinned=invocation.options
        for value in (pinned.ssh_executable,pinned.askpass_executable,pinned.stdin_file,
                      pinned.known_hosts,pinned.budget_dir,pinned.log_file,*pinned.client_keys,
                      *pinned.host_profiles[0].client_keys,pinned.host_profiles[0].known_hosts,
                      invocation.report_path,invocation.spool_dir):
            self.assertTrue(Path(value).is_absolute(),value)
        self.assertEqual(pinned.stdin_sha256,hashlib.sha256(b'abc').hexdigest())
        self.assertEqual(pinned.host_profiles[1].client_keys,None)
        credentials.assert_called_once_with(options)

    def test_missing_output_parents_fail_before_creating_any_state(self):
        for changes,reason in (({'report_path':'absent/result.json'},'report parent'),
                               ({'spool_dir':'absent'},'spool directory')):
            with self.ports(exists=False),patch.object(schedules,'private_directory') as create,\
                 self.assertRaisesRegex(ScheduleError,reason):
                schedules.prepare_invocation('a'*32,'state',['one'],'read',**changes)
            create.assert_not_called()

    def test_registration_without_ssh_does_not_persist_a_nonexecutable_invocation(self):
        with self.ports(),patch.object(schedules.shutil,'which',return_value=None),\
             self.assertRaisesRegex(ScheduleError,'unavailable at registration'):
            schedules.prepare_invocation('a'*32,'state',['one'],'read')
