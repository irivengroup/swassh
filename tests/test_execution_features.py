"""Execution extensions preserve bounded input, live privacy and SSH policy."""
import asyncio
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from swassh import Host, HostProfile, Options, Status, Swarm
from swassh.application.profiles import ProfileResolver
from swassh.infrastructure.execution_input import InputSnapshot, load_profiles
from swassh.infrastructure.live_output import LiveOutput
from swassh.infrastructure.resources import resource_plan
from swassh.infrastructure.ssh import _Buffer, _config, _outcome
from swassh.infrastructure.scheduled_execution import prepare_invocation
from swassh.infrastructure.schedule_store import encode_invocation, decode_invocation
from swassh.infrastructure.authentication import Authentication


class SettingsTests(unittest.TestCase):
    def test_password_prompt_is_not_misclassified_as_provider_failure(self):
        diagnostic = 'debug1: read_passphrase: requested to askpass\nPermission denied (password).'
        status, message, retry = _outcome(255, diagnostic, True, auth_method='password')
        self.assertEqual(status, Status.AUTH_FAILED)
        self.assertIn('authentication denied', message)
        self.assertFalse(retry)
        status, message, retry = _outcome(255, 'ssh_askpass: exec(provider): No such file or directory', True, auth_method='password')
        self.assertEqual(status, Status.AUTH_FAILED)
        self.assertIn('provider failed', message)
        self.assertFalse(retry)

    def test_authentication_modes_never_fallback_or_delegate(self):
        for invalid in ({'auth_method': 'auto'}, {'auth_method': 'password'}, {'askpass_executable': ''}):
            with self.assertRaises(ValueError):
                Options(**invalid)
        config = _config(Host('host'), Options(auth_method='gssapi'))
        self.assertIn('GSSAPIAuthentication yes', config)
        self.assertIn('GSSAPIDelegateCredentials no', config)
        self.assertIn('PreferredAuthentications gssapi-with-mic', config)
        password = Options(auth_method='password', askpass_executable=sys.executable)
        config = _config(Host('host'), password)
        self.assertIn('BatchMode no', config)
        self.assertIn('PubkeyAuthentication no', config)
        self.assertIn('NumberOfPasswordPrompts 1', config)
        with patch.object(Authentication, 'provider', return_value='trusted-provider'):
            env = Authentication.environment(password, password)
        self.assertEqual(env['SSH_ASKPASS'], 'trusted-provider')
        self.assertEqual(env['SSH_ASKPASS_REQUIRE'], 'force')
        with patch.dict(os.environ, {'SSH_ASKPASS': 'unrequested-provider'}):
            self.assertNotIn('SSH_ASKPASS', Authentication.environment(Options(), Options()))
        with self.assertRaises(ValueError):
            Authentication.provider(Options(askpass_executable='missing-provider-xyz'))

    def test_options_validate_text_codecs_and_limits(self):
        for changes in ({'encoding': 'not-a-codec'}, {'encoding': 'base64_codec'}, {'encoding': 3},
                        {'stream_rate': 0}, {'stream_output': 1}, {'max_stdin_bytes': 0},
                        {'stdin_file': ''}, {'stdin_sha256': 'bad'}, {'host_profiles': []},
                        {'host_profiles': (HostProfile('host'), HostProfile('HOST'))},
                        {'host_profiles': (HostProfile('host', command_timeout=-1),)}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                Options(**changes)
        self.assertEqual(Options(encoding='latin-1').encoding, 'latin-1')

    def test_profiles_preserve_user_precedence_and_bastion_policy(self):
        options = Options(username='global', client_keys=('global-key',), known_hosts='global-known',
            jump_host=Host('jump', username='jumper'), host_profiles=(HostProfile('HOST', username='local',
                client_keys=('target-key',), known_hosts='target-known', connect_timeout=7),))
        resolver = ProfileResolver(options)
        hosts = resolver.targets(['host', 'local@host', 'explicit@host', 'other'])
        self.assertEqual([h.username for h in hosts], ['local', 'explicit', 'global'])
        self.assertEqual(resolver.for_host(Host('host')).bastion_concurrency, options.bastion_concurrency)
        config = _config(Host('host'), options)
        target, rest = config.split('Host swassh-jump')
        jump, common = rest.split('Host *')
        self.assertIn('target-key', target)
        self.assertNotIn('global-key', target)
        self.assertIn('global-key', jump)
        self.assertNotIn('target-key', jump)
        self.assertIn('StrictHostKeyChecking yes', common)
        self.assertIn('ServerAliveInterval 5', common)

    def test_strict_profile_loading_and_relative_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root/'profiles.json'
            source.write_text(json.dumps([{'hostname': 'host', 'client_keys': ['key'], 'known_hosts': 'known'}]))
            profile, = load_profiles(source)
            self.assertEqual(profile.client_keys, (str(root/'key'),))
            self.assertEqual(profile.known_hosts, str(root/'known'))
            for value in ('[{"hostname":"a","hostname":"b"}]', '[{"hostname":"a","password":"x"}]', '{}',
                          '[{"hostname":"a","client_keys":"key"}]', '[{"hostname":"a","known_hosts":5}]'):
                source.write_text(value)
                with self.assertRaises(ValueError):
                    load_profiles(source)

    def test_input_size_digest_and_schedule_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root/'input'
            path.write_bytes(b'input\x00bytes')
            options = Options(stdin_file=str(path), max_stdin_bytes=32, ssh_executable=sys.executable,
                host_profiles=(HostProfile('host', encoding='latin-1'),))
            self.assertEqual(InputSnapshot.stdin(options), b'input\x00bytes')
            with self.assertRaises(ValueError):
                InputSnapshot.stdin(replace(options, max_stdin_bytes=1))
            job = prepare_invocation('a'*32, root, ['host'], 'cat', options)
            restored = decode_invocation(encode_invocation(job))
            self.assertEqual(restored, job)
            self.assertEqual(restored.options.stdin_sha256, hashlib.sha256(path.read_bytes()).hexdigest())
            path.write_bytes(b'changed')
            with self.assertRaises(ValueError):
                InputSnapshot.stdin(restored.options)
            self.assertIsNone(InputSnapshot.stdin(Options()))
            with self.assertRaises((ValueError, OSError)):
                InputSnapshot.read(root, 32)

    @unittest.skipUnless(os.name == 'posix', 'POSIX links and FIFO')
    def test_input_rejects_link_and_special_file_without_blocking(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root/'target'
            target.write_bytes(b'x')
            link = root/'link'
            link.symlink_to(target)
            fifo = root/'fifo'
            os.mkfifo(fifo)
            for path in (link, fifo):
                with self.assertRaises((ValueError, OSError)):
                    InputSnapshot.read(path, 100)

    def test_memory_plan_accounts_for_optional_buffers(self):
        with patch('swassh.infrastructure.resources._available_memory', return_value=None):
            plain = resource_plan(Options())
            extra = resource_plan(Options(stream_output=True, stdin_file='input', host_profiles=(HostProfile('host'),)))
            self.assertLess(extra.memory_budget_bytes, plain.memory_budget_bytes)
            with self.assertRaises(ValueError):
                resource_plan(Options(memory_budget_mib=64, stream_output=True))

    def test_native_stream_input_and_small_profile_fit_default_budget(self):
        # The installed CLI combines all three features. Charging the maximum
        # profile table for one tiny entry must not reject that existing flow.
        options = Options(stream_output=True, stdin_file='input',
                          host_profiles=(HostProfile('host', encoding='latin-1'),))
        with patch('swassh.infrastructure.resources._available_memory', return_value=None):
            plan = resource_plan(options, guarded=True)
            self.assertGreaterEqual(plan.workers, 1)
            self.assertEqual(plan.estimated_worker_bytes, 49 * 1024**2)
            with self.assertRaises(ValueError):
                resource_plan(replace(options, memory_budget_mib=64), guarded=True)

    def test_large_profile_table_still_reserves_its_full_metadata(self):
        profiles = tuple(HostProfile('host' + str(index), known_hosts='a' * 4096)
                         for index in range(800))
        options = Options(stream_output=True, stdin_file='input', host_profiles=profiles)
        with patch('swassh.infrastructure.resources._available_memory', return_value=None):
            with self.assertRaises(ValueError):
                resource_plan(options, guarded=True)
            plan = resource_plan(replace(options, memory_budget_mib=160), guarded=True)
            self.assertGreaterEqual(plan.workers, 1)


class IOTests(unittest.IsolatedAsyncioTestCase):
    async def test_stalled_live_consumer_times_out_and_cannot_survive_cleanup(self):
        from swassh.infrastructure.process_guard import launch_native
        sink = LiveOutput(Options(report_timeout=3))
        sink.process = await launch_native(sys.executable, '-c', 'import time; time.sleep(60)',
            options=Options(), connected=False, stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
        process = sink.process
        try:
            with self.assertRaises(TimeoutError):
                for _ in range(256):
                    await sink._write({'text': 'x'*8192})
        finally:
            with self.assertRaises(TimeoutError):
                await sink.close()
        self.assertIsNotNone(process.returncode)
        self.assertIsNone(sink.process)

    async def test_real_live_writer_is_guarded_and_escapes_terminal_controls(self):
        from swassh.infrastructure.process_guard import launch_native
        async def launch(*args, **kwargs):
            return await launch_native(*args, stderr=asyncio.subprocess.PIPE, **kwargs)
        sink = LiveOutput(Options())
        with patch('swassh.infrastructure.live_output.launch_native', launch):
            await sink.start()
        process = sink.process
        reading = asyncio.create_task(process.stderr.read())
        try:
            await sink.emit(Host('host'), 'stdout', '\x1b[2Jremote\n')
            await sink.close()
            raw = await reading
            events = [json.loads(line) for line in raw.splitlines()]
            self.assertNotIn(b'\x1b', raw)
            self.assertEqual(events[0]['text'], '\x1b[2Jremote\n')
            self.assertEqual(events[-1]['dropped_events'], 0)
            self.assertEqual(process.returncode, 0)
        finally:
            await sink.close()
            reading.cancel()
            await asyncio.gather(reading, return_exceptions=True)

    async def test_incremental_decoding_and_bounded_line_fragments(self):
        events = []
        async def emit(text, **flags):
            events.append((text, flags))
        reader = asyncio.StreamReader()
        buffer = _Buffer(4096, encoding='utf-8', live=emit)
        task = asyncio.create_task(buffer.consume(reader))
        reader.feed_data(b'caf\xc3')
        await asyncio.sleep(0)
        reader.feed_data(b'\xa9\n'+b'x'*3000)
        reader.feed_eof()
        await task
        self.assertEqual(''.join(row[0] for row in events), buffer.text)
        self.assertEqual(events[0][0], 'caf\u00e9\n')
        self.assertTrue(all(len(row[0]) <= 1024 for row in events))
        self.assertTrue(any(row[1]['continued'] for row in events))

    async def test_live_rate_overflow_is_counted(self):
        sink = LiveOutput(Options(stream_rate=1))
        sent = []
        async def write(event):
            sent.append(event)
        with patch.object(sink, '_write', write):
            await sink.emit(Host('host'), 'stdout', 'one')
            await sink.emit(Host('host'), 'stderr', 'two')
        self.assertEqual(len(sent), 1)
        self.assertEqual(sink.dropped, 1)
        await sink.close()

    async def test_stdin_bytes_and_profile_encoding_over_real_pipes(self):
        original = asyncio.create_subprocess_exec
        fixture = Path(__file__).with_name('fake_ssh.py')
        async def launch(executable, *args, **kwargs):
            kwargs.pop('options')
            return await original(sys.executable, str(fixture), *args, **kwargs)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'input'
            path.write_bytes(b'caf\xe9\x00\n')
            options = Options(ssh_executable=sys.executable, stdin_file=str(path),
                host_profiles=(HostProfile('host', encoding='latin-1'),))
            with patch('swassh.infrastructure.ssh.launch_native', launch):
                report = await Swarm(options).run(['host'], 'stdin-echo')
            self.assertEqual(report.results[0].status, Status.SUCCESS)
            self.assertEqual(report.results[0].stdout, 'caf\u00e9\x00\n')

    async def test_live_event_precedes_remote_completion(self):
        original = asyncio.create_subprocess_exec
        fixture = Path(__file__).with_name('fake_ssh.py')
        events = []
        with tempfile.TemporaryDirectory() as directory:
            release = Path(directory)/'release'
            async def launch(executable, *args, **kwargs):
                kwargs.pop('options')
                kwargs['env']['SWASSH_TEST_RELEASE'] = str(release)
                return await original(sys.executable, str(fixture), *args, **kwargs)
            async def start(sink):
                pass
            async def close(sink):
                pass
            async def emit(sink, host, channel, text, **flags):
                events.append((channel, text))
                if text == 'early\n':
                    self.assertFalse(release.exists())
                    release.write_text('continue')
            with patch('swassh.infrastructure.ssh.launch_native', launch), patch.object(LiveOutput, 'start', start), patch.object(LiveOutput, 'close', close), patch.object(LiveOutput, 'emit', emit):
                report = await Swarm(Options(ssh_executable=sys.executable, stream_output=True)).run(['host'], 'live')
            self.assertTrue(report.ok)
            self.assertEqual(events, [('stdout', 'early\n'), ('stdout', 'late\n')])



class LiteralControlValidationTests(unittest.TestCase):
    """Literal payload checks supplement the existing subclass iterator policy."""

    @staticmethod
    def constructors(value):
        from swassh import TransferReceipt
        for field in ('client_keys', 'known_hosts', 'log_file', 'budget_dir', 'stdin_file', 'askpass_executable'):
            argument = (value,) if field == 'client_keys' else value
            yield 'options-' + field, lambda field=field, argument=argument: Options(**{field: argument})
        for field in ('local_path', 'remote_path', 'temporary_path', 'fallback_reason'):
            arguments = dict(direction='push', local_path='local', remote_path='remote', backend='sftp')
            arguments[field] = value
            yield 'receipt-' + field, lambda arguments=arguments: TransferReceipt(**arguments)

    def test_literal_controls_cannot_be_hidden_by_a_string_subclass(self):
        class HiddenControls(str):
            def __iter__(self):
                return iter('apparently-safe')
        for codepoint in (0, 31, 127, 159):
            value = HiddenControls('literal-' + chr(codepoint) + '-payload')
            for name, construct in self.constructors(value):
                with self.subTest(field=name, codepoint=codepoint):
                    with self.assertRaises(ValueError):
                        construct()

    def test_subclass_iterator_rejections_and_errors_remain_observable(self):
        class CustomIteration(str):
            def __new__(cls, yielded):
                instance = super().__new__(cls, 'literal-safe-payload')
                instance.yielded = yielded
                return instance
            def __iter__(self):
                return iter(self.yielded)
        for yielded in ('\x00', '\x7f', '\x9f', '\xa0', 'safe'):
            value = CustomIteration(yielded)
            for name, construct in self.constructors(value):
                with self.subTest(field=name, yielded=repr(yielded)):
                    if yielded in ('\x00', '\x7f', '\x9f'):
                        with self.assertRaises(ValueError):
                            construct()
                    else:
                        self.assertIsNotNone(construct())
        class BrokenIteration(str):
            def __iter__(self):
                raise OSError('synthetic iterator failure')
        for name, construct in self.constructors(BrokenIteration('literal-safe')):
            with self.subTest(field=name):
                with self.assertRaisesRegex(OSError, '^synthetic iterator failure$'):
                    construct()

    def test_builtin_control_policy_and_utf8_limits_are_preserved(self):
        for codepoint in (*range(256), 0x100, 0x2028, 0x2029, 0x1f600, 0x10ffff):
            value = 'literal-' + chr(codepoint) + '-payload'
            prohibited = codepoint < 32 or 127 <= codepoint <= 159
            for name, construct in self.constructors(value):
                with self.subTest(field=name, codepoint=codepoint):
                    if prohibited:
                        with self.assertRaises(ValueError):
                            construct()
                    else:
                        self.assertIsNotNone(construct())
        for value in ('a'*4095, 'a'*4096, 'a'*4097, '\xe9'*2048, '\xe9'*2049, '\U0001f600'*1024, '\U0001f600'*1025):
            for name, construct in self.constructors(value):
                with self.subTest(field=name, utf8_bytes=len(value.encode('utf-8'))):
                    if len(value.encode('utf-8')) > 4096:
                        with self.assertRaises(ValueError):
                            construct()
                    else:
                        self.assertIsNotNone(construct())
        with self.assertRaises(ValueError):
            Options(known_hosts='${UNEXPANDED}')
        from swassh import TransferReceipt
        self.assertEqual(TransferReceipt('push', '${LITERAL}', 'remote').local_path, '${LITERAL}')

    def test_inherited_string_subclasses_keep_their_values_and_identity(self):
        class InheritedString(str):
            """Use normal string iteration with a distinct application type."""
        value = InheritedString('literal-\u03b1')
        for name, construct in self.constructors(value):
            with self.subTest(field=name):
                result = construct()
                field = name.split('-', 1)[1]
                stored = getattr(result, field)
                self.assertIs(stored[0] if field == 'client_keys' else stored, value)
