"""Reboot contracts: exact evidence, bounded reconnect and no command replay."""
import asyncio
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import AsyncMock, Mock, patch

from swassh import Host, NetworkProcedure, NetworkStep, NetworkSwarm, Options, ReconnectPolicy, Status
from swassh.infrastructure.network import DeviceDialogue, DeviceDriver, DialogueBudget, NetworkDialogueError, NetworkTransport


def reboot_procedure():
    """Fully executable against network_fixture.py, never a hardware recipe."""
    return NetworkProcedure('cisco_ios', 'firmware', (
        NetworkStep('identify', 'identify', ('fixture-model', 'fixture-old'), exact_lines=True),
        NetworkStep('backup', 'backup', ('backup-complete',)),
        NetworkStep('transfer', 'transfer', ('transfer-complete',)),
        NetworkStep('checksum', 'checksum', ('a'*64,)),
        NetworkStep('activate', 'activate', ('activation-accepted',), reboot=True),
        NetworkStep('verify', 'verify', ('fixture-model', 'fixture-new'), exact_lines=True),
    ), 'a'*64, 'fixture-model', 'fixture-old', 'fixture-new',
        'Restore saved fixture state through the isolated fixture console', ReconnectPolicy(3, 10, 0.1))


class RebootContractTests(unittest.TestCase):
    def test_reconnect_cannot_apply_to_configuration_or_answer_a_post_reboot_question(self):
        value = reboot_procedure()
        configuration = (value.steps[0], value.steps[1],
                         NetworkStep('configure', 'configure', ('configured',)),
                         value.steps[-2], value.steps[-1])
        with self.assertRaisesRegex(ValueError, 'exactly one firmware reboot'):
            NetworkProcedure(value.platform, 'configuration', configuration, reconnect=value.reconnect)
        # The final step still finishes at a prompt: the forbidden question is
        # on an intermediate verification step, beyond the generic last-step check.
        steps = (*value.steps[:-1], replace(value.steps[-1], until='confirm?'), value.steps[-1])
        with self.assertRaisesRegex(ValueError, 'verification cannot answer interactive questions'):
            replace(value, steps=steps)

    def test_public_plan_declares_bounded_reconnect_without_command_replay(self):
        plan=NetworkSwarm(reboot_procedure()).plan([Host('one')])
        self.assertIn('bounded connection-only retries',plan['disconnect_policy'])
        self.assertIn('no command replay',plan['disconnect_policy'])
        self.assertEqual(plan['targets'],['one:22']);self.assertEqual(len(plan['approval_sha256']),64)

    def test_optional_fields_preserve_rc1_serialization_and_digest(self):
        raw = {'platform': 'cisco_ios', 'operation': 'administration', 'image_sha256': None,
               'model': None, 'current_version': None, 'target_version': None, 'recovery': None,
               'steps': [{'stage': 'identify', 'command': 'show version', 'expect': ['Version'], 'until': None}]}
        procedure = NetworkProcedure.decode(json.dumps(raw).encode())
        self.assertEqual(procedure.to_dict(), raw)
        expected = hashlib.sha256(json.dumps({'procedure': raw, 'targets': ['host:22']},
            sort_keys=True, ensure_ascii=True, separators=(',', ':')).encode('ascii')).hexdigest()
        self.assertEqual(procedure.digest([Host('host')]), expected)

    def test_reboot_round_trip_and_review_changes_with_policy(self):
        procedure = reboot_procedure()
        self.assertEqual(NetworkProcedure.decode(json.dumps(procedure.to_dict()).encode()), procedure)
        self.assertNotEqual(procedure.digest([Host('host')]),
                            replace(procedure, reconnect=ReconnectPolicy(2, 10, 0.1)).digest([Host('host')]))

    def test_invalid_retry_bounds_and_incomplete_schema_are_rejected(self):
        for kwargs in ({'attempts': True}, {'attempts': 61}, {'attempts': 0}, {'timeout': float('inf')},
                       {'timeout': 3601}, {'timeout': False}, {'interval': 0}, {'interval': float('nan')}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                ReconnectPolicy(**kwargs)
        for policy in (True, {}, {'attempts': 1, 'timeout': 3},
                       {'attempts': 1, 'timeout': 3, 'interval': 1, 'unknown': True}):
            raw = reboot_procedure().to_dict() | {'reconnect': policy}
            with self.assertRaises(ValueError):
                NetworkProcedure.decode(json.dumps(raw).encode())

    def test_no_implicit_reboot_retry_and_only_verification_after_reboot(self):
        procedure = reboot_procedure()
        for change in ({'reconnect': None}, {'reconnect': True}, {'operation': 'configuration'},
                       {'steps': procedure.steps[:-1]},
                       {'steps': (*procedure.steps, NetworkStep('persist', 'write', ('done',)))},
                       {'steps': (*procedure.steps[:-1], replace(procedure.steps[-1], until='confirm?'))},
                       {'steps': (*procedure.steps[:-1], replace(procedure.steps[-1], exact_lines=False))},
                       {'steps': (replace(procedure.steps[0], exact_lines=False), *procedure.steps[1:])},
                       {'steps': tuple(replace(step, reboot=False) for step in procedure.steps)},
                       {'steps': (*procedure.steps[:-1], replace(procedure.steps[-1], expect=('fixture-new',)))}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                replace(procedure, **change)
        for kwargs in ({'stage': 'verify', 'reboot': True}, {'reboot': 1},
                       {'reboot': True, 'until': 'confirm?'}, {'exact_lines': 1}):
            with self.assertRaises(ValueError):
                NetworkStep(**({'stage': 'activate', 'command': 'reboot', 'expect': ()} | kwargs))
        with self.assertRaisesRegex(ValueError, 'acceptance evidence'):
            NetworkStep('activate', 'reboot', (), reboot=True)


class RebootDialogueTests(unittest.IsolatedAsyncioTestCase):
    async def test_reconnect_authentication_failure_exhaustion_and_mid_command_disconnect_never_replay(self):
        initial = [b'r#', b'identify\nfixture-model\nfixture-old\nr#',
                   b'backup\nbackup-complete\nr#', b'transfer\ntransfer-complete\nr#',
                   b'checksum\n' + b'a' * 64 + b'\nr#', b'activate\nactivation-accepted\n', b'']
        for failure, expected, count in (('authentication', Status.AUTH_FAILED, 2),
                                          ('exhausted', Status.UNREACHABLE, 4),
                                          ('mid-command', Status.ERROR, 1)):
            opened, closed = [], []
            async def launch(*args, **kwargs):
                self.assertEqual(len(opened), len(closed), 'a new connection cannot overlap prior cleanup')
                chunks = ([b'r#', b''] if failure == 'mid-command' else initial) if not opened else [b'']
                process = Mock(returncode=255)
                process.stdout.read = AsyncMock(side_effect=chunks)
                process.stdin.drain = AsyncMock()
                if opened:
                    diagnostic = 'Permission denied (publickey).' if failure == 'authentication' else 'ssh: connect to host test port 22: Connection refused'
                    Path(args[args.index('-E') + 1]).write_text(diagnostic)
                opened.append(process)
                return process
            async def cleanup(process, tasks):
                await asyncio.gather(*tasks, return_exceptions=True)
                closed.append(process)
            with self.subTest(failure=failure), \
                    patch('swassh.infrastructure.network.LocalPreflight') as preflight, \
                    patch('swassh.infrastructure.network.launch_native', launch), \
                    patch('swassh.infrastructure.network._cleanup_process', cleanup):
                preflight.return_value.transport.return_value = 'synthetic-ssh'
                async with asyncio.timeout(10):
                    result = await NetworkTransport(Options(command_timeout=10), reboot_procedure()).execute(Host('test'), '')
            self.assertEqual(result.status, expected, result)
            self.assertEqual(len(opened), count)
            self.assertEqual(opened, closed)
            self.assertEqual(opened[0].stdin.write.call_count, 1 if failure == 'mid-command' else 5)
            for process in opened[1:]:
                process.stdin.write.assert_not_called()

    def channel(self, chunks, budget=None):
        process = Mock()
        process.stdout.read = AsyncMock(side_effect=chunks)
        process.stdin.drain = AsyncMock()
        return DeviceDialogue(process, DeviceDriver('cisco_ios'), 4096, 'utf-8', budget)

    async def test_reboot_waits_for_eof_even_after_returned_prompt(self):
        channel = self.channel([b'r#', b'activate\nactivation-accepted\nr#', b'\n', b''])
        await channel.receive()
        output = await channel.execute(reboot_procedure().steps[4])
        self.assertIn('activation-accepted', output)
        self.assertEqual(channel.process.stdout.read.await_count, 4)
        channel.process.stdin.write.assert_called_once_with(b'activate\n')

    async def test_rejected_reboot_or_missing_echo_cannot_authorize_reconnect(self):
        for response in (b'activate\n% Invalid input detected\nr#', b'activation-accepted\n'):
            channel = self.channel([b'r#', response, b''])
            await channel.receive()
            with self.assertRaises(NetworkDialogueError):
                await channel.execute(reboot_procedure().steps[4])

    async def test_exact_version_lines_reject_substrings_and_command_echo(self):
        for value in ('fixture-model\nfixture-new-extra', 'fixture-model\nprevious fixture-new',
                      'fixture-new', 'fixture-model\nverify'):
            channel = self.channel([b'r#', ('verify\n'+value+'\nr#').encode()])
            await channel.receive()
            with self.assertRaises(NetworkDialogueError):
                await channel.execute(reboot_procedure().steps[-1])

    async def test_output_budget_is_not_reset_by_reconnection(self):
        budget = DialogueBudget(5)
        first = self.channel([b'abc#'], budget)
        await first.receive()
        second = self.channel([b'abc#'], budget)
        with self.assertRaisesRegex(NetworkDialogueError, 'budget exceeded'):
            await second.receive()

    async def test_decoder_must_finish_cleanly_at_expected_reboot_eof(self):
        channel = self.channel([b'r#', b'activate\nactivation-accepted\n\xc3', b''])
        await channel.receive()
        with self.assertRaises(UnicodeError):
            await channel.execute(reboot_procedure().steps[4])

    async def test_native_connection_timeout_retries_without_replaying_commands(self):
        """OpenSSH's own pre-auth timeout is as retryable as waiting for a prompt."""
        initial = [b'r#', b'identify\nfixture-model\nfixture-old\nr#',
                   b'backup\nbackup-complete\nr#', b'transfer\ntransfer-complete\nr#',
                   b'checksum\n' + b'a'*64 + b'\nr#', b'activate\nactivation-accepted\n', b'']
        processes = []
        for chunks in (initial, [b''], [b'r#', b'verify\nfixture-model\nfixture-new\nr#']):
            process = Mock(returncode=255)
            process.stdout.read = AsyncMock(side_effect=chunks)
            process.stdin.drain = AsyncMock()
            processes.append(process)
        opened, closed = [], []

        async def launch(*args, **kwargs):
            if len(opened) == 1:
                Path(args[args.index('-E')+1]).write_text('ssh: connect to host test port 22: Connection timed out')
            self.assertEqual(len(opened), len(closed), 'prior lease must close before reconnect')
            process = processes[len(opened)]
            opened.append(process)
            return process

        async def cleanup(process, tasks):
            await asyncio.gather(*tasks, return_exceptions=True)
            closed.append(process)

        with patch('swassh.infrastructure.network.LocalPreflight') as preflight, \
                patch('swassh.infrastructure.network.launch_native', launch), \
                patch('swassh.infrastructure.network._cleanup_process', cleanup):
            preflight.return_value.transport.return_value = 'ssh'
            result = await NetworkTransport(Options(command_timeout=10), reboot_procedure()).execute(Host('test'), '')
        self.assertEqual(result.status, Status.SUCCESS, result)
        self.assertEqual(len(opened), 3)
        self.assertEqual(processes[0].stdin.write.call_count, 5)
        processes[1].stdin.write.assert_not_called()
        processes[2].stdin.write.assert_called_once_with(b'verify\n')


    async def test_reconnect_observes_private_admission_without_extending_the_boot_window(self):
        """Separate local admission from the handshake while preserving outer caps."""
        import tempfile
        import time
        from types import SimpleNamespace
        from swassh.infrastructure.admission_deadline import AdmissionDeadline, publish_admission
        initial=[b'r#',b'identify\nfixture-model\nfixture-old\nr#',
                 b'backup\nbackup-complete\nr#',b'transfer\ntransfer-complete\nr#',
                 b'checksum\n'+b'a'*64+b'\nr#',b'activate\nactivation-accepted\n',b'']
        for mode,expected in (('admitted',Status.SUCCESS),('expired',Status.TIMEOUT),
                              ('invalid',Status.ERROR),('early-exit',Status.ERROR),('window',Status.TIMEOUT)):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as directory:
                opened,closed=[],[]
                ready=asyncio.Event()
                observe=AdmissionDeadline.observe
                async def observed(admission,process):
                    await observe(admission,process)
                    ready.set()
                async def launch(*argv,**kwargs):
                    process=SimpleNamespace(returncode=None,stdin=Mock(),stdout=SimpleNamespace())
                    process.stdin.drain=AsyncMock()
                    reconnect=bool(opened)
                    chunks=iter([b'r#',b'verify\nfixture-model\nfixture-new\nr#'] if reconnect else initial)
                    async def read(size):
                        if reconnect:await ready.wait()
                        return next(chunks)
                    process.stdout.read=AsyncMock(side_effect=read)
                    process._swassh_admission_observation=reconnect
                    if reconnect:
                        process._swassh_guardian=(None,SimpleNamespace(name=directory))
                        process._swassh_guardian_started=time.monotonic()
                        if mode in ('admitted','expired'):publish_admission(directory,mode,0.)
                        elif mode=='invalid':(Path(directory)/'admission.json').write_text('{}')
                        elif mode=='early-exit':process.returncode=125
                        self.assertGreater(kwargs['max_native_seconds'],0)
                    opened.append(process)
                    return process
                async def cleanup(process,tasks):
                    await asyncio.gather(*tasks,return_exceptions=True)
                    closed.append(process)
                policy=ReconnectPolicy(1,1 if mode=='window' else 2,0.1)
                procedure=replace(reboot_procedure(),reconnect=policy)
                started=time.monotonic()
                with patch('swassh.infrastructure.network.LocalPreflight') as preflight, \
                        patch('swassh.infrastructure.network.launch_native',launch), \
                        patch('swassh.infrastructure.network._cleanup_process',cleanup), \
                        patch.object(AdmissionDeadline,'observe',observed):
                    preflight.return_value.transport.return_value='synthetic-ssh'
                    result=await NetworkTransport(Options(command_timeout=5,connect_timeout=2 if mode=='window' else 0.2),procedure).execute(Host('test'),'')
                self.assertEqual(result.status,expected,result)
                self.assertEqual(len(opened),2)
                self.assertEqual(opened,closed)
                self.assertEqual(opened[0].stdin.write.call_count,5)
                if mode=='admitted':
                    opened[1].stdin.write.assert_called_once_with(b'verify\n')
                    self.assertTrue(ready.is_set())
                else:
                    opened[1].stdin.write.assert_not_called()
                    self.assertFalse(ready.is_set())
                if mode=='window':self.assertLess(time.monotonic()-started,2)
