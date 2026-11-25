"""Device procedure safety contracts; fixtures are not hardware certification."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, Mock, patch

from swassh import Host, NetworkProcedure, NetworkStep, NetworkSwarm, Options
from swassh.domain.network import PLATFORMS
from swassh.infrastructure.network import DeviceDriver, DeviceDialogue, NetworkDialogueError
from swassh.interfaces.cli import main


def procedure(platform='cisco_ios'):
    return NetworkProcedure(platform, 'administration',
                            (NetworkStep('identify', 'show version', ('fixture-version',)),))


PROMPTS = dict.fromkeys(PLATFORMS, 'router#') | {
    'juniper_junos': 'operator@router>', 'aruba_os': '(router) [mynode] #',
    'huawei_vrp': '<router>', 'fortinet_fortios': 'router #'}


class ProcedureContracts(unittest.TestCase):
    def test_decode_rejects_wrong_input_type_and_more_than_one_thousand_steps(self):
        with self.assertRaisesRegex(ValueError, 'exceeds 1 MiB'):
            NetworkProcedure.decode('not bytes')
        valid = procedure().to_dict()
        with self.assertRaisesRegex(ValueError, 'invalid network steps'):
            NetworkProcedure.decode(json.dumps(valid | {'steps': valid['steps'] * 1001}).encode())

    def test_invalid_procedure_and_non_string_approval_fail_before_network_creation(self):
        with self.assertRaisesRegex(ValueError,'validated NetworkProcedure'):NetworkSwarm(object())
        service=NetworkSwarm(procedure())
        for token in (None,True,42,b'a'*64):
            with self.subTest(token=token),self.assertRaisesRegex(ValueError,'approval does not match'):
                service._approved([Host('one')],token)

    def test_every_explicit_platform_round_trips(self):
        for platform in PLATFORMS:
            with self.subTest(platform=platform):
                original = procedure(platform)
                self.assertEqual(NetworkProcedure.decode(json.dumps(original.to_dict()).encode()), original)

    def test_unknown_duplicate_oversized_and_nested_json_fail_closed(self):
        rows = [b'{}', b'[]', b'{"platform":"a","platform":"b"}', b'x'*1048577,
                b'['*2000 + b']'*2000, b'\xff']
        valid = procedure().to_dict()
        for change in ({'platform': 'guess'}, {'operation': 'guess'}, {'steps': []}, {'steps': 'x'},
                       {'unknown': True}, {'image_sha256': 'a'*64}):
            rows.append(json.dumps(valid | change).encode())
        for raw in rows:
            with self.subTest(raw=raw[:60]), self.assertRaises(ValueError):
                NetworkProcedure.decode(raw)

    def test_missing_evidence_stage_order_and_control_injection_rejected(self):
        for step in ({'stage': 'identify', 'command': 'a\nb', 'expect': ['x']},
                     {'stage': 'identify', 'command': 'a', 'expect': 'x'},
                     {'stage': 'identify', 'command': 'a', 'expect': []},
                     {'stage': 'verify', 'command': 'a', 'expect': ['x']},
                     {'stage': 'identify', 'command': '', 'expect': ['x']},
                     {'stage': 'identify', 'command': 'a', 'expect': ['x'], 'until': 'confirm?'},
                     {'stage': 'identify', 'command': 'a', 'expect': ['x'], 'secret': 'x'}):
            with self.subTest(step=step), self.assertRaises(ValueError):
                NetworkProcedure.decode(json.dumps(procedure().to_dict() | {'steps': [step]}).encode())
        with self.assertRaises(ValueError):
            NetworkProcedure('cisco_ios', 'configuration', procedure().steps)
        with self.assertRaises(ValueError):
            NetworkProcedure('cisco_ios', 'administration', (
                *procedure().steps, NetworkStep('verify', 'a', ('x',)), NetworkStep('prepare', 'b', ('y',))))

    def test_firmware_requires_backup_transfer_digest_activation_and_verification(self):
        stages = ('identify', 'backup', 'transfer', 'checksum', 'activate', 'verify')
        digest = 'a'*64
        evidence = {'identify': ('fixture-model', 'fixture-old'), 'checksum': (digest,), 'verify': ('fixture-new',)}
        steps = tuple(NetworkStep(stage, stage, evidence.get(stage, ('evidence',))) for stage in stages)
        identity = dict(model='fixture-model', current_version='fixture-old', target_version='fixture-new',
                        recovery='Use isolated fixture console to restore saved fixture state')
        plan = NetworkProcedure('juniper_junos', 'firmware', steps, digest, **identity)
        self.assertEqual(plan.image_sha256, digest)
        self.assertEqual(NetworkProcedure.decode(json.dumps(plan.to_dict()).encode()), plan)
        for missing in range(len(steps)):
            with self.assertRaises(ValueError):
                NetworkProcedure('juniper_junos', 'firmware', steps[:missing]+steps[missing+1:], digest, **identity)
        for value in (None, 'wrong', 'b'*64):
            with self.assertRaises(ValueError):
                NetworkProcedure('juniper_junos', 'firmware', steps, value, **identity)
        for field in identity:
            with self.assertRaises(ValueError):
                NetworkProcedure('juniper_junos', 'firmware', steps, digest, **(identity | {field: None}))

    def test_approval_binds_target_order_and_content(self):
        service = NetworkSwarm(procedure())
        hosts = [Host('one'), Host('two')]
        digest = service.plan(hosts)['approval_sha256']
        self.assertEqual(service._approved(hosts, digest), tuple(hosts))
        for targets, token in [(hosts[::-1], digest), (hosts, 'é'*64), (hosts, '0'*64), (hosts[:1], digest)]:
            with self.assertRaises(ValueError):
                service._approved(targets, token)
        for options in (Options(retries=1), Options(stdin_file='file'), Options(stream_output=True)):
            with self.assertRaises(ValueError):
                NetworkSwarm(procedure(), options)
        with self.assertRaises(ValueError):
            NetworkSwarm(procedure(), Options(encoding='utf-16')).plan(hosts)
        non_ascii = NetworkProcedure('cisco_ios', 'administration', (
            NetworkStep('identify', 'show café', ('fixture',)),))
        with self.assertRaises(UnicodeError):
            NetworkSwarm(non_ascii, Options(encoding='ascii')).plan(hosts)

    def test_cli_default_review_never_connects_and_invalid_apply_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'procedure.json'
            path.write_text(json.dumps(procedure().to_dict()), encoding='utf-8')
            output = io.StringIO()
            with patch('swassh.interfaces.network.NetworkTransport') as transport, \
                    contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(['network', '--procedure', str(path), '-H', 'one']), 0)
                review = json.loads(output.getvalue())
                self.assertEqual(review['targets'], ['one:22'])
                self.assertEqual(len(review['approval_sha256']), 64)
                transport.assert_not_called()
                self.assertEqual(main(['network', '--procedure', str(path), '-H', 'one', '--apply', '0'*64, '--plan-only']), 2)


class DialogueContracts(unittest.IsolatedAsyncioTestCase):
    async def test_unsupported_driver_unsafe_options_and_c1_terminal_controls_fail_closed(self):
        from swassh.infrastructure.network import NetworkTransport
        with self.assertRaisesRegex(ValueError, 'unsupported network platform'):
            DeviceDriver('guessed-platform')
        for options in (Options(stdin_file='input'), Options(stream_output=True), Options(retries=1)):
            with patch('swassh.infrastructure.network.LocalPreflight.transport') as launch, \
                    self.assertRaisesRegex(ValueError, 'reject stdin injection'):
                NetworkTransport(options, procedure())
            launch.assert_not_called()
        driver = DeviceDriver('huawei_vrp')
        self.assertTrue(driver.prompt('<router>'))
        self.assertTrue(driver.prompt('[router]'))
        self.assertFalse(driver.prompt('[foreign]'))
        channel = self.channel('cisco_ios', [b'router#', 'cmd\n\u0085\nrouter#'.encode()])
        await channel.receive()
        with self.assertRaisesRegex(NetworkDialogueError, 'terminal control sequence'):
            await channel.execute(NetworkStep('identify', 'cmd', ('evidence',)))
        channel = self.channel('cisco_ios', [b'router#', b'checksum\nverified\nrouter#'])
        await channel.receive()
        self.assertEqual(await channel.execute(NetworkStep('checksum', 'checksum', ('verified',))), 'verified')

    def channel(self, platform, chunks, limit=65536):
        process = Mock()
        process.stdout.read = AsyncMock(side_effect=[*chunks, b''])
        process.stdin.drain = AsyncMock()
        return DeviceDialogue(process, DeviceDriver(platform), limit, 'utf-8')

    async def test_all_platform_prompts_and_fragmented_responses(self):
        for platform, prompt in PROMPTS.items():
            with self.subTest(platform=platform):
                channel = self.channel(platform, [prompt.encode(), b'show ver', b'sion\r\nfixture-',
                                                  b'version\r\n', prompt.encode()])
                self.assertEqual(await channel.receive(), '')
                output = await channel.execute(procedure(platform).steps[0])
                self.assertEqual(output, 'fixture-version')
                channel.process.stdin.write.assert_called_once_with(b'show version\n')

    async def test_echo_cannot_satisfy_evidence_and_failed_output_is_retained(self):
        channel = self.channel('cisco_ios', [b'router#', b'show version\nno evidence\nrouter#'])
        await channel.receive()
        with self.assertRaises(NetworkDialogueError) as caught:
            await channel.execute(NetworkStep('identify', 'show version', ('show version',)))
        self.assertEqual(caught.exception.output, 'no evidence')

    async def test_stale_prompt_paging_controls_and_limits_fail_closed(self):
        for chunks, limit in [([b'router#', b'router#'], 65536),
                              ([b'router#', b'cmd\n--More--'], 65536),
                              ([b'router#', b'cmd\n\x1b]2;title\x07\nrouter#'], 65536),
                              ([b'router#', b'cmd\n' + b'x'*40], 24),
                              ([b'router#', b'cmd\nother#'], 65536),
                              ([b'router#', b'cmd\n% Invalid input detected\nrouter#'], 65536)]:
            channel = self.channel('cisco_ios', chunks, limit)
            await channel.receive()
            with self.assertRaises(NetworkDialogueError):
                await channel.execute(NetworkStep('identify', 'cmd', ('evidence',)))

    async def test_explicit_question_and_reply_are_serialized(self):
        channel = self.channel('cisco_ios', [b'router#', b'copy\nready\nDestination?',
                                           b'\ncomplete\nrouter#'])
        await channel.receive()
        self.assertEqual(await channel.execute(NetworkStep('transfer', 'copy', ('ready',), 'Destination?')), 'ready')
        self.assertEqual(await channel.execute(NetworkStep('transfer', '', ('complete',))), 'complete')
        self.assertEqual(channel.process.stdin.write.call_count, 2)

    async def test_explicit_empty_confirmation_can_finish_with_no_output_body(self):
        channel = self.channel('cisco_ios', [b'router#', b'copy\nready\nDestination?', b'router#'])
        await channel.receive()
        self.assertEqual(await channel.execute(NetworkStep('transfer', 'copy', ('ready',), 'Destination?')), 'ready')
        self.assertEqual(await channel.execute(NetworkStep('transfer', '', ())), '')
        self.assertEqual([call.args[0] for call in channel.process.stdin.write.call_args_list], [b'copy\n', b'\n'])


    async def test_sha256_is_a_complete_digest_not_an_echo_or_hex_substring(self):
        digest = 'a'*64
        for output, accepted in [(digest.upper(), True), ('b'+digest, False), (digest+'0', False), ('wrong', False)]:
            channel = self.channel('cisco_ios', [b'router#', ('checksum\n'+output+'\nrouter#').encode()])
            await channel.receive()
            step = NetworkStep('checksum', 'checksum', (digest,))
            if accepted:
                self.assertEqual(await channel.execute(step), output)
            else:
                with self.assertRaises(NetworkDialogueError):
                    await channel.execute(step)

    async def test_ansi_fragments_and_large_output_do_not_corrupt_evidence(self):
        output = b'x'*20000 + b'\nfixture-version\n'
        channel = self.channel('cisco_ios', [b'router#', b'show version\n\x1b[', b'32m',
                                           *[output[i:i+1000] for i in range(0, len(output), 1000)],
                                           b'\x1b[0mrouter#'])
        await channel.receive()
        self.assertIn('fixture-version', await channel.execute(procedure().steps[0]))

    async def test_configuration_prompts_remain_bound_to_original_identity(self):
        for platform, first, next_prompt in [('cisco_ios', 'r#', 'r(config-if)#'),
                                             ('huawei_vrp', '<r>', '[*r-interface]'),
                                             ('fortinet_fortios', 'r #', 'r (interface) #')]:
            driver = DeviceDriver(platform)
            self.assertTrue(driver.prompt(first))
            self.assertTrue(driver.prompt(next_prompt))
            self.assertFalse(driver.prompt('other#'))
