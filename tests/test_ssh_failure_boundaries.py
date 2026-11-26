"""Authentication refusal and input failures must never permit blind replay."""
import asyncio
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch

from swassh import Host, Options, Status
from swassh.infrastructure import ssh


class AuthenticationRefusalTests(unittest.TestCase):
    def test_unavailable_gssapi_ticket_is_not_an_unsupported_option_and_timeout_stays_retryable(self):
        status,message,retry=ssh._outcome(255,'GSSAPI: no credentials available',True,'gssapi')
        self.assertEqual(status,Status.ERROR);self.assertIn('SSH client failed',message);self.assertFalse(retry)
        self.assertEqual(ssh._outcome(255,'connect: operation timed out',True),
            (Status.TIMEOUT,'SSH connection deadline exceeded',True))

    def test_jump_and_target_proxy_commands_receive_the_explicit_wire_lifetime(self):
        options=Options(jump_host=Host('jump',2222,'operator'))
        with patch.object(ssh,'proxy_command',side_effect=lambda host,settings,*,lifetime:'synthetic-proxy '+host.hostname) as proxy:
            config=ssh._config(Host('target'),options,wire_lifetime=17)
        proxy.assert_called_once_with(options.jump_host,options,lifetime=17)
        self.assertIn('ProxyJump swassh-jump',config);self.assertIn('ProxyCommand synthetic-proxy jump',config)
        self.assertIn('StrictHostKeyChecking yes',config);self.assertIn('ForwardAgent no',config)

    def test_connector_discovery_is_limited_to_direct_posix_non_gssapi_connections(self):
        for platform in ('posix','nt'):
            for jump in (None,Host('jump')):
                for auth in ('publickey','gssapi'):
                    options=Options(jump_host=jump,auth_method=auth);port=SimpleNamespace(**vars(os));port.name=platform
                    with self.subTest(platform=platform,jump=jump,auth=auth),patch.object(ssh,'os',port),\
                            patch.object(ssh.LocalPreflight,'transport',return_value='synthetic-ssh'),\
                            patch('swassh.infrastructure.relay_connect.NativeConnector.find',return_value='verified-connector') as find:
                        transport=ssh.SSHTransport(options)
                    eligible=platform=='posix' and jump is None and auth!='gssapi'
                    self.assertEqual(find.call_count,int(eligible))
                    self.assertEqual(transport.relay_connector,'verified-connector' if eligible else None)
                    self.assertIsNone(transport.input);self.assertIsNone(transport.live)

    def test_unsupported_gssapi_options_are_terminal_only_for_requested_gssapi(self):
        for marker in ('unsupported option GSSAPIAuthentication', 'bad configuration option GSSAPIAuthentication'):
            with self.subTest(marker=marker):
                status, message, retry = ssh._outcome(255, marker, True, 'gssapi')
                self.assertEqual(status, Status.AUTH_FAILED)
                self.assertEqual(message, 'OpenSSH client does not support the requested GSSAPI options')
                self.assertFalse(retry)
                self.assertEqual(ssh._outcome(255, marker, True, 'publickey')[0], Status.ERROR)
        self.assertEqual(ssh._outcome(255, 'unsupported option unrelated', True, 'gssapi')[0], Status.ERROR)

    def test_denials_keep_authentication_specific_diagnostics_without_replay(self):
        for auth, expected in (('publickey', 'passwords are disabled'),
                               ('password', 'password authentication denied'),
                               ('gssapi', 'GSSAPI authentication denied')):
            for marker in ('Permission denied', 'No supported authentication methods'):
                with self.subTest(auth=auth, marker=marker):
                    status, message, retry = ssh._outcome(255, marker, True, auth)
                    self.assertEqual(status, Status.AUTH_FAILED)
                    self.assertIn(expected, message); self.assertFalse(retry)

    def test_each_key_failure_is_terminal_and_authentication_evidence_takes_precedence(self):
        markers = ('bad permissions', 'unprotected private key file', 'invalid format', 'error in libcrypto',
                   'agent refused operation', 'sign_and_send_pubkey: signing failed',
                   'incorrect passphrase', 'read_passphrase:', "can't open /dev/tty")
        for marker in markers:
            with self.subTest(marker=marker):
                status, message, retry = ssh._outcome(255, marker, True)
                self.assertEqual(status, Status.AUTH_FAILED); self.assertIsInstance(message, str)
                self.assertFalse(retry)
                status, _, retry = ssh._outcome(255, 'Authenticated to synthetic\n'+marker, True)
                self.assertEqual(status, Status.INTERRUPTED); self.assertFalse(retry)

    def test_config_quote_rejects_each_control_character_and_preserves_literals(self):
        for marker in ('\n', '\r', '\0'):
            with self.subTest(marker=repr(marker)), self.assertRaises(ValueError): ssh._quote('a'+marker+'b')
        self.assertEqual(ssh._quote('a%"\\b'), '"a%%\\"\\\\b"')


class SSHInputFailureTests(unittest.IsolatedAsyncioTestCase):
    async def test_relay_selection_channel_reuse_and_pty_preserve_native_launch_contract(self):
        class ReusedTransport(ssh.SSHTransport):
            def channel_connected(self):return False
        cases=((True,None,'publickey',False),(False,None,'publickey',False),
               (True,Host('jump'),'publickey',False),(True,None,'gssapi',False),
               (True,None,'publickey',True))
        port=SimpleNamespace(**vars(os));port.name='posix'
        for connected,jump,auth,pty in cases:
            options=Options(jump_host=jump,auth_method=auth,pty=pty)
            with patch.object(ssh.LocalPreflight,'transport',return_value='synthetic-ssh'),\
                    patch('swassh.infrastructure.relay_connect.NativeConnector.find',return_value=None):
                transport=(ssh.SSHTransport if connected else ReusedTransport)(options)
            process=SimpleNamespace(stdout=asyncio.StreamReader(),stderr=asyncio.StreamReader(),returncode=0)
            process.stdout.feed_data(b'synthetic output');process.stdout.feed_eof();process.stderr.feed_eof()
            process.wait=AsyncMock(return_value=0);launches=[]
            async def launch(*argv,**kwargs):
                self.assertTrue(Path(argv[argv.index('-F')+1]).is_file());launches.append((argv,kwargs));return process
            async def cleanup(native,tasks):
                self.assertIs(native,process)
                for task in tasks:task.cancel()
                await asyncio.gather(*tasks,return_exceptions=True)
                return {'admission_wait_seconds':1.5,'native_seconds':2.5}
            with self.subTest(connected=connected,jump=jump,auth=auth,pty=pty),\
                    patch.object(ssh,'os',port),patch.object(ssh,'launch_native',side_effect=launch),\
                    patch.object(ssh,'_cleanup_process',side_effect=cleanup),\
                    patch.object(ssh,'native_relay',wraps=ssh.native_relay) as relay:
                result=await transport.execute(Host('synthetic'),'read-only')
            self.assertEqual(result.status,Status.SUCCESS);self.assertEqual(result.attempts,1)
            self.assertEqual(result.stdout,'synthetic output');self.assertEqual(len(launches),1)
            argv,settings=launches[0];self.assertIn('-tt' if pty else '-T',argv)
            self.assertEqual(settings.get('connected',True),connected)
            selected=relay.call_args.args[0]
            self.assertEqual(selected is not None,connected and jump is None and auth!='gssapi')
            if selected is not None:self.assertEqual(selected['host'],'synthetic');self.assertEqual(selected['port'],22)
            self.assertEqual(transport.metrics()['shared_admission_wait_seconds'],1.5)
            self.assertEqual(transport.metrics()['native_client_seconds'],2.5)
            await transport.aclose()

    async def test_remote_stdin_close_is_allowed_but_other_io_errors_remain_visible(self):
        transport = object.__new__(ssh.SSHTransport); transport.input = b'input'
        for error in (BrokenPipeError, ConnectionResetError, OSError):
            writer = Mock(); writer.drain = AsyncMock(side_effect=error('synthetic pipe failure'))
            with self.subTest(error=error.__name__):
                if error is OSError:
                    with self.assertRaisesRegex(OSError, 'synthetic'): await transport._feed(writer)
                else: await transport._feed(writer)
                writer.write.assert_called_once_with(b'input'); writer.close.assert_called_once()

    async def test_interaction_factory_failure_never_launches_native_or_retries(self):
        options = Options()
        with patch.object(ssh.LocalPreflight, 'transport', return_value='synthetic-ssh'), \
                patch('swassh.infrastructure.relay_connect.NativeConnector.find', return_value=None):
            transport = ssh.SSHTransport(options, interaction_factory=Mock(side_effect=RuntimeError('private provider failure')))
        try:
            with patch.object(ssh, 'launch_native', new_callable=AsyncMock) as launch:
                result = await transport.execute(Host('synthetic'), 'read-only')
            self.assertEqual(result.status, Status.ERROR); self.assertEqual(result.attempts, 1)
            self.assertNotIn('private provider failure', result.error)
            launch.assert_not_awaited()
        finally: await transport.aclose()

    async def test_interaction_rejects_retries_and_stdin_before_local_preflight(self):
        for options in (Options(retries=1), Options(stdin_file='synthetic-input')):
            with self.subTest(options=options), patch.object(ssh.LocalPreflight, 'transport') as preflight:
                with self.assertRaisesRegex(ValueError, 'requires no stdin_file and retries=0'):
                    ssh.SSHTransport(options, interaction_factory=Mock())
                preflight.assert_not_called()


    async def test_missing_native_streams_fail_closed_and_release_the_process(self):
        """A failed pipe contract has the same safe result with or without -O."""
        for missing in ('stdout', 'stderr', 'both'):
            with self.subTest(missing=missing):
                options = Options(retries=2)
                with patch.object(ssh.LocalPreflight, 'transport', return_value='synthetic-ssh'), \
                        patch('swassh.infrastructure.relay_connect.NativeConnector.find', return_value=None):
                    transport = ssh.SSHTransport(options)
                process = SimpleNamespace(stdout=asyncio.StreamReader(), stderr=asyncio.StreamReader(), returncode=0)
                for name in ('stdout', 'stderr'):
                    if missing in (name, 'both'):
                        setattr(process, name, None)
                    else:
                        getattr(process, name).feed_eof()
                process.wait = AsyncMock(return_value=0)
                async def cleanup(owned, tasks):
                    self.assertIs(owned, process)
                    self.assertEqual(tasks, [])
                    return {'admission_wait_seconds': 0.25, 'native_seconds': 0.5}
                try:
                    with patch.object(ssh, 'launch_native', new_callable=AsyncMock, return_value=process) as launch, \
                            patch.object(ssh, '_cleanup_process', side_effect=cleanup) as release:
                        result = await transport.execute(Host('synthetic'), 'read-only')
                    self.assertEqual(result.status, Status.ERROR)
                    self.assertEqual(result.error, 'SSH client I/O or diagnostic error; remote state may be unknown')
                    self.assertEqual(result.attempts, 1)
                    self.assertEqual(result.stdout, '')
                    self.assertEqual(result.stderr, '')
                    launch.assert_awaited_once()
                    release.assert_awaited_once()
                    self.assertEqual(transport.metrics()['native_client_seconds'], 0.5)
                finally:
                    await transport.aclose()
