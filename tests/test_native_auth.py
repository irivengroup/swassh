"""Native authentication tests require the explicitly isolated QA harness."""
import os
import sys
import unittest
import subprocess
from pathlib import Path
from dataclasses import replace
from unittest.mock import patch
import test_native_ssh as fixture
from swassh import Host, Options, Status, Swarm


@unittest.skipUnless(sys.platform.startswith('linux') and os.environ.get('SWASSH_TEST_PASSWORD_USER') and os.environ.get('SWASSH_TEST_KERBEROS'), 'isolated native authentication realm required')
class NativeAuthenticationTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        fixture.NativeSSHTests.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        fixture.NativeSSHTests.tearDownClass.__func__(cls)

    @unittest.skipUnless(os.environ.get('SWASSH_TEST_PASSWORD_USER'), 'isolated password account not provisioned')
    async def test_real_password_provider_and_sftp(self):
        from swassh import FileSwarm, FileTransfer, TransferDirection, TransferSettings
        options = Options(auth_method='password', askpass_executable=os.environ['SWASSH_TEST_ASKPASS'],
            username=os.environ['SWASSH_TEST_PASSWORD_USER'], known_hosts=str(self.root/'known_hosts'))
        host = Host('127.0.0.1', self.port)
        result = (await Swarm(options).run([host], "printf 'password-ok'" )).results[0]
        self.assertEqual(result.status, Status.SUCCESS)
        self.assertEqual(result.stdout, 'password-ok')
        source = self.root/'password-source'
        source.write_bytes(b'password-transfer-fixture')
        remote = os.environ['SWASSH_TEST_REMOTE_HOME']+'/transfer'
        report = await FileSwarm(options, TransferSettings(rsync_executable='missing-rsync', verify_sha256=True)).run([host], FileTransfer(TransferDirection.PUSH, str(source), remote))
        self.assertTrue(report.ok, [r.error for r in report.results])
        # A refused credential must not be retried or described as a broken helper.
        provider = self.root/'wrong-password-provider'
        provider.write_text('#!/bin/sh\nprintf invalid-fixture-credential\n')
        provider.chmod(0o700)
        denied = (await Swarm(replace(options, askpass_executable=str(provider))).run([host], 'true')).results[0]
        self.assertEqual(denied.status, Status.AUTH_FAILED)
        self.assertIn('authentication denied', denied.error)
        self.assertEqual(denied.attempts, 1)

    @unittest.skipUnless(os.environ.get('SWASSH_TEST_KERBEROS'), 'isolated Kerberos realm not provisioned')
    async def test_real_kerberos_ticket(self):
        options = Options(auth_method='gssapi', username=self.username, known_hosts=str(self.root/'known_hosts'))
        result = (await Swarm(options).run([Host('localhost', self.port)], "printf 'kerberos-ok'")).results[0]
        detail = result.error
        if result.status != Status.SUCCESS:
            from swassh.infrastructure.ssh import _config
            config = self.root/'kerberos-probe'
            config.write_text(_config(Host('localhost', self.port), options))
            probe = subprocess.run([fixture.NativeTools.require('ssh'), '-F', str(config), '-vvv', '-T', 'swassh-target', 'true'],
                env=fixture.NativeTools.environment(KRB5_TRACE='/dev/stderr'), capture_output=True, text=True, timeout=10)
            detail = '\n'.join(line for line in probe.stderr.splitlines() if any(
                word in line.lower() for word in ('gss', 'kerberos', 'principal', 'credential', 'ticket', 'server not found')))
        self.assertEqual(result.status, Status.SUCCESS, detail)
        self.assertEqual(result.stdout, 'kerberos-ok')
        with patch.dict(os.environ, {'KRB5CCNAME': 'FILE:'+str(self.root/'missing-ticket-cache')}):
            denied = (await Swarm(options).run([Host('localhost', self.port)], 'true')).results[0]
        self.assertEqual(denied.status, Status.AUTH_FAILED)
        self.assertEqual(denied.attempts, 1)




@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux authentication fixture helper')
class AuthenticationFixtureProviderTests(unittest.TestCase):
    """Execute the generated helper without creating accounts or a KDC.

    Only account management, mount metadata and the later network setup are
    intercepted. Private files and the provider shell execute for real; the
    complete namespace gate separately exercises real authentication.
    """

    def provider(self, name):
        import runpy
        import tempfile
        from pathlib import Path
        from types import SimpleNamespace
        module = SimpleNamespace(**runpy.run_path(str(Path(__file__).resolve().parents[1] / 'scripts/auth_fixture.py')))
        temporary = tempfile.TemporaryDirectory(prefix='swassh-auth-provider-')
        self.addCleanup(temporary.cleanup)
        base = Path(temporary.name)
        workspace = base / name
        workspace.mkdir(mode=0o700)
        mounts = ('1 0 0:1 / /etc rw - overlay overlay rw\n'
                  '2 0 0:2 / /root rw - tmpfs tmpfs rw\n')
        account = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
        stop = OSError('stop before KDC or network provisioning')
        with patch.object(module.Path, 'read_text', return_value=mounts), \
                patch.object(module.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'', b'')) as account_command, \
                patch('pwd.getpwnam', return_value=account), patch.object(module.os, 'chown'), \
                patch.object(module.socket, 'socket', side_effect=stop):
            with self.assertRaises(OSError) as raised:
                module.provision_realm(workspace)
        self.assertIs(raised.exception, stop)
        self.assertEqual(account_command.call_count, 2)
        self.assertEqual([call.args[0][0] for call in account_command.call_args_list], ['useradd', 'chpasswd'])
        helper, secret = workspace / 'authentication/askpass', workspace / 'authentication/password'
        self.assertTrue(helper.is_file())
        self.assertTrue(secret.is_file())
        return base, helper, secret

    def execute(self, base, helper, *, environment=None):
        return subprocess.run([str(helper)], cwd=base, env=environment,
                              capture_output=True, timeout=5)

    def test_spaces_and_quotes_are_literal_secret_path_characters(self):
        for name in ('space in workspace', "single'quote"):
            with self.subTest(name=name):
                base, helper, secret = self.provider(name)
                result = self.execute(base, helper)
                self.assertEqual(result.returncode, 0)
                self.assertEqual(result.stdout, secret.read_bytes())
                self.assertEqual(result.stderr, b'')

    def test_path_command_substitutions_are_never_executed(self):
        for name in ('literal$(touch injected-marker)', 'literal`touch injected-marker`'):
            with self.subTest(name=name):
                base, helper, secret = self.provider(name)
                result = self.execute(base, helper)
                self.assertFalse((base / 'injected-marker').exists(), 'secret path executed as shell syntax')
                self.assertEqual(result.returncode, 0)
                self.assertEqual(result.stdout, secret.read_bytes())
                self.assertEqual(result.stderr, b'')

    def test_provider_does_not_resolve_cat_from_the_environment_path(self):
        base, helper, secret = self.provider('ordinary')
        binaries = base / 'bin'
        binaries.mkdir(mode=0o700)
        hostile = binaries / 'cat'
        hostile.write_text('#!/bin/sh\n: > injected-marker\nprintf unexpected\n', encoding='utf-8')
        hostile.chmod(0o700)
        result = self.execute(base, helper, environment={**os.environ, 'PATH': str(binaries)})
        self.assertFalse((base / 'injected-marker').exists(), 'helper searched PATH for its reader')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, secret.read_bytes())
        self.assertEqual(result.stderr, b'')

    def test_provider_remains_private_and_fails_if_the_secret_is_missing(self):
        import stat
        base, helper, secret = self.provider('ordinary')
        self.assertEqual(stat.S_IMODE(helper.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(secret.stat().st_mode), 0o600)
        contents = secret.read_bytes()
        self.assertNotIn(contents, helper.read_bytes())
        secret.unlink()
        result = self.execute(base, helper)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'')
        self.assertNotIn(contents, result.stderr)



import contextlib


class NativeToolLookupTests(unittest.TestCase):
    """Exercise lookup failures and the Windows API boundary without launching tools."""

    def test_missing_system_tool_and_unknown_names_never_fall_back_to_path(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            trusted, hostile = root/'trusted', root/'hostile'
            trusted.mkdir(); hostile.mkdir()
            for name in ('ssh', 'ssh.exe'):
                (hostile/name).write_bytes(b'unexecuted hostile prerequisite')
                (hostile/name).chmod(0o700)
            with patch.object(fixture.NativeTools, 'search_path', return_value=str(trusted)), \
                    patch.dict(os.environ, {'PATH': str(hostile)}):
                self.assertIsNone(fixture.NativeTools.find('ssh'))
                with self.assertRaisesRegex(RuntimeError, 'prerequisite'):
                    fixture.NativeTools.require('ssh')
                for name in ('../ssh', '/bin/ssh', 'unknown', 'ssh.exe'):
                    with self.subTest(name=name), self.assertRaises(ValueError):
                        fixture.NativeTools.find(name)

    def test_windows_directory_uses_bounded_os_result_not_environment(self):
        from types import SimpleNamespace
        class Query:
            def __init__(self, value, length):
                self.value, self.length = value, length
            def __call__(self, buffer, capacity):
                if capacity != 32768:
                    raise AssertionError('system directory query lost its bound')
                buffer.value = self.value
                return self.length
        with patch.dict(os.environ, {'SystemRoot': 'Z:\\hostile', 'WINDIR': 'Z:\\hostile'}):
            for value, length, accepted in ((r'C:\Windows\System32', 19, True),
                    ('', 0, False), (r'C:\Windows\System32', 32768, False),
                    ('relative', 8, False)):
                query = Query(value, length)
                with self.subTest(value=value, length=length), \
                        patch('swassh.infrastructure.windows.kernel32',
                              return_value=SimpleNamespace(GetSystemDirectoryW=query)):
                    if accepted:
                        self.assertEqual(fixture.NativeTools.windows_directory(), value)
                    else:
                        with self.assertRaises(OSError):
                            fixture.NativeTools.windows_directory()
                self.assertEqual(len(query.argtypes), 2)


@unittest.skipUnless(sys.platform.startswith('linux'), 'POSIX native prerequisite substitution')
class NativePrerequisiteBoundaryTests(unittest.TestCase):
    """Run harmless trusted and hostile programs through the original QA callers.

    Only the trusted directory is injected. Server, account and network effects
    are intercepted; executable selection and the programs themselves are real.
    """

    @contextlib.contextmanager
    def prerequisites(self, target):
        import shlex
        import tempfile
        from pathlib import Path
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory(prefix='swassh-native-tools-') as temporary:
            base = Path(temporary)
            trusted, hostile = base/'trusted', base/'hostile'
            trusted.mkdir(mode=0o700); hostile.mkdir(mode=0o700)
            marker = base/'substituted-tool-executed'
            bodies = {'ssh': "printf 'swassh.infrastructure.tcp_proxy\\n'\n",
                'ssh-keygen': 'while [ "$1" != "-f" ]; do shift; done\nshift\nprintf key > "$1.pub"\n',
                'rsync': "printf 'rsync  version 3.5.0  protocol version 32\\n'\n",
                'sshd': 'exit 0\n'}
            for name, body in bodies.items():
                for directory in (trusted, hostile):
                    attack = ': > '+shlex.quote(str(marker))+'\n' if directory == hostile and name == target else ''
                    program = directory/name
                    program.write_text('#!/bin/sh\n'+attack+body, encoding='utf-8')
                    program.chmod(0o700)
            calls, native_run = [], subprocess.run
            def launch(argv, **settings):
                calls.append((list(argv), settings))
                return native_run(argv, **settings)
            server = SimpleNamespace(poll=lambda: None, terminate=lambda: None, wait=lambda **_: 0)
            proxy = SimpleNamespace(run=launch, Popen=lambda *_, **__: server)
            with patch.object(fixture.NativeTools, 'search_path', return_value=str(trusted)), \
                    patch.dict(os.environ, {'PATH': str(hostile)+os.pathsep+str(trusted)}), \
                    patch.object(fixture, 'subprocess', proxy), \
                    patch.object(sys.modules[__name__], 'subprocess', proxy):
                yield SimpleNamespace(base=base, trusted=trusted, marker=marker, calls=calls, launch=launch)

    @contextlib.contextmanager
    def server_boundary(self):
        from types import SimpleNamespace
        class LocalSocket:
            def __enter__(self): return self
            def __exit__(self, *_): return False
            def bind(self, address):
                if address != ('127.0.0.1', 0):
                    raise AssertionError('fixture endpoint changed')
            def getsockname(self): return ('127.0.0.1', 12345)
        with patch.object(fixture, 'socket', SimpleNamespace(socket=LocalSocket,
                create_connection=lambda *_, **__: contextlib.nullcontext())), \
                patch.object(fixture.os, 'geteuid', return_value=1):
            yield

    def assert_trusted(self, case, name, *, timeout=None):
        self.assertFalse(case.marker.exists(), 'caller PATH executed a substituted prerequisite')
        calls = [(argv, settings) for argv, settings in case.calls if Path(argv[0]).name == name]
        self.assertTrue(calls, 'original prerequisite caller did not execute')
        for argv, settings in calls:
            self.assertEqual(argv[0], str(case.trusted/name))
            self.assertEqual(settings['env']['PATH'], str(case.trusted))
            if timeout is not None:
                self.assertEqual(settings['timeout'], timeout)

    def test_key_generation_never_executes_caller_path_program(self):
        from types import SimpleNamespace
        with self.prerequisites('ssh-keygen') as case:
            owner = SimpleNamespace()
            try:
                with patch.object(fixture.socket, 'socket', side_effect=OSError('controlled socket boundary')):
                    with self.assertRaisesRegex(OSError, 'controlled socket'):
                        fixture.NativeSSHTests.setUpClass.__func__(owner)
                self.assert_trusted(case, 'ssh-keygen')
                self.assertEqual(len(case.calls), 2)
                self.assertTrue(all(settings['check'] for _, settings in case.calls))
            finally:
                if hasattr(owner, 'directory'): owner.directory.cleanup()

    def test_preflight_probe_never_executes_caller_path_program(self):
        from types import SimpleNamespace
        with self.prerequisites('ssh') as case, self.server_boundary():
            owner = SimpleNamespace()
            try:
                fixture.NativeSSHTests.setUpClass.__func__(owner)
                self.assert_trusted(case, 'ssh', timeout=5)
                self.assertTrue(case.calls[-1][1]['capture_output'])
            finally:
                if hasattr(owner, 'server'): fixture.NativeSSHTests.tearDownClass.__func__(owner)
                elif hasattr(owner, 'directory'): owner.directory.cleanup()

    def test_rsync_version_probe_keeps_original_version_guard_and_trusted_program(self):
        with self.prerequisites('rsync') as case:
            fixture.NativeSSHTests.require_rsync(self)
            self.assert_trusted(case, 'rsync')
            self.assertEqual(case.calls[0][0][1:], ['--version'])
            self.assertTrue(case.calls[0][1]['check'])

    def test_configuration_parser_never_executes_caller_path_program(self):
        import test_bandwidth
        from types import SimpleNamespace
        with self.prerequisites('ssh') as case, patch.object(test_bandwidth, 'subprocess',
                SimpleNamespace(run=case.launch)):
            original = test_bandwidth.RelayIntegrationTests(
                'test_openssh_accepts_private_proxy_configuration_without_connecting')
            try:
                original.setUp()
                original.test_openssh_accepts_private_proxy_configuration_without_connecting()
                self.assert_trusted(case, 'ssh', timeout=5)
                self.assertEqual(len(case.calls), 2)
            finally:
                original.doCleanups()

    def test_failed_kerberos_diagnostic_never_executes_caller_path_program(self):
        import asyncio
        from types import SimpleNamespace
        class DiagnosticObserved(Exception):
            """Stop after the real diagnostic, before the expected authentication failure."""
        with self.prerequisites('ssh') as case:
            def diagnostic(argv, **settings):
                case.launch(argv, **settings)
                raise DiagnosticObserved()
            async def denied(*_, **__):
                return SimpleNamespace(results=[SimpleNamespace(status=Status.AUTH_FAILED, error='controlled')])
            original = NativeAuthenticationTests('test_real_kerberos_ticket')
            original.root, original.username, original.port = case.base, 'fixture-user', 12345
            method = NativeAuthenticationTests.test_real_kerberos_ticket
            while hasattr(method, '__wrapped__'): method = method.__wrapped__
            with patch.object(Swarm, 'run', side_effect=denied), \
                    patch.object(sys.modules[__name__], 'subprocess', SimpleNamespace(run=diagnostic)):
                with self.assertRaises(DiagnosticObserved):
                    asyncio.run(method(original))
            self.assert_trusted(case, 'ssh', timeout=10)
            self.assertEqual(case.calls[0][1]['env']['KRB5_TRACE'], '/dev/stderr')


@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux authentication tool boundary')
class AuthenticationToolBoundaryTests(unittest.TestCase):
    """Execute harmless tool substitutes; intercept all account and fixture work.

    The trusted search directory is injected only for this hermetic test. Both
    trusted and hostile programs are real private files; none performs mounts,
    namespace creation, account changes or network operations. The complete
    authentication gate separately executes the actual installed system tools.
    """

    @contextlib.contextmanager
    def scenario(self, *, missing=None):
        import importlib.util
        import shlex
        import tempfile
        from pathlib import Path
        from types import SimpleNamespace
        script=Path(__file__).resolve().parents[1]/'scripts/native_auth_gate.py'
        spec=importlib.util.spec_from_file_location('authentication_tool_boundary',script)
        module=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory(prefix='swassh-auth-tools-') as temporary:
            base=Path(temporary);trusted=base/'trusted';hostile=base/'hostile'
            trusted.mkdir(mode=0o700);hostile.mkdir(mode=0o700)
            marker=base/'substituted-tool-executed'
            for name in ('mount','ip','unshare','krb5kdc'):
                if name!=missing:
                    program=trusted/name
                    program.write_text('#!/bin/sh\nexit 0\n',encoding='utf-8')
                    program.chmod(0o700)
                program=hostile/name
                program.write_text('#!/bin/sh\nprintf substituted >> '+shlex.quote(str(marker))+'\nexit 0\n',encoding='utf-8')
                program.chmod(0o700)
            calls=[]
            def launch(argv, *args, **kwargs):
                calls.append((list(argv),dict(kwargs)))
                return subprocess.run(argv,*args,**kwargs)
            inherited_paths=[]
            account=unittest.mock.Mock(side_effect=lambda _: inherited_paths.append(os.environ['PATH']) or {})
            network=unittest.mock.Mock(return_value=0)
            fake_os=SimpleNamespace(getpid=lambda:1,geteuid=lambda:0,environ=os.environ)
            fake_sys=SimpleNamespace(platform='linux',executable=sys.executable)
            with patch.dict(os.environ,{'PATH':str(hostile)}), \
                    patch.object(module,'_SYSTEM_TOOL_PATH',str(trusted),create=True), \
                    patch.object(module,'os',fake_os),patch.object(module,'sys',fake_sys), \
                    patch.object(module,'subprocess',SimpleNamespace(run=launch)), \
                    patch.dict(sys.modules,{'auth_fixture':SimpleNamespace(provision_realm=account),
                        'native_network_gate':SimpleNamespace(NativeNetworkGate=lambda:SimpleNamespace(run=network))}):
                yield SimpleNamespace(module=module,gate=module.AuthenticationGate(),base=base,
                    trusted=trusted,marker=marker,calls=calls,account=account,network=network,inherited_paths=inherited_paths,
                    os=fake_os,sys=fake_sys)

    def test_namespace_entry_never_executes_unshare_from_caller_path(self):
        with self.scenario() as case:
            self.assertEqual(case.gate.run(),0)
            self.assertFalse(case.marker.exists(),'caller PATH ran before isolation')
            self.assertEqual(len(case.calls),1)
            argv,settings=case.calls[0]
            self.assertEqual(argv[0],str(case.trusted/'unshare'))
            self.assertEqual(argv[1:9],['--mount','--pid','--net','--fork','--kill-child','--mount-proc','--propagation','private'])
            self.assertEqual(argv[-2],'--isolated')
            self.assertEqual(settings.get('timeout'),180)
            self.assertEqual(settings.get('env',{}).get('PATH'),str(case.trusted))
            self.assertEqual(set(settings),{'timeout','env'})
            case.account.assert_not_called();case.network.assert_not_called()

    def test_isolated_mounts_and_loopback_never_execute_tools_from_caller_path(self):
        with self.scenario() as case:
            workspace=case.base/'workspace';workspace.mkdir()
            self.assertEqual(case.gate.isolated(str(workspace)),0)
            self.assertFalse(case.marker.exists(),'caller PATH replaced mount or ip')
            self.assertEqual(len(case.calls),3)
            self.assertEqual([row[0][0] for row in case.calls],
                [str(case.trusted/'mount'),str(case.trusted/'mount'),str(case.trusted/'ip')])
            self.assertEqual(case.calls[0][0][1:],['-t','overlay','overlay','-o',
                f'lowerdir=/etc,upperdir={workspace}/upper,workdir={workspace}/work','/etc'])
            self.assertEqual(case.calls[1][0][1:],['-t','tmpfs','-o','mode=0700','tmpfs','/root'])
            self.assertEqual(case.calls[2][0][1:],['link','set','lo','up'])
            self.assertTrue(all(settings=={'check':True} for _,settings in case.calls))
            self.assertEqual(case.inherited_paths,[str(case.trusted)])
            case.account.assert_called_once_with(workspace)
            case.network.assert_called_once_with('test_native_auth.py')

    def test_missing_trusted_program_fails_before_any_launch_without_path_fallback(self):
        with self.scenario(missing='unshare') as case:
            with self.assertRaisesRegex(RuntimeError,'prerequisite'):
                case.gate.run()
            self.assertEqual(case.calls,[])
            self.assertFalse(case.marker.exists())
            case.account.assert_not_called();case.network.assert_not_called()

    def test_platform_privilege_and_pid_boundaries_remain_fatal_before_tool_execution(self):
        with self.scenario() as case:
            case.sys.platform='win32'
            with self.assertRaisesRegex(RuntimeError,'Linux root'):
                case.gate.run()
            case.sys.platform='linux';case.os.geteuid=lambda:1
            with self.assertRaisesRegex(RuntimeError,'Linux root'):
                case.gate.run()
            case.os.getpid=lambda:2
            with self.assertRaisesRegex(RuntimeError,'PID namespace'):
                case.gate.isolated(str(case.base/'must-not-exist'))
            self.assertFalse((case.base/'must-not-exist').exists())
            self.assertEqual(case.calls,[])
            self.assertFalse(case.marker.exists())


    @contextlib.contextmanager
    def realm(self, case, *, stop_before_socket=False):
        import importlib.util
        from pathlib import Path
        from types import SimpleNamespace
        script=Path(__file__).resolve().parents[1]/'scripts/auth_fixture.py'
        spec=importlib.util.spec_from_file_location('realm_tool_boundary',script)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        commands=unittest.mock.Mock(return_value=subprocess.CompletedProcess([],0,b'',b''))
        daemons=[]
        def daemon(argv, **settings):
            daemons.append((list(argv),settings))
            subprocess.run(argv,**settings,timeout=5)
            return SimpleNamespace(poll=lambda:0)
        class LocalSocket:
            def __enter__(self):return self
            def __exit__(self,*args):return False
            def bind(self,address):
                if address!=('127.0.0.1',0):raise AssertionError('fixture address changed')
            def getsockname(self):return ('127.0.0.1',12345)
        mounts=('1 0 0:1 / /etc rw - overlay overlay rw\n'
                '2 0 0:2 / /root rw - tmpfs tmpfs rw\n')
        socket_factory=unittest.mock.Mock(side_effect=OSError('controlled socket boundary')) if stop_before_socket else LocalSocket
        account=SimpleNamespace(pw_uid=os.getuid(),pw_gid=os.getgid())
        with patch.object(module,'_SYSTEM_TOOL_PATH',str(case.trusted),create=True), \
                patch.object(module,'subprocess',SimpleNamespace(run=commands,Popen=daemon)), \
                patch.object(module,'socket',SimpleNamespace(socket=socket_factory,getfqdn=lambda _: 'localhost')), \
                patch.object(module.Path,'read_text',return_value=mounts), \
                patch('pwd.getpwnam',return_value=account),patch.object(module.os,'chown'):
            workspace=case.base/'realm-workspace';workspace.mkdir(mode=0o700)
            yield SimpleNamespace(module=module,workspace=workspace,commands=commands,daemons=daemons)

    def test_account_provisioning_gets_only_trusted_search_path(self):
        with self.scenario() as case,self.realm(case,stop_before_socket=True) as realm:
            with self.assertRaisesRegex(OSError,'socket boundary'):
                realm.module.provision_realm(realm.workspace)
            self.assertEqual([c.args[0][0] for c in realm.commands.call_args_list],['useradd','chpasswd'])
            for call in realm.commands.call_args_list:
                self.assertIsInstance(call.kwargs['env'],dict)
                self.assertEqual(call.kwargs['env']['PATH'],str(case.trusted))
            self.assertFalse(case.marker.exists())
            self.assertEqual(realm.daemons,[])

    def test_kdc_uses_trusted_program_and_refuses_a_missing_prerequisite(self):
        for missing in (None,'krb5kdc'):
            with self.subTest(missing=missing),self.scenario(missing=missing) as case,self.realm(case) as realm:
                expected='prerequisite' if missing else 'isolated KDC exited'
                with self.assertRaisesRegex(RuntimeError,expected):
                    realm.module.provision_realm(realm.workspace)
                self.assertFalse(case.marker.exists(),'caller PATH replaced the KDC')
                if missing:
                    self.assertEqual(realm.daemons,[])
                else:
                    self.assertEqual(len(realm.daemons),1)
                    self.assertEqual(realm.daemons[0][0],[str(case.trusted/'krb5kdc'),'-n'])
                    self.assertEqual(realm.daemons[0][1]['env']['PATH'],str(case.trusted))
