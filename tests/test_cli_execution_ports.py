"""CLI routes reviewed operations through recording ports without native I/O."""
import contextlib
import builtins
from datetime import UTC,datetime
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock,Mock,patch

from swassh import Host,Result,Status
from swassh.application.preflight import CheckReport
from swassh.infrastructure.report import Report
from swassh.infrastructure.execution_input import InputSnapshot
from swassh.interfaces import cli,session,network,convergence


class CLIExecutionPortTests(unittest.TestCase):
    def test_session_platform_checks_and_execution_refusal_are_scoped_to_cli(self):
        original_import=builtins.__import__
        for name,check in (('posix',True),('nt',True),('nt',False)):
            platform=SimpleNamespace(**vars(os));platform.name=name
            def scoped_import(module,globals=None,locals=None,fromlist=(),level=0):
                return platform if module=='os' and globals is cli.__dict__ else original_import(module,globals,locals,fromlist,level)
            output,error=io.StringIO(),io.StringIO()
            with self.subTest(platform=name,check=check),patch.object(builtins,'__import__',scoped_import),\
                    patch.object(cli,'os',platform,create=True),patch.object(InputSnapshot,'read',return_value=b'["true"]'),\
                    patch.object(cli.LocalPreflight,'inspect',return_value=CheckReport(())),\
                    patch.object(cli.LocalPreflight,'require_credentials'),\
                    patch.object(cli,'cli_invocation_budget',return_value=contextlib.nullcontext()),\
                    patch.object(session,'Session') as connect,contextlib.redirect_stdout(output),contextlib.redirect_stderr(error):
                code=cli.main(['session','-H','one','--commands-file','synthetic','-j','1',*(['--check','--format','json'] if check else [])])
            self.assertEqual(code,0 if name=='posix' else 2);connect.assert_not_called()
            if check:
                self.assertEqual(error.getvalue(),'');self.assertEqual(json.loads(output.getvalue())['ok'],name=='posix')
            else:
                self.assertEqual(output.getvalue(),'');self.assertIn('reusable connections require POSIX',error.getvalue())

    def test_posix_session_renders_each_format_and_stops_after_first_failed_command(self):
        # Only the CLI's local platform-policy import is replaced. pathlib,
        # filesystem/native adapters keep the real OS, and no native port opens.
        platform=SimpleNamespace(**vars(os));platform.name='posix'
        original_import=builtins.__import__
        def scoped_import(name,globals=None,locals=None,fromlist=(),level=0):
            if name=='os' and globals is cli.__dict__:
                return platform
            return original_import(name,globals,locals,fromlist,level)
        now=datetime(2030,1,1,tzinfo=UTC)
        for format in ('json','csv','text'):
            for failed in (False,True):
                calls=[];reports=[];events=[]
                class RecordingSession:
                    def __init__(self,host,options,*,lifetime):
                        self_options=options
                        if self_options.concurrency!=1:raise AssertionError('session must be scoped to one connection')
                        self.host=host
                    async def __aenter__(self):events.append('enter');return self
                    async def __aexit__(self,*args):events.append('exit')
                    async def run(self,command):
                        calls.append(command)
                        report=Report(command,(Result(self.host,Status.FAILED if failed and command=='second' else Status.SUCCESS,
                            stdout='synthetic output'),),now,now)
                        reports.append(report);return report
                output,error=io.StringIO(),io.StringIO()
                with patch.object(session,'Session',RecordingSession),patch.object(InputSnapshot,'read',return_value=b'["first","second","third"]'),\
                        patch.object(cli.LocalPreflight,'require_credentials'),patch.object(cli,'cli_invocation_budget',return_value=contextlib.nullcontext()),\
                        patch.object(builtins,'__import__',scoped_import),patch.object(cli,'os',platform,create=True),\
                        contextlib.redirect_stdout(output),contextlib.redirect_stderr(error):
                    code=cli.main(['session','-H','one','--commands-file','synthetic','--format',format])
                self.assertEqual(code,int(failed));self.assertEqual(error.getvalue(),'')
                self.assertEqual(calls,['first','second'] if failed else ['first','second','third'])
                self.assertEqual(events,['enter','exit'])
                rendered=[getattr(report,'to_'+format)() for report in reports]
                self.assertEqual(output.getvalue(),''.join(value if value.endswith('\n') else value+'\n' for value in rendered))

    def test_reviewed_network_and_desired_state_write_only_through_the_selected_service(self):
        for action in ('network','converge'):
            output,error=io.StringIO(),io.StringIO();service=Mock()
            service._approved.return_value=(Host('one'),)
            calls=[]
            async def export(hosts,path,format,**kwargs):
                calls.append((hosts,format,kwargs));Path(path).write_bytes(b'synthetic report\n')
                return SimpleNamespace(ok=True)
            service.run_to_file=AsyncMock(side_effect=export)
            factory=network.NetworkSwarm if action=='network' else convergence.ConvergentSwarm
            args=['network','--procedure','synthetic','--apply','a'*64] if action=='network' else ['converge','--action-file','synthetic']
            with patch.object(factory,'from_file',return_value=service),patch.object(cli.LocalPreflight,'require_credentials'),\
                    patch.object(cli,'cli_invocation_budget',return_value=contextlib.nullcontext()),\
                    contextlib.redirect_stdout(output),contextlib.redirect_stderr(error):
                code=cli.main([*args,'-H','one','--format','json'])
            self.assertEqual((code,error.getvalue(),output.getvalue()),(0,'','synthetic report\n'))
            self.assertEqual(len(calls),1);self.assertEqual(calls[0][0],(Host('one'),));self.assertEqual(calls[0][1],'json')
            if action=='network':
                service._approved.assert_called_once_with((Host('one'),),'a'*64)
                self.assertEqual(calls[0][2]['approval'],'a'*64)
            else:self.assertNotIn('approval',calls[0][2])


if __name__=='__main__':unittest.main()
