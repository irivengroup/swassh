"""CLI management and local planning never silently ignore execution settings."""
from contextlib import ExitStack, nullcontext, redirect_stderr, redirect_stdout
import io
import json
import runpy
import sys
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch

from swassh import Workflow, WorkflowStep
from swassh.application.profiles import HostProfile
from swassh.application.preflight import CheckIssue, CheckReport
from swassh.infrastructure.execution_input import InputSnapshot
from swassh.interfaces import cli, workflows


class CLIManagementContractTests(unittest.TestCase):
    def invoke(self, argv, *patches):
        output,error=io.StringIO(),io.StringIO()
        with ExitStack() as stack:
            stack.enter_context(redirect_stdout(output));stack.enter_context(redirect_stderr(error))
            for item in patches:stack.enter_context(item)
            code=cli.main(argv)
        return code,output.getvalue(),error.getvalue()

    def test_workflow_management_dispatches_one_action_and_redacts_metadata(self):
        record=SimpleNamespace(to_dict=lambda:{'id':'a'*32,'state':'pending'})
        for action in ('list','show','cancel','resume','reconcile','purge','worker'):
            runner=Mock();runner.__enter__=Mock(return_value=runner);runner.__exit__=Mock(return_value=False)
            runner.store.list.return_value=[record];runner.store.get.return_value=record
            runner.store.cancel.return_value=record;runner.resume.return_value=record
            runner.reconcile=AsyncMock(return_value=record)
            argv=['workflow','--'+action]
            if action not in ('list','worker'):argv+=['a'*32]
            if action=='list':argv+=['--limit','3','--offset','2']
            if action=='reconcile':argv+=['--step','install']
            if action=='worker':argv+=['--once','--poll-interval','0.1']
            worker=AsyncMock()
            with patch.object(workflows,'WorkflowRunner',return_value=runner) as factory:
                code,out,err=self.invoke(argv,patch('swassh.interfaces.scheduling.run_worker',worker))
            self.assertEqual((code,err),(0,''));factory.assert_called_once_with(None)
            if action=='worker':worker.assert_awaited_once_with(runner,once=True,poll_interval=0.1);self.assertEqual(out,'')
            else:self.assertEqual(json.loads(out),[] if action=='purge' else [record.to_dict()])
            if action=='list':runner.store.list.assert_called_once_with(3,2)
            if action=='show':runner.store.get.assert_called_once_with('a'*32)
            if action=='resume':runner.resume.assert_called_once_with('a'*32)
            if action=='reconcile':runner.reconcile.assert_awaited_once_with('a'*32,'install')
            if action=='purge':runner.purge.assert_called_once_with('a'*32)
            self.assertLessEqual(runner.store.cancel.call_count,1)

    def test_registration_and_management_reject_ignored_scope_flags_before_storage(self):
        invalid=([],['--workflow-file','spec','-H','one'],['--workflow-file','spec','-i','synthetic'],['--workflow-file','spec','-o','report'],
            ['--workflow-file','spec','--spool-dir','spool'],['--workflow-file','spec','--offset','1'],
            ['--show','a'*32,'--once'],['--show','a'*32,'--poll-interval','1'],
            ['--show','a'*32,'--limit','2'],['--show','a'*32,'--step','install'],
            ['--reconcile','a'*32],['--list','--connect-timeout','4'])
        for args in invalid:
            with self.subTest(args=args),patch.object(workflows,'WorkflowRunner') as factory:
                code,out,err=self.invoke(['workflow',*args])
            self.assertEqual(code,2);self.assertEqual(out,'');self.assertIn('swassh workflow:',err)
            factory.assert_not_called()

    def test_workflow_local_check_and_registration_use_the_same_plan(self):
        workflow=Workflow('plan',(WorkflowStep('install',('one',),command='true'),))
        record=SimpleNamespace(to_dict=lambda:{'id':'a'*32})
        runner=Mock();runner.__enter__=Mock(return_value=runner);runner.__exit__=Mock(return_value=False)
        runner.register.return_value=record
        for check in (True,False):
            report=CheckReport((CheckIssue('synthetic','ok' if check else 'error','controlled'),))
            with patch.object(workflows.WorkflowRunner,'load',return_value=workflow),patch.object(cli.LocalPreflight,'inspect',return_value=report) as inspect:
                code,out,err=self.invoke(['workflow','--workflow-file','spec','--check'])
            self.assertEqual(code,0 if check else 2);self.assertEqual(json.loads(out)['ok'],check)
            inspect.assert_called_once();self.assertEqual(err,'')
        # Replace the facade boundary, not its inherited allocation slot.
        # Restoring object.__new__ by assignment changes CPython slot behavior
        # and would contaminate subsequent real-storage integration tests.
        factory=Mock(return_value=runner)
        factory.load.return_value=workflow
        factory.plan=workflows.WorkflowRunner.plan
        with patch.object(workflows,'WorkflowRunner',factory):
            code,out,err=self.invoke(['workflow','--workflow-file','spec'])
        self.assertEqual((code,err),(0,''));self.assertEqual(json.loads(out),[record.to_dict()])
        self.assertEqual(runner.register.call_args.args[0],workflow)

    def test_schedule_show_cancel_purge_and_worker_dispatch_without_execution(self):
        for action in ('show','cancel','purge','worker'):
            scheduler=Mock();scheduler.__enter__=Mock(return_value=scheduler);scheduler.__exit__=Mock(return_value=False)
            item=object();scheduler.store.get.return_value=item;scheduler.store.cancel.return_value=item
            worker=AsyncMock();argv=['schedule','--'+action]+([] if action=='worker' else ['a'*32])
            if action=='worker':argv+=['--once']
            with patch.object(cli,'Scheduler',return_value=scheduler),patch.object(cli,'render_jobs',return_value='controlled\n') as render:
                code,out,err=self.invoke(argv,patch.object(cli,'run_worker',worker))
            self.assertEqual((code,err),(0,''))
            if action=='worker':worker.assert_awaited_once();render.assert_not_called();self.assertEqual(out,'')
            else:
                self.assertEqual(out,'controlled\n');self.assertEqual(render.call_args.args[0],[] if action=='purge' else [item])
            scheduler.schedule.assert_not_called()

    def test_session_local_scope_and_command_file_validation_precede_connections(self):
        base=['session','--commands-file','synthetic.json','-H','one','--plan-only']
        with patch.object(InputSnapshot,'read',return_value=b'["true"]'):
            for extra in (['-j','2'],['--adaptive'],['--progress'],['-o','report'],['--spool-dir','spool'],['--session-lifetime','0'],['--session-lifetime','3601']):
                code,out,err=self.invoke([*base,*extra]);self.assertEqual(code,2);self.assertEqual(out,'')
            code,out,err=self.invoke(base);self.assertEqual((code,err),(0,''));self.assertEqual(json.loads(out)['mode'],'session')
        for data in (b'{}',b'[]',b'[""]',json.dumps(['true']*1001).encode()):
            with patch.object(InputSnapshot,'read',return_value=data):
                code,out,err=self.invoke(base)
            self.assertEqual(code,2);self.assertEqual(out,'');self.assertIn('invalid input',err)
        code,out,err=self.invoke(['shell','-H','one','--plan-only','--hide-output'])
        self.assertEqual(code,2);self.assertEqual(out,'')

    def test_direct_report_formats_are_streamed_and_interrupt_diagnostics_are_controlled(self):
        for format in ('json','csv','text'):
            def execute(hosts,command,path,options,fmt,*,spool_dir):
                self.assertEqual(fmt,format);Path(path).write_bytes(b'synthetic report\n')
                return SimpleNamespace(ok=True)
            code,out,err=self.invoke(['run','true','-H','one','--format',format],
                patch.object(cli,'execute_to_file',side_effect=execute),
                patch.object(cli.LocalPreflight,'require_credentials'),
                patch.object(cli,'cli_invocation_budget',return_value=nullcontext()))
            self.assertEqual((code,out,err),(0,'synthetic report\n',''))
        code,out,err=self.invoke(['run','true','-H','one','--plan-only'],
            patch.object(cli,'normalize_hosts',side_effect=KeyboardInterrupt))
        self.assertEqual(code,130);self.assertIn('remote commands may still be running',err)

    def test_schedule_registration_requires_time_and_bounds_both_grace_limits(self):
        base=['schedule','true','-H','one','--plan-only']
        cases=([],['--at','2099-01-01T00:00:00Z','--misfire-grace','86401'])
        for extra in cases:
            with self.subTest(extra=extra),patch.object(cli,'Scheduler') as scheduler:
                code,out,err=self.invoke([*base,*extra])
            self.assertEqual(code,2);self.assertEqual(out,'')
            self.assertIn('swassh schedule:',err);scheduler.assert_not_called()

    def test_profile_file_is_resolved_for_a_local_plan_without_credentials(self):
        with patch.object(cli,'load_profiles',return_value=(HostProfile('one',username='operator'),)) as load,\
                patch.object(cli.LocalPreflight,'require_credentials') as credentials:
            code,out,err=self.invoke(['run','true','-H','one','--host-profiles','synthetic','--plan-only'])
        self.assertEqual((code,err),(0,''));self.assertIn('canary_count',json.loads(out))
        load.assert_called_once_with(Path('synthetic'));credentials.assert_not_called()

    def test_tunnel_rejects_scope_and_lifetime_before_opening_a_channel(self):
        from swassh.interfaces.channels import SSHTunnel
        base=['tunnel','--local-port','8080','--remote-host','internal','--remote-port','443','--plan-only']
        cases=(['-H','one','two'],['-H','one','--spool-dir','unused'],
               ['-H','one','--format','json'],['-H','one','--lifetime','0'],
               ['-H','one','--lifetime','3601'])
        for extra in cases:
            with self.subTest(extra=extra),patch.object(SSHTunnel,'__aenter__') as enter:
                code,out,err=self.invoke([*base,*extra])
            self.assertEqual(code,2);self.assertEqual(out,'');self.assertIn('invalid input',err)
            enter.assert_not_called()

    def test_tunnel_check_reports_both_outcomes_without_listening(self):
        from swassh.interfaces.channels import SSHTunnel
        for ok in (False,True):
            report=CheckReport((CheckIssue('transport','ok' if ok else 'error','controlled'),))
            with self.subTest(ok=ok),patch.object(cli.LocalPreflight,'inspect',return_value=report) as inspect,\
                    patch.object(SSHTunnel,'__aenter__') as enter:
                code,out,err=self.invoke(['tunnel','-H','one','--local-port','8080',
                    '--remote-host','internal','--remote-port','443','--check'])
            self.assertEqual(code,0 if ok else 2);self.assertEqual(err,'')
            self.assertIn('OK' if ok else 'FAILED',out);inspect.assert_called_once();enter.assert_not_called()

    def test_network_check_and_review_never_apply_or_write_an_execution_report(self):
        from swassh.interfaces.network import NetworkSwarm
        service=Mock();service.plan.return_value={'review':'synthetic'}
        with patch.object(NetworkSwarm,'from_file',return_value=service):
            code,out,err=self.invoke(['network','--procedure','synthetic','-H','one','--check'],
                patch.object(cli.LocalPreflight,'inspect',return_value=CheckReport(())))
            self.assertEqual((code,err),(0,''));self.assertIn('SWASSH local checks: OK',out)
            code,out,err=self.invoke(['network','--procedure','synthetic','-H','one','--output','forbidden'])
        self.assertEqual(code,2);self.assertEqual(out,'');self.assertIn('invalid input or report I/O (ValueError)',err)
        service._approved.assert_not_called();service.run_to_file.assert_not_called();service.plan.assert_not_called()

    def test_shell_rejects_report_and_progress_overrides_even_in_local_plan(self):
        for extra in (['--format','json'],['--progress']):
            with self.subTest(extra=extra):
                code,out,err=self.invoke(['shell','-H','one','--plan-only',*extra])
            self.assertEqual(code,2);self.assertEqual(out,'');self.assertIn('invalid input',err)

    def test_transfer_checks_preserve_direction_and_settings_without_transfer(self):
        from swassh.domain.transfers import TransferDirection
        for action in ('push','pull'):
            report=CheckReport((CheckIssue('transfer','error','controlled refusal'),))
            with self.subTest(action=action),patch.object(cli.LocalPreflight,'inspect',return_value=report) as inspect,\
                    patch.object(cli,'push_to_file') as push,patch.object(cli,'pull_to_file') as pull:
                code,out,err=self.invoke([action,'-H','one','--source','/source','--destination','/destination',
                    '--check','--format','json','--max-file-mib','2'])
            self.assertEqual(code,2);self.assertEqual(err,'');self.assertFalse(json.loads(out)['ok'])
            request=inspect.call_args.kwargs['request'];settings=inspect.call_args.kwargs['settings']
            self.assertEqual(request.direction,TransferDirection(action))
            self.assertEqual(str(request.local_path),'/source' if action=='push' else '/destination')
            self.assertEqual(request.remote_path,'/destination' if action=='push' else '/source')
            self.assertEqual(settings.max_file_mib,2);push.assert_not_called();pull.assert_not_called()

    def test_module_entrypoint_has_the_same_version_exit_contract(self):
        output,error=io.StringIO(),io.StringIO()
        with patch.object(sys,'argv',['swassh','--version']),redirect_stdout(output),redirect_stderr(error),\
                self.assertRaises(SystemExit) as stopped:
            runpy.run_module('swassh.interfaces.cli',run_name='__main__',alter_sys=True)
        self.assertEqual(stopped.exception.code,0)
        self.assertEqual(output.getvalue(),f'swassh {cli.__version__}\n')


if __name__=='__main__':unittest.main()
