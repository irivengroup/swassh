"""Console entrypoint: swassh."""

from __future__ import annotations

import argparse
from contextlib import nullcontext
import asyncio
import shutil
import sqlite3
import sys
import tempfile
from dataclasses import replace
from datetime import UTC, datetime
from collections.abc import Sequence
from pathlib import Path

from .. import __version__
from ..infrastructure.audit import default_log_path
from ..infrastructure.bastion import cli_invocation_budget
from .api import Swarm, execute_to_file
from .scheduling import Scheduler, render_jobs, run_worker
from ..domain.scheduling import ScheduleError, parse_schedule_time
from ..domain.workflows import WorkflowError
from ..infrastructure.resources import resource_plan
from .transfers import FileSwarm, push_to_file, pull_to_file
from ..application.transfer_settings import TransferSettings
from ..domain.transfers import FileTransfer, TransferDirection
from ..infrastructure.inventory import load_inventory
from ..domain.inventory import normalize_hosts, parse_host
from ..domain.commands import validate_command
from ..application.options import Options
from ..application.preflight import CheckIssue, PreflightError
from ..infrastructure.preflight import LocalPreflight
from ..infrastructure.execution_input import load_profiles
from ..application.profiles import ProfileResolver


def _render_check(report, format):
    """Render only controlled check messages; never commands or credential paths."""
    import csv
    import io
    import json
    if format == 'json':
        return json.dumps(report.to_dict(), indent=2) + '\n'
    if format == 'csv':
        output = io.StringIO(newline='')
        writer = csv.DictWriter(output, ('code', 'level', 'message'))
        writer.writeheader()
        writer.writerows(report.to_dict()['checks'])
        return output.getvalue()
    return 'SWASSH local checks: ' + ('OK' if report.ok else 'FAILED') + '\n' + ''.join(
        f'[{issue.level}] {issue.code}: {issue.message}\n' for issue in report.issues)


def _remote_command(value: str) -> str:
    try:
        return validate_command(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _parser(action: str = "root", *, selected: str | None = None) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        allow_abbrev=False,
        prog="swassh" + (" " + action if action != "root" else ""),
        description="Run remote commands or transfer files with bounded SSH concurrency.",
        epilog="Examples: swassh run 'uname -r' -i hosts.txt; swassh push --source ./release/ --destination /srv/app/ -i hosts.txt."
    )
    parser.add_argument("--version", action="version", version=f"swassh {__version__}")
    if action == "root":
        commands = parser.add_subparsers(dest="action", required=True)
        for name, help_text in (("run", "execute a remote command or script"),
                                ("network", "review or apply a network device procedure"),
                                ("converge", "check, apply if needed and verify an explicit desired state"),
                                ("tunnel", "hold a bounded SSH TCP forward on loopback only"),
                                ("session", "execute a JSON command sequence over one reusable connection"),
                                ("shell", "open one interactive remote shell with a PTY"),
                                ("push", "send files to the fleet"),
                                ("pull", "collect files from the fleet"),
                                ("schedule", "schedule a command or manage the persistent queue"),
                                ("workflow", "register, inspect or run a persistent dependency workflow"),
                                ("setup-path", "configure user PATH when necessary, with backups")):
            # Only the selected command needs its full option tree at startup.
            # The default retains the complete parser for library callers.
            parents = [_parser(name)] if selected is None or name == selected else []
            commands.add_parser(name, parents=parents, add_help=False,
                                allow_abbrev=False, help=help_text)
        return parser
    if action == "setup-path":
        parser.add_argument('--app-venv', action='store_true',
                            help='persist the PATH of an intentionally retained application environment')
        return parser
    if action == 'session':
        parser.add_argument('--commands-file', type=Path, required=True, help='UTF-8 JSON array of 1..1000 commands, at most 1 MiB; stop on first failure')
        parser.add_argument('--session-lifetime', type=float, default=300, help='maximum master lifetime in seconds, 1..3600')
    if action == 'network':
        parser.add_argument('--procedure', type=Path, required=True, help='strict UTF-8 JSON procedure; default is local review only')
        parser.add_argument('--apply', metavar='SHA256', help='apply the reviewed procedure digest bound to these targets')
    if action == 'converge':
        parser.add_argument('--action-file', type=Path, required=True,
                            help='strict desired-state JSON with name, check, apply and optional verify')
    if action == 'tunnel':
        parser.add_argument('--local-port',type=int,required=True,help='explicit local listening port, 1..65535')
        parser.add_argument('--remote-host',required=True,help='destination resolved by the SSH server')
        parser.add_argument('--remote-port',type=int,required=True,help='destination TCP port, 1..65535')
        parser.add_argument('--bind-address',choices=('127.0.0.1','::1'),default='127.0.0.1')
        parser.add_argument('--lifetime',type=float,default=300,help='maximum tunnel lifetime in seconds, 1..3600')
    source = parser.add_mutually_exclusive_group(required=action not in ("schedule", "workflow"))
    source.add_argument("-H", "--hosts", nargs="+", help="[user@]host[:port] targets")
    source.add_argument(
        "-i", "--inventory", type=Path, help="TXT, CSV, JSON or YAML inventory"
    )
    if action in ("run", "schedule"):
        parser.add_argument("command", type=_remote_command, nargs="?" if action == "schedule" else None,
                            help="remote shell command or remote script with options, quoted as one argument")
    if action in ("schedule", "workflow"):
        if action == 'workflow':
            parser.add_argument('--workflow-file', type=Path, help='strict bounded dependency workflow JSON')
        else:
            parser.add_argument("--at", help="date and time: YYYY-MM-DD HH:MM[:SS] or ISO with offset")
            parser.add_argument("--timezone", help="IANA timezone or fixed offset; default UTC")
            parser.add_argument("--fold", type=int, choices=(0, 1), help="choose first/second occurrence of ambiguous local time")
            parser.add_argument("--misfire-grace", type=int, default=300, help="maximum start delay in seconds, 1..86400")
        parser.add_argument("--state-dir", type=Path, help="private persistent state directory")
        management = parser.add_mutually_exclusive_group()
        management.add_argument("--list", action="store_true", help="list recent jobs without commands or inventories")
        management.add_argument("--show", metavar="JOB_ID")
        management.add_argument("--cancel", metavar="JOB_ID", help="cancel a pending job")
        management.add_argument("--purge", metavar="JOB_ID", help="delete a terminal record; retain reports")
        management.add_argument("--worker", action="store_true", help="run the serial queue worker")
        if action == 'workflow':
            management.add_argument('--resume', metavar='WORKFLOW_ID', help='resume after explicit verification of ambiguous steps')
            management.add_argument('--reconcile', metavar='WORKFLOW_ID', help='run only a declared read-only verifier')
            parser.add_argument('--step', help='step identifier for --reconcile')
        parser.add_argument("--once", action="store_true", help="worker: dispatch at most one due job, then exit")
        parser.add_argument("--poll-interval", type=float, default=1, help="worker: poll every 0.1..60 seconds")
        parser.add_argument("--limit", type=int, default=20, help="list: maximum 1..200 records")
        parser.add_argument("--offset", type=int, default=0, help="list: nonnegative pagination offset")
    if action in ("push", "pull"):
        parser.add_argument("--source", required=True, help="source file or directory; trailing slash copies directory contents")
        parser.add_argument("--destination", required=True, help="remote path for push; isolated local root for pull")
        parser.add_argument("--transfer-timeout", type=float, default=600)
        parser.add_argument("--transfer-bandwidth-kib", type=int, default=10240, help="aggregate fleet bandwidth cap in KiB/s")
        parser.add_argument("--max-file-mib", type=int, default=1024)
        parser.add_argument("--rsync-max-alloc-mib", type=int, default=16)
        parser.add_argument("--rsync-executable", default="rsync")
        parser.add_argument("--sftp-executable", default="sftp")
        parser.add_argument("--dry-run", action="store_true", help="readonly rsync preview, with aggregate change counts")
        parser.add_argument("--verify-sha256", action="store_true", help="verify a single file before publication")
    parser.add_argument("-u", "--user", help="default SSH user")
    parser.add_argument('--host-profiles', type=Path, help='strict JSON endpoint profiles; relative paths use its directory')
    parser.add_argument('--encoding', default='utf-8', help='remote output text encoding; commands remain unchanged')
    parser.add_argument('--auth-method', choices=('publickey', 'password', 'gssapi'), default='publickey', help='explicit authentication mode; no weaker fallback')
    parser.add_argument('--askpass-executable', help='trusted external password provider executable; never a password value')
    if action in ('run', 'schedule', 'session'):
        parser.add_argument('--pty', action='store_true', help='request a remote PTY; remote stderr merges into stdout')
        parser.add_argument('--stdin-file', help='send one bounded immutable file snapshot to every target')
        parser.add_argument('--max-stdin-bytes', type=int, default=1048576, help='stdin file ceiling, up to 16777216 bytes')
        parser.add_argument('--stream-output', action='store_true', help='live bounded JSON lines on stderr; final report unchanged')
        parser.add_argument('--stream-rate', type=int, default=100, help='aggregate live event rate; overflow is counted')
    parser.add_argument(
        "-k", "--key", action="append", default=[], help="private key path; repeatable"
    )
    parser.add_argument(
        "--known-hosts", help="verified known_hosts file; default ~/.ssh/known_hosts"
    )
    parser.add_argument("-j", "--concurrency", type=int, default=32)
    parser.add_argument("--canary", type=int, nargs="?", const=1, default=1,
                        help="first-wave hosts (default 1); release the fleet only on success")
    parser.add_argument("--connect-timeout", type=float, default=10)
    parser.add_argument("--command-timeout", type=float, default=60)
    parser.add_argument("--report-timeout", type=float, default=60, help="deadline per report-worker operation")
    parser.add_argument(
        "--retries", type=int, default=0, help="connection-only retries"
    )
    parser.add_argument("--retry-delay", type=float, default=0.5)
    parser.add_argument(
        "--max-output-bytes",
        type=int,
        default=65536,
        help="capture cap per stream per host",
    )
    parser.add_argument(
        "--connect-rate", type=float, default=20, help="new SSH connections per second"
    )
    parser.add_argument("--memory-budget-mib", type=int, default=128)
    parser.add_argument("--budget-dir", help="shared local budget root; default ~/.swassh/budgets")
    parser.add_argument("--bastion-concurrency", type=int, default=32)
    parser.add_argument("--bastion-connect-rate", type=float, default=20)
    parser.add_argument("--bastion-memory-mib", type=int, default=512)
    parser.add_argument("--bastion-bandwidth-kib", type=int, default=10240,
                        help='aggregate bidirectional encrypted SSH payload cap in KiB/s for this local budget root')
    parser.add_argument("--adaptive", action="store_true", help="reduce admission on network failures, without replay")
    parser.add_argument("--circuit-threshold", type=int, default=5)
    parser.add_argument("--progress", action="store_true", help="bounded aggregate progress on stderr")
    parser.add_argument("--progress-interval", type=float, default=2)
    parser.add_argument(
        "--max-report-mib", type=int, default=1024, help="private spool disk budget"
    )
    parser.add_argument(
        "--spool-dir", type=Path, help="directory for private intermediate report"
    )
    checking = parser.add_mutually_exclusive_group()
    checking.add_argument("--check", action="store_true", help="check local prerequisites without network access or creating a scheduled job")
    checking.add_argument(
        "--plan-only",
        action="store_true",
        help="print resource plan without connecting",
    )
    parser.add_argument(
        "--log-file", default=None if action in ("schedule", "workflow") else str(default_log_path()), help="rotating JSONL audit log"
    )
    parser.add_argument(
        "--ssh-executable", default="ssh", help="system OpenSSH executable"
    )
    parser.add_argument("--jump", help="optional SSH gateway [user@]host[:port]")
    parser.add_argument("--format", choices=("json",) if action == 'workflow' else ("text", "json", "csv"),
                        default='json' if action == 'workflow' else 'text')
    output_mode = parser.add_mutually_exclusive_group()
    output_mode.add_argument("--show-output", action="store_true", default=True,
                             help="show text output for every host (default)")
    output_mode.add_argument("--hide-output", action="store_false", dest="show_output",
                             help="show only the compact exceptional-response summary")
    parser.add_argument("--output-lines", type=int, default=10,
                        help="text lines per stream (default 10; 0 shows all captured lines)")
    parser.add_argument(
        "-o", "--output", type=Path, help="atomic report file; schedule defaults to a private per-job file" if action == "schedule" else "atomic report file; otherwise stdout"
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = _parser(selected=argv[0] if argv else "")
    args = parser.parse_args(argv)
    action = args.action
    try:
        if action == "setup-path":
            from ..infrastructure.installation import setup_path
            try:
                    if args.app_venv:
                        setup_path(allow_venv=True)
                    else:
                        setup_path()
            except ValueError as exc:
                sys.stderr.write(f"swassh setup-path: {exc}\n")
                return 2
            return 0
        if action == 'workflow':
            from .workflows import workflow_management
            result = workflow_management(args, argv)
            if result is not None:
                return result
        if action == "schedule":
            management = args.list or args.show or args.cancel or args.purge or args.worker
            if management:
                # Reject execution flags rather than silently ignoring their safety settings.
                allowed = {"--state-dir", "--format", "--list", "--show", "--cancel", "--purge", "--worker", "--limit", "--offset", "--once", "--poll-interval"}
                flags = {token.split("=", 1)[0] for token in argv[1:] if token.startswith("-")}
                if args.command is not None or flags - allowed:
                    raise ScheduleError('management actions cannot include commands, inventories or execution options')
                if not args.worker and (args.once or '--poll-interval' in flags):
                    raise ScheduleError('--once and --poll-interval require --worker')
                if not args.list and flags & {'--limit', '--offset'}:
                    raise ScheduleError('--limit and --offset require --list')
                with Scheduler(args.state_dir) as scheduler:
                    if args.worker:
                        asyncio.run(run_worker(scheduler, once=args.once, poll_interval=args.poll_interval))
                        return 0
                    if args.list:
                        jobs = scheduler.store.list(args.limit, args.offset)
                    elif args.show:
                        jobs = [scheduler.store.get(args.show)]
                    elif args.cancel:
                        jobs = [scheduler.store.cancel(args.cancel, datetime.now(UTC))]
                    else:
                        scheduler.store.purge(args.purge, datetime.now(UTC))
                        jobs = []
                    sys.stdout.write(render_jobs(jobs, args.format))
                    return 0
            if not args.command or not (args.inventory or args.hosts) or not args.at:
                raise ScheduleError('registration requires a positional command, -i/--hosts and --at')
            if any(token.split('=', 1)[0] in {'--once', '--limit', '--offset', '--poll-interval'} for token in argv[1:]):
                raise ScheduleError('worker/list options cannot be used when registering a job')
            due = parse_schedule_time(args.at, args.timezone, args.fold)
            if due <= datetime.now(UTC):
                raise ScheduleError('scheduled date and time must be in the future')
            if not 1 <= args.misfire_grace <= 86400:
                raise ScheduleError('misfire grace must be between 1 and 86400 seconds')
        options = Options(
            pty=getattr(args, 'pty', False),
            encoding=args.encoding,
            auth_method=args.auth_method, askpass_executable=args.askpass_executable,
            host_profiles=load_profiles(args.host_profiles) if args.host_profiles else (),
            stdin_file=getattr(args, 'stdin_file', None),
            max_stdin_bytes=getattr(args, 'max_stdin_bytes', 1048576),
            stream_output=getattr(args, 'stream_output', False),
            stream_rate=getattr(args, 'stream_rate', 100),
            show_output=args.show_output, output_lines=args.output_lines,
            budget_dir=args.budget_dir, bastion_concurrency=args.bastion_concurrency,
            bastion_connect_rate=args.bastion_connect_rate, bastion_memory_mib=args.bastion_memory_mib,
            bastion_bandwidth_kib=args.bastion_bandwidth_kib, adaptive=args.adaptive,
            circuit_threshold=args.circuit_threshold,
            progress_interval=args.progress_interval if args.progress else 0,
            concurrency=args.concurrency,
            canary=args.canary,
            username=args.user,
            client_keys=tuple(args.key),
            known_hosts=args.known_hosts,
            connect_timeout=args.connect_timeout,
            command_timeout=args.command_timeout,
            report_timeout=args.report_timeout,
            retries=args.retries,
            retry_delay=args.retry_delay,
            max_output_bytes=args.max_output_bytes,
            connect_rate=args.connect_rate,
            memory_budget_mib=args.memory_budget_mib,
            max_report_mib=args.max_report_mib,
            log_file=args.log_file,
            ssh_executable=args.ssh_executable,
            jump_host=parse_host(args.jump) if args.jump else None,
        )
        if action == 'workflow':
            from .workflows import WorkflowRunner, render_workflows
            import json
            workflow = WorkflowRunner.load(args.workflow_file)
            plan = WorkflowRunner.plan(workflow, options)
            if args.plan_only:
                sys.stdout.write(json.dumps(plan, indent=2) + '\n')
                return 0
            if args.check:
                check = LocalPreflight().inspect(options, state=args.state_dir)
                sys.stdout.write(_render_check(check, args.format))
                return 0 if check.ok else 2
            with WorkflowRunner(args.state_dir) as runner:
                sys.stdout.write(render_workflows([runner.register(workflow, options)]))
            return 0
        if action in ('session', 'shell'):
            flags = {token.split('=', 1)[0] for token in argv[1:] if token.startswith('-')}
            if flags & {'-j', '--concurrency'} and options.concurrency != 1:
                raise ValueError('session and shell support concurrency=1 only')
            if options.adaptive or options.progress_interval:
                raise ValueError('adaptive fleet admission and progress are unavailable for single-host session/shell')
            if action == 'shell' and flags & {'--canary', '--retries', '--max-output-bytes', '--max-report-mib', '--output-lines', '--hide-output', '--circuit-threshold'}:
                raise ValueError('interactive shell does not accept command-report or replay options')
            options = replace(options, concurrency=1)
        network_review = action == 'network' and not args.apply
        if not args.plan_only and not args.check and not network_review:
            LocalPreflight().require_credentials(options)
        boundary = cli_invocation_budget(options) if action not in ("schedule", "tunnel") and not (args.plan_only or args.check or network_review) else nullcontext()
        with boundary:
            hosts = (
                load_inventory(args.inventory)
                if args.inventory
                else normalize_hosts(args.hosts)
            )
            hosts = ProfileResolver(options).targets(hosts)
            if action == 'tunnel':
                import json
                import math
                from ..domain.channels import LocalForward
                from .channels import SSHTunnel
                if len(hosts)!=1 or args.output or args.spool_dir or args.format!='text':
                    raise ValueError('tunnels require one host and direct output without report or spool options')
                if not math.isfinite(args.lifetime) or not 1 <= args.lifetime <= 3600:
                    raise ValueError('tunnel lifetime must be between 1 and 3600 seconds')
                forward=LocalForward(args.local_port,args.remote_host,args.remote_port,args.bind_address)
                scoped=replace(options,concurrency=1)
                # Validate scope-specific settings even in plan/check mode.
                tunnel=SSHTunnel(hosts[0],forward,scoped,lifetime=args.lifetime)
                plan=resource_plan(scoped,guarded=True).to_dict() | {'mode':'tunnel',
                    'bind_address':forward.bind_address,'local_port':forward.local_port,
                    'remote_host':forward.remote_host,'remote_port':forward.remote_port,'lifetime':args.lifetime}
                if args.plan_only:
                    sys.stdout.write(json.dumps(plan,indent=2)+'\n')
                    return 0
                if args.check:
                    check=LocalPreflight().inspect(scoped)
                    sys.stdout.write(_render_check(check,args.format))
                    return 0 if check.ok else 2
                async def hold_tunnel():
                    async with tunnel:
                        sys.stdout.write(json.dumps({'state':'listening','bind_address':forward.bind_address,
                            'local_port':forward.local_port,'destination_verified':False})+'\n')
                        sys.stdout.flush()
                        await tunnel.wait()
                asyncio.run(hold_tunnel())
                return 0
            if action == 'converge':
                from .convergence import ConvergentSwarm
                desired_service = ConvergentSwarm.from_file(args.action_file, options)
            if action == 'network':
                import json
                from .network import NetworkSwarm
                network = NetworkSwarm.from_file(args.procedure, options)
                if args.apply and (args.check or args.plan_only):
                    raise ValueError('network apply cannot be combined with check or plan-only')
                if not args.apply and not args.check:
                    if args.output:
                        raise ValueError('network local review writes to stdout; use execution output only with apply')
                    sys.stdout.write(json.dumps(network.plan(hosts), indent=2) + '\n')
                    return 0
                if args.apply:
                    network._approved(hosts, args.apply)
            if action in ('session', 'shell'):
                import os
                if len(hosts) != 1:
                    raise ValueError('session and shell require exactly one target')
                if args.output or args.spool_dir:
                    raise ValueError('session and shell write to stdout; output/spool options are unavailable')
                if action == 'shell' and (args.format != 'text' or not args.show_output or args.progress):
                    raise ValueError('shell requires direct terminal output without report format or progress overrides')
                if action == 'session' and os.name != 'posix' and not (args.plan_only or args.check):
                    sys.stderr.write('swassh session: reusable connections require POSIX OpenSSH multiplexing; ordinary run and shell remain available\n')
                    return 2
            if action in ('session', 'shell'):
                import json
                from ..infrastructure.execution_input import InputSnapshot
                commands = None
                if action == 'session':
                    commands = json.loads(InputSnapshot.read(args.commands_file, 1048576).decode('utf-8'))
                    if not isinstance(commands, list) or not 1 <= len(commands) <= 1000:
                        raise ValueError('session commands must be a JSON array of 1..1000 commands')
                    for command in commands:
                        validate_command(command)
                    if not 1 <= args.session_lifetime <= 3600:
                        raise ValueError('session lifetime must be 1..3600 seconds')
            if args.check:
                settings = request = None
                if action in ('push', 'pull'):
                    settings = TransferSettings(rsync_executable=args.rsync_executable,
                        sftp_executable=args.sftp_executable, timeout=args.transfer_timeout,
                        bandwidth_kib=args.transfer_bandwidth_kib, max_file_mib=args.max_file_mib,
                        max_rsync_alloc_mib=args.rsync_max_alloc_mib,
                        dry_run=args.dry_run, verify_sha256=args.verify_sha256)
                    local, remote = (args.source, args.destination) if action == 'push' else (args.destination, args.source)
                    request = FileTransfer(TransferDirection(action), local, remote)
                resource_plan(options, guarded=True, persistent_master=action == 'session')
                check = LocalPreflight().inspect(options, output=args.output, spool=args.spool_dir,
                    request=request, settings=settings,
                    state=args.state_dir if action == 'schedule' else None)
                check = replace(check, issues=(CheckIssue('inventory_valid', 'ok', f'{len(hosts)} normalized targets.'), *check.issues))
                if action == 'session' and os.name != 'posix':
                    check = replace(check, issues=(*check.issues, CheckIssue('session_platform', 'error', 'Reusable sessions require POSIX OpenSSH multiplexing.')))
                sys.stdout.write(_render_check(check, args.format))
                return 0 if check.ok else 2
            if action in ('session', 'shell'):
                from .session import Session
                from ..infrastructure.terminal import InteractiveShell
                from ..infrastructure.execution_input import InputSnapshot
                import json
                plan = resource_plan(options, guarded=True, persistent_master=action == 'session')
                if args.plan_only:
                    sys.stdout.write(json.dumps(plan.to_dict() | {'mode': action, 'host_count': 1})+'\n')
                    return 0
                async def interactive_operation():
                    if action == 'shell':
                        try:
                            return 0 if await InteractiveShell(options, hosts[0]).run() == 0 else 1
                        except TimeoutError:
                            sys.stderr.write('swassh shell: deadline exceeded; remote work may still be running\n')
                            return 1
                    async with Session(hosts[0], options, lifetime=args.session_lifetime) as session:
                        for command in commands:
                            report = await session.run(command)
                            rendered = report.to_json() if args.format == 'json' else report.to_csv() if args.format == 'csv' else report.to_text()
                            sys.stdout.write(rendered + ('\n' if not rendered.endswith('\n') else ''))
                            sys.stdout.flush()
                            if not report.ok:
                                return 1
                    return 0
                return asyncio.run(interactive_operation())
            if action == "schedule":
                plan = resource_plan(options, guarded=True).to_dict() | {"due_at": due.isoformat(),
                    "host_count": len(hosts), "canary_requested": options.canary,
                    "canary_count": min(options.canary, len(hosts))}
                if args.plan_only:
                    import json
                    sys.stdout.write(json.dumps(plan, indent=2) + "\n")
                    return 0
                with Scheduler(args.state_dir) as scheduler:
                    job = scheduler.schedule(hosts, args.command, args.at, timezone=args.timezone,
                        fold=args.fold, options=options, report_path=args.output,
                        format=args.format, spool_dir=args.spool_dir, misfire_grace=args.misfire_grace)
                    sys.stdout.write(render_jobs([job], args.format))
                    if args.format == 'text':
                        sys.stdout.write('A supervised swassh schedule --worker must be running with this state directory.\n')
                return 0
            settings = None
            if action in ("push", "pull"):
                settings = TransferSettings(rsync_executable=args.rsync_executable,
                    sftp_executable=args.sftp_executable, timeout=args.transfer_timeout,
                    bandwidth_kib=args.transfer_bandwidth_kib, max_file_mib=args.max_file_mib,
                    max_rsync_alloc_mib=args.rsync_max_alloc_mib,
                    dry_run=args.dry_run, verify_sha256=args.verify_sha256)
                local, remote = (args.source, args.destination) if action == "push" else (args.destination, args.source)
                FileTransfer(TransferDirection(action), local, remote)
                service = FileSwarm(options, settings)
            elif action == 'converge':
                service = desired_service
            else:
                service = Swarm(options)
            if args.plan_only:
                import json

                sys.stdout.write(
                    json.dumps(service.plan().to_dict() | {"canary_requested": options.canary,
                        "canary_count": min(options.canary, len(hosts))}, indent=2) + "\n"
                )
                return 0
            def run(output, spool):
                if action == 'converge':
                    return asyncio.run(service.run_to_file(hosts, output, args.format, spool_dir=spool))
                if action == 'network':
                    return asyncio.run(network.run_to_file(hosts, output, args.format,
                        approval=args.apply, spool_dir=spool))
                if action == "run":
                    return execute_to_file(hosts, args.command, output, options, args.format, spool_dir=spool)
                operation = push_to_file if action == "push" else pull_to_file
                return operation(hosts, args.source, args.destination, output, options,
                                 args.format, settings=settings, spool_dir=spool)
            if args.output:
                report = run(args.output, args.spool_dir)
            else:
                with tempfile.TemporaryDirectory(prefix="swassh-cli-", dir=args.spool_dir) as directory:
                    output = Path(directory) / "report"
                    report = run(output, directory)
                    with output.open(encoding="utf-8", newline="") as stream:
                        if args.format == "text":
                            from ..infrastructure.report import TerminalColor
                            colors = TerminalColor()
                            for line in stream:
                                colors.write(sys.stdout, line)
                        else:
                            shutil.copyfileobj(stream, sys.stdout, length=65536)
            return 0 if report.ok else 1
    except PreflightError as exc:
        sys.stderr.write(_render_check(exc.report, 'text'))
        return 2
    except KeyboardInterrupt:
        sys.stderr.write("swassh: interrupted; remote commands may still be running\n")
        return 130
    except WorkflowError as exc:
        sys.stderr.write(f"swassh workflow: {exc}\n")
        return 2
    except ScheduleError as exc:
        sys.stderr.write(f"swassh schedule: {exc}\n")
        return 2
    except (ValueError, OSError, RuntimeError, sqlite3.Error) as exc:
        # Never print arbitrary exception contents which could embed inventory secrets.
        sys.stderr.write(
            f"swassh: invalid input or report I/O ({type(exc).__name__}): "
            "check inventory, options, credentials and output path\n"
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
