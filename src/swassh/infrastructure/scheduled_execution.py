"""Resolve registration paths once, and execute snapshots through the normal swarm."""
from dataclasses import replace
from pathlib import Path
import shutil
import hashlib

from ..application.options import Options
from ..application.schedule_contracts import ScheduledInvocation
from ..domain.inventory import normalize_hosts
from ..domain.scheduling import ScheduleError, validate_job_id
from .filesystem import private_directory
from .preflight import LocalPreflight
from .execution_input import InputSnapshot
from ..application.profiles import ProfileResolver


def prepare_invocation(id, state_dir, hosts, command, options=None, *, report_path=None, format='json', spool_dir=None):
    validate_job_id(id)
    state_dir = Path(state_dir).expanduser().absolute()
    options = options if options is not None else Options()
    LocalPreflight().require_credentials(options)
    targets = ProfileResolver(options).targets(hosts)
    stdin = InputSnapshot.stdin(options)
    executable = shutil.which(options.ssh_executable)
    if executable is None:
        raise ScheduleError('OpenSSH executable unavailable at registration')
    run_directory = Path(state_dir) / 'runs' / id
    def absolute(path):
        return str(Path(path).expanduser().absolute())
    pinned = replace(options, ssh_executable=absolute(executable),
        askpass_executable=absolute(shutil.which(options.askpass_executable)) if options.askpass_executable else None,
        stdin_file=absolute(options.stdin_file) if options.stdin_file else None,
        stdin_sha256=hashlib.sha256(stdin).hexdigest() if stdin is not None else None,
        host_profiles=tuple(replace(profile,
            client_keys=tuple(absolute(key) for key in profile.client_keys) if profile.client_keys is not None else None,
            known_hosts=absolute(profile.known_hosts) if profile.known_hosts else None) for profile in options.host_profiles),
        budget_dir=absolute(options.budget_dir) if options.budget_dir else None,
        client_keys=tuple(absolute(key) for key in options.client_keys),
        known_hosts=absolute(options.known_hosts or '~/.ssh/known_hosts'),
        log_file=absolute(options.log_file) if options.log_file else str(run_directory / 'audit.jsonl'))
    output = absolute(report_path) if report_path is not None else str(run_directory / ('report.' + format))
    if report_path is not None and not Path(output).parent.is_dir():
        raise ScheduleError('scheduled report parent directory must already exist')
    spool = absolute(spool_dir) if spool_dir is not None else None
    if spool is not None and not Path(spool).is_dir():
        raise ScheduleError('scheduled spool directory must already exist')
    return ScheduledInvocation(command, targets, pinned, output, format, spool)


class SwarmScheduledExecutor:
    def __init__(self, state_dir, swarm_factory):
        self.state_dir, self.swarm_factory = Path(state_dir), swarm_factory

    async def __call__(self, job):
        invocation = job.invocation
        private_directory(self.state_dir / 'runs', tighten=True)
        private_directory(self.state_dir / 'runs' / job.info.id, tighten=True)
        return await self.swarm_factory(invocation.options).run_to_file(
            invocation.hosts, invocation.command, invocation.report_path, invocation.format,
            spool_dir=invocation.spool_dir)
