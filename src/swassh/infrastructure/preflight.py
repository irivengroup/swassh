"""Read-only local prerequisite inspection; credentials are never read or copied."""
import os
from pathlib import Path
import shutil
import stat

from ..application.preflight import CheckIssue, CheckReport, PreflightError
from ..domain.transfers import TransferDirection
from .filesystem import PinnedDirectory, is_link
from .execution_input import InputSnapshot
from .authentication import Authentication


class LocalPreflight:
    """Inspect current local state without subprocesses or remote connections.

    These observations do not reserve paths, validate cryptographic key contents,
    prove remote authorization, or guarantee that a later write will succeed.
    The execution adapters retain their own descriptor and permission checks.
    """
    def _file(self, path, label, *, private=False):
        try:
            resolved = Path(path).expanduser().resolve(strict=True)
            with PinnedDirectory(resolved.parent) as parent:
                descriptor = parent.open(resolved.name, os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0)
                                         | getattr(os, 'O_NOFOLLOW', 0))
                try:
                    info = os.fstat(descriptor)
                finally:
                    os.close(descriptor)
            if not stat.S_ISREG(info.st_mode):
                return CheckIssue(label + '_not_regular', 'error', 'Expected a regular readable file.')
            if private and not info.st_size:
                return CheckIssue(label + '_empty', 'error', 'Explicit private key file is empty.')
            if private and os.name == 'posix' and info.st_uid == os.geteuid() and info.st_mode & 0o077:
                return CheckIssue(label + '_permissions', 'error', 'Private key permissions are too broad; restrict access to its owner.')
            return CheckIssue(label + '_readable', 'ok', 'File is readable; content and remote authorization are not verified.')
        except FileNotFoundError:
            return CheckIssue(label + '_missing', 'error', 'File does not exist; correct the explicit path.')
        except PermissionError:
            return CheckIssue(label + '_unreadable', 'error', 'File access denied; verify account and permissions.')
        except (OSError, ValueError, RuntimeError):
            return CheckIssue(label + '_unsafe', 'error', 'File or parent path cannot be inspected safely.')

    def credentials(self, options):
        """Inspect explicit key metadata without reading secret contents."""
        issues = [self._file(path, f'key_{index}', private=True)
                  for index, path in enumerate(options.client_keys, 1)]
        for index, profile in enumerate(options.host_profiles, 1):
            issues.extend(self._file(path, f'profile_{index}_key_{key}', private=True)
                          for key, path in enumerate(profile.client_keys or (), 1))
        if options.askpass_executable or options.auth_method == 'password' or any(profile.auth_method == 'password' for profile in options.host_profiles):
            try:
                Authentication.provider(options)
                issues.append(CheckIssue('password_provider_available', 'ok', 'External provider is available; no secret requested.'))
            except (OSError, ValueError):
                issues.append(CheckIssue('password_provider_invalid', 'error', 'External askpass provider is unavailable or unsafe.'))
        return CheckReport(tuple(issues))

    def require_credentials(self, options):
        """Raise PreflightError before execution when explicit keys are unusable."""
        report = self.credentials(options)
        if not report.ok:
            raise PreflightError(report)

    def transport(self, options):
        """Return the located SSH executable or raise a controlled local error."""
        executable = shutil.which(options.ssh_executable)
        issues = list(self.credentials(options).issues)
        if executable is None:
            issues.append(CheckIssue('ssh_missing', 'error', 'OpenSSH executable not found; install it or correct --ssh-executable.'))
        report = CheckReport(tuple(issues))
        if not report.ok:
            raise PreflightError(report)
        return executable

    def _directory(self, path, label):
        try:
            with PinnedDirectory(Path(path).expanduser()) as directory:
                writable = os.access(directory.path, os.W_OK | os.X_OK)
            if not writable:
                return CheckIssue(label + '_access', 'error', 'Directory is not writable/searchable by this account.')
            return CheckIssue(label + '_accessible', 'ok', 'Directory access appears sufficient; no write was attempted.')
        except (OSError, ValueError):
            return CheckIssue(label + '_unavailable', 'error', 'Directory is missing, inaccessible or unsafe.')

    def _future_directory(self, path, label):
        """Check an existing ancestor without creating the future directory."""
        candidate = Path(path).expanduser().absolute()
        try:
            while True:
                try:
                    candidate.stat()
                    break
                except FileNotFoundError:
                    if candidate == candidate.parent:
                        raise
                    candidate = candidate.parent
            return self._directory(candidate, label)
        except (OSError, ValueError):
            return CheckIssue(label + '_unavailable', 'error', 'Existing parent cannot be inspected safely.')

    def inspect(self, options, *, output=None, spool=None, request=None, settings=None, state=None):
        """Collect local observations without creating files or launching tools.

        Transfer requests require settings. Paths are observations only and
        must be checked again by the execution adapters at their point of use.
        """
        issues = list(self.credentials(options).issues)
        executable = shutil.which(options.ssh_executable)
        for index, profile in enumerate(options.host_profiles, 1):
            if profile.known_hosts is not None:
                issues.append(self._file(profile.known_hosts, f'profile_{index}_known_hosts'))
        if options.stdin_file is not None:
            try:
                InputSnapshot.stdin(options)
                issues.append(CheckIssue('stdin_readable', 'ok', 'Input snapshot fits its budget; contents are not displayed.'))
            except (OSError, ValueError):
                issues.append(CheckIssue('stdin_invalid', 'error', 'Input is unsafe, changed, unreadable or exceeds its budget.'))
        issues.append(CheckIssue('ssh_available' if executable else 'ssh_missing',
            'ok' if executable else 'error',
            'OpenSSH executable lookup only; version and server capabilities are not verified.'))
        known = self._file(options.known_hosts or '~/.ssh/known_hosts', 'known_hosts')
        if options.auth_method == 'gssapi' or any(profile.auth_method == 'gssapi' for profile in options.host_profiles):
            issues.append(CheckIssue('gssapi_unverified', 'warning', 'Client GSSAPI support, tickets, realm and service principals are not probed.'))
        # A readable file does not prove that any particular server key is trusted.
        issues.append(known)
        if os.name == 'posix' and os.environ.get('SSH_AUTH_SOCK'):
            try:
                socket_present = stat.S_ISSOCK(Path(os.environ['SSH_AUTH_SOCK']).stat().st_mode)
            except (OSError, ValueError):
                socket_present = False
            issues.append(CheckIssue('agent_socket_present' if socket_present else 'agent_socket_unavailable',
                'warning', 'Agent socket presence does not prove availability or an unlocked identity.' if socket_present
                else 'Configured SSH agent socket is unavailable; load the key into an available agent if required.'))
        else:
            issues.append(CheckIssue('agent_unverified', 'warning',
                'Agent identities are not probed. Encrypted keys need an available unlocked agent; no terminal prompt is used.'))
        if not options.client_keys:
            issues.append(CheckIssue('identity_implicit', 'warning',
                'No explicit key supplied. Default identities or agent authentication remain unverified; use -k when appropriate.'))
        if output is not None:
            destination = Path(output).expanduser().absolute()
            issues.append(self._directory(destination.parent, 'report_parent'))
            if destination.is_symlink() or (destination.exists() and not destination.is_file()):
                issues.append(CheckIssue('report_target_invalid', 'error', 'Report destination must not be a link or non-file object.'))
        if spool is not None:
            issues.append(self._directory(spool, 'spool'))
        issues.append(self._future_directory(options.budget_dir or Path.home() / '.swassh/budgets', 'budget_parent'))
        if options.log_file is not None:
            issues.append(self._future_directory(Path(options.log_file).expanduser().parent, 'audit_parent'))
        if state is not None:
            issues.append(self._future_directory(state, 'scheduler_parent'))
        if request is not None:
            if settings is None:
                raise ValueError('transfer settings required')
            rsync = shutil.which(settings.rsync_executable) if os.name == 'posix' else None
            sftp = shutil.which(settings.sftp_executable)
            local = Path(request.local_path).expanduser()
            directory = local.is_dir() if request.direction == TransferDirection.PUSH else request.remote_path.endswith('/')
            required_rsync = settings.dry_run or directory
            available = bool(rsync if required_rsync else rsync or sftp)
            issues.append(CheckIssue('transfer_tool_available' if available else 'transfer_tool_missing',
                'ok' if available else 'error', 'Required local transfer tool lookup; versions and remote tools are not verified.'))
            if request.direction == TransferDirection.PUSH:
                try:
                    info = local.lstat()
                    if is_link(info):
                        issues.append(CheckIssue('source_link', 'error', 'Transfer source must not be a symbolic link or reparse point.'))
                    elif stat.S_ISREG(info.st_mode) and info.st_size > settings.max_file_mib * 1024**2:
                        issues.append(CheckIssue('source_budget', 'error', 'Source exceeds the configured file size budget.'))
                    if directory != request.remote_path.endswith('/'):
                        issues.append(CheckIssue('destination_shape', 'error', 'Directory destinations must end with slash; file destinations must name a file.'))
                except (OSError, ValueError):
                    issues.append(CheckIssue('source_metadata', 'error', 'Source metadata is unavailable.'))
                if local.is_dir():
                    try:
                        with PinnedDirectory(local):
                            issues.append(CheckIssue('source_directory', 'ok', 'Source directory exists; descendants are not scanned.'))
                    except (OSError, ValueError):
                        issues.append(CheckIssue('source_directory_unsafe', 'error', 'Source directory cannot be inspected safely.'))
                else:
                    issues.append(self._file(local, 'source'))
            else:
                # Normal pull may create its private destination; preview may not.
                if local.absolute() == Path(local.absolute().anchor):
                    issues.append(CheckIssue('pull_root', 'error', 'Pull destination must not be a filesystem root.'))
                inspect_directory = self._directory if settings.dry_run else self._future_directory
                issues.append(inspect_directory(local, 'pull_destination'))
            if directory and settings.verify_sha256:
                issues.append(CheckIssue('sha256_directory', 'error', 'SHA-256 verification supports single files only.'))
        issues.append(CheckIssue('remote_unverified', 'warning',
            'No network connection made. Server trust, authentication and remote permissions remain unverified.'))
        return CheckReport(tuple(issues))
