"""Bounded native rsync/SFTP transfers over private strict OpenSSH configuration."""
from __future__ import annotations

from ..application.task_ownership import wait_owned

import asyncio
import os
import re
import shlex
import shutil
import stat
import tempfile
import time
import uuid
from dataclasses import replace
from pathlib import Path, PurePosixPath

from ..application.options import Options
from ..application.transfer_settings import TransferSettings
from ..domain.models import Host, Result, Status, TransferReceipt
from ..domain.transfers import FileTransfer, TransferDirection, host_directory, local_filename
from .ssh import SSHTransport, _Buffer, _config, _cleanup_process
from .filesystem import private_directory, PinnedDirectory
from .process_guard import launch_native
from .preview import PreviewBuffer
from .integrity import PROBE, TOOLS, digest_file, hash_command, parse_hash, publish_command
from .lifecycle import finish_task, ensure_subprocess_loop
from .authentication import Authentication


def _modern_rsync(text: str) -> bool:
    match = re.search(r"rsync\s+version\s+(\d+)\.(\d+)\.(\d+)", text)
    return bool(match and tuple(map(int, match.groups())) >= (3, 5, 0))


def _batch_quote(path: str) -> str:
    if any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in path):
        raise ValueError("SFTP paths cannot contain control characters")
    # OpenSSH sftp protects glob metacharacters inside quotes itself.
    # Escape only the batch lexer quote/backslash characters, once.
    return '"' + path.replace("\\", "\\\\").replace('"', '\\"') + '"'



class NativeFileTransport:
    def __init__(self, options: Options, settings: TransferSettings,
                 request: FileTransfer, bandwidth_kib: int):
        self.options, self.settings, self.request = options, settings, request
        self.bandwidth_kib = bandwidth_kib
        self.ssh = SSHTransport(options)
        self.rsync = shutil.which(settings.rsync_executable) if os.name == "posix" else None
        self.sftp = shutil.which(settings.sftp_executable)
        self._directory = None
        self.local = Path(request.local_path).expanduser().absolute()
        self.is_directory = request.remote_path.endswith("/")
        self.size = None
        self._local_reason = None
        self.source_digest = None
        self._admission_wait_seconds = self._native_seconds = 0.0

    def metrics(self):
        values = self.ssh.metrics()
        return {"shared_admission_wait_seconds": self._admission_wait_seconds + values["shared_admission_wait_seconds"],
                "native_client_seconds": self._native_seconds + values["native_client_seconds"]}

    async def __aenter__(self):
        self._directory = tempfile.TemporaryDirectory(prefix="swassh-transfer-")
        try:
            if self.request.direction == TransferDirection.PUSH:
                info = self.local.lstat()
                if stat.S_ISDIR(info.st_mode):
                    self.is_directory = True
                    if not self.request.remote_path.endswith("/"):
                        raise ValueError("directory destination must end with slash")
                    # A directory is synced live by rsync. Never traverse it in Python.
                    self.source = str(self.local) + ("/" if self.request.local_path.endswith("/") else "")
                elif stat.S_ISREG(info.st_mode):
                    if os.name == 'nt':
                        from .windows import open_file_without_reparse
                        # CPython #157671: Windows lstat and fstat can report
                        # different ctime semantics. Establish the baseline via
                        # fstat too; retain change-time checks during the copy.
                        metadata_fd = open_file_without_reparse(self.local, os.O_RDONLY)
                        try:
                            opened = os.fstat(metadata_fd)
                            if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (
                                    info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns):
                                raise ValueError('source changed before metadata acquisition')
                            info = opened
                        finally:
                            os.close(metadata_fd)
                    if self.is_directory:
                        raise ValueError("file destination must name a file")
                    if info.st_size > self.settings.max_file_mib * 1024**2:
                        raise ValueError("source exceeds file budget")
                    snapshot = Path(self._directory.name) / "source"
                    def copy():
                        # No symlink-following source race; only regular files are accepted.
                        fd = os.open(self.local, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
                        with os.fdopen(fd, "rb") as source, snapshot.open("xb") as target:
                            before = os.fstat(source.fileno())
                            if not stat.S_ISREG(before.st_mode) or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns):
                                raise ValueError("source changed before snapshot")
                            copied = 0
                            while chunk := source.read(65536):
                                copied += len(chunk)
                                if copied > self.settings.max_file_mib * 1024**2:
                                    raise ValueError("source exceeded budget during snapshot")
                                target.write(chunk)
                            after = os.fstat(source.fileno())
                            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                                    after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                                raise ValueError("source changed during snapshot")
                        os.utime(snapshot, ns=(info.st_atime_ns, info.st_mtime_ns))
                        if hasattr(os, "chown"):
                            current = snapshot.stat()
                            if (current.st_uid, current.st_gid) != (info.st_uid, info.st_gid):
                                os.chown(snapshot, info.st_uid, info.st_gid)
                        snapshot.chmod(stat.S_IMODE(info.st_mode) & ~0o6000)
                    # Cancellation must wait for the I/O thread before deleting its staging.
                    copying = asyncio.create_task(asyncio.to_thread(copy))
                    try:
                        await wait_owned(copying)
                    except asyncio.CancelledError:
                        await finish_task(copying)
                        raise
                    self.source, self.size = str(snapshot), info.st_size
                else:
                    raise ValueError("push requires a regular file or directory")
            else:
                if self.local == Path(self.local.anchor):
                    raise ValueError("pull destination must not be a filesystem root")
                if self.settings.dry_run:
                    # The preview destination must exist; never create directories.
                    with PinnedDirectory(self.local) as pinned:
                        self.local = pinned.path
                else:
                    self.local = private_directory(self.local)
            if self.settings.verify_sha256:
                if self.is_directory:
                    raise ValueError("SHA-256 verification is available for single files only")
                if self.request.direction == TransferDirection.PUSH:
                    # A verified remote temporary must never be world-writable.
                    Path(self.source).chmod(0o600)
                    hashing = asyncio.create_task(asyncio.to_thread(digest_file, self.source,
                        self.settings.max_file_mib * 1024**2))
                    try:
                        self.source_digest = await wait_owned(hashing)
                    except asyncio.CancelledError:
                        await finish_task(hashing)
                        raise
            if self.rsync:
                version = await self._run([self.rsync, "--version"], Host("localhost"), timeout=5)
                if version.status != Status.SUCCESS or not _modern_rsync(version.stdout):
                    self.rsync = None
                    self._local_reason = "local rsync version unsupported"
            else:
                self._local_reason = "local rsync unavailable"
            return self
        except BaseException:
            self._directory.cleanup()
            self._directory = None
            raise

    async def __aexit__(self, *exc):
        if self._directory:
            self._directory.cleanup()
            self._directory = None

    async def _run(self, argv: list[str], host: Host, *, timeout: float | None = None,
                   watched: Path | None = None) -> Result:
        started = time.monotonic()
        preview = "--dry-run" in argv
        encoding = self.ssh.profiles.for_host(host).encoding
        stdout, stderr = (PreviewBuffer(self.options.max_output_bytes) if preview else _Buffer(self.options.max_output_bytes, encoding=encoding)), _Buffer(self.options.max_output_bytes, encoding=encoding)
        process = None
        tasks = []
        status, error, code = Status.ERROR, None, None
        async def watchdog():
            while True:
                await asyncio.sleep(0.1)
                if watched:
                    # Dedicated directory also includes rsync's hidden native temporary.
                    total = 0
                    # DirEntry.stat() omits Windows link counts and caches
                    # metadata. Inspect opened entries inside the pinned stage;
                    # keep nofollow/nonblocking and hard-link rejection intact.
                    with PinnedDirectory(watched.parent, private=True) as parent, os.scandir(
                            parent.fd if parent.fd is not None else parent.path) as entries:
                        for entry in entries:
                            if os.name == 'nt':
                                # Native SFTP denies concurrent data readers.
                                # Query full handle metadata, including links,
                                # rather than weakening validation to stat().
                                from .windows import regular_file_size
                                total += regular_file_size(parent.path / entry.name)
                            else:
                                descriptor = parent.open(entry.name, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
                                                         | getattr(os, 'O_NONBLOCK', 0))
                                try:
                                    info = os.fstat(descriptor)
                                finally:
                                    os.close(descriptor)
                                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                                    raise ValueError("download staging contains a link or special entry")
                                total += info.st_size
                    if total > self.settings.max_file_mib * 1024**2:
                        raise ValueError("download exceeds file budget")
        try:
            ensure_subprocess_loop()
            env = Authentication.environment(self.options, self.ssh.profiles.for_host(host))
            for key in list(env):
                if key.startswith("RSYNC_"):
                    del env[key]
            async with asyncio.timeout(timeout or self.settings.timeout):
                process = await launch_native(*argv, options=self.options,
                    connected=not (len(argv) == 2 and argv[1] == "--version"),
                    bandwidth=self.bandwidth_kib,
                    stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE, env=env,
                    start_new_session=os.name == "posix", limit=65536)
                tasks = [asyncio.create_task(stdout.consume(process.stdout)),
                         asyncio.create_task(stderr.consume(process.stderr))]
                waiter, watcher = asyncio.create_task(process.wait()), asyncio.create_task(watchdog())
                tasks.extend([waiter, watcher])
                done, _ = await asyncio.wait([waiter, watcher], return_when=asyncio.FIRST_COMPLETED)
                if watcher in done:
                    await watcher
                code = await waiter
                await asyncio.gather(*tasks[:2])
                status = Status.SUCCESS if code == 0 else Status.ERROR if code == 125 else Status.FAILED
                if preview and stdout.invalid:
                    status, error = Status.ERROR, "invalid rsync preview itemisation"
        except TimeoutError:
            status, error = Status.TIMEOUT, "transfer deadline exceeded; remote state may be partial"
        except (OSError, ValueError):
            status, error = Status.ERROR, "transfer I/O or file budget error"
        finally:
            metrics = await _cleanup_process(process, tasks)
            self._admission_wait_seconds += metrics.get("admission_wait_seconds", 0)
            self._native_seconds += metrics.get("native_seconds", 0)
        return Result(host, status, stdout.text, stderr.text, code, error=error,
                      duration=time.monotonic()-started,
                      stdout_truncated=stdout.truncated, stderr_truncated=stderr.truncated)

    async def transfer(self, host: Host) -> Result:
        started = time.monotonic()
        receipt = TransferReceipt(self.request.direction.value, str(self.local), self.request.remote_path)
        fallback = self._local_reason
        backend = "sftp"
        if self.rsync:
            # Probe is read-only; never retry a data operation or infer replay from stderr.
            probe = await self.ssh.execute(host, "rsync --version")
            if probe.status == Status.SUCCESS and _modern_rsync(probe.stdout):
                backend = "rsync"
                fallback = None
            elif probe.status in (Status.SUCCESS, Status.FAILED):
                fallback = "remote rsync unavailable or unsupported"
            else:
                return replace(probe, transfer=receipt)
        if self.settings.dry_run and backend != "rsync":
            return Result(host, Status.ERROR, error="readonly preview requires supported rsync on both sides",
                transfer=replace(receipt, backend=backend, fallback_reason=fallback))
        if backend == "sftp" and self.is_directory:
            return Result(host, Status.ERROR,
                error="SFTP cannot preserve directory --delete, hard links and numeric IDs; rsync required",
                transfer=replace(receipt, backend="sftp", fallback_reason=fallback))
        if backend == "sftp" and not self.sftp:
            return Result(host, Status.ERROR, error="native SFTP client unavailable",
                          transfer=replace(receipt, fallback_reason=fallback))
        # rsync's protected-args still interprets remote source wildcards.
        if backend == "rsync" and self.request.direction == TransferDirection.PULL and any(
                c in self.request.remote_path for c in "*?[]\\"):
            if self.is_directory:
                return Result(host, Status.ERROR, error="directory source must not contain glob characters", transfer=receipt)
            if self.settings.dry_run:
                return Result(host, Status.ERROR, error="rsync preview requires a literal source without glob characters", transfer=receipt)
            backend, fallback = "sftp", "literal remote path requires SFTP"
            if not self.sftp:
                return Result(host, Status.ERROR, error="native SFTP client unavailable", transfer=receipt)
        tool = expected = None
        if self.settings.verify_sha256:
            probe = await self.ssh.execute(host, PROBE)
            tool = probe.stdout.strip()
            if probe.status != Status.SUCCESS or probe.stdout_truncated or tool not in TOOLS:
                return replace(probe, status=Status.ERROR, error="no supported remote SHA-256 utility; no data sent", transfer=receipt)
            if self.request.direction == TransferDirection.PULL:
                check = await self.ssh.execute(host, hash_command(tool, self.request.remote_path))
                if check.status != Status.SUCCESS or check.stdout_truncated:
                    return replace(check, status=Status.ERROR if check.stdout_truncated else check.status,
                        error="remote source hash unavailable; no data received", transfer=receipt)
                try:
                    expected = parse_hash(tool, check.stdout)
                except ValueError:
                    return Result(host, Status.ERROR, error="invalid remote source hash; no data received", transfer=receipt)
        stage = None
        staging = None
        temporary = None
        pinned = None
        try:
            with tempfile.TemporaryDirectory(prefix="swassh-host-") as directory:
                config = Path(directory) / "config"
                config.write_text(_config(host, self.options, self.ssh.profiles.for_host(host),
                    wire_lifetime=self.settings.timeout).replace("LogLevel DEBUG1", "LogLevel ERROR"), encoding="utf-8")
                config.chmod(0o600)
                if self.request.direction == TransferDirection.PULL:
                    destination = self.local / host_directory(host)
                    if self.settings.dry_run:
                        with PinnedDirectory(destination) as existing:
                            destination = existing.path
                    else:
                        destination = private_directory(destination, tighten=True)
                    # A preview must not rewrite the destination DACL on Windows.
                    pinned = PinnedDirectory(destination, private=not self.settings.dry_run)
                    if self.is_directory:
                        target = str(destination) + "/"
                    else:
                        final = destination / local_filename(self.request.remote_path)
                        if self.settings.dry_run:
                            target = str(final)
                        else:
                            staging = tempfile.TemporaryDirectory(prefix=".swassh-stage-", dir=destination)
                            stage = Path(staging.name) / "data"
                            stage.touch(mode=0o600)
                            target = str(stage)
                    receipt = replace(receipt, local_path=target if self.is_directory else str(final))
                else:
                    target = self.request.remote_path
                    if self.settings.verify_sha256:
                        remote = PurePosixPath(target)
                        temporary = str(remote.parent / (".swassh-"+uuid.uuid4().hex+".part"))
                        target = temporary
                if backend == "rsync":
                    ssh_command = shlex.join([self.ssh.executable, "-F", str(config), "-T"])
                    source, destination_arg = ((self.source, "swassh-target:"+target)
                        if self.request.direction == TransferDirection.PUSH else
                        ("swassh-target:"+self.request.remote_path, target))
                    profile = self.settings.rsync_options
                    if self.settings.dry_run:
                        # Suppress -v/-P and use only fixed-size itemisation records.
                        profile = ("-azH", "--numeric-ids", "--delete", "--dry-run", "--itemize-changes", "--out-format=SWASSH:%i")
                    argv = [self.rsync, *profile, "--protect-args",
                            "--safe-links", "--no-devices", "--no-specials",
                            "--chmod=" + ("Dgo-rwx,Dugo-s,Fugo-s" if self.request.direction == TransferDirection.PULL else "Dugo-s,Fugo-s"),
                            "--max-alloc="+str(self.settings.max_rsync_alloc_mib)+"M",
                            "--bwlimit="+str(self.bandwidth_kib), "-e", ssh_command,
                            "--", source, destination_arg]
                else:
                    batch = Path(directory) / "batch"
                    if self.request.direction == TransferDirection.PUSH:
                        remote = PurePosixPath(target)
                        temporary = temporary or str(remote.parent / (".swassh-"+uuid.uuid4().hex+".part"))
                        commands = ("@put -p -f " + _batch_quote(self.source) + " " + _batch_quote(temporary) + "\n"
                                    + ("" if self.settings.verify_sha256 else
                                       "@rename " + _batch_quote(temporary) + " " + _batch_quote(target) + "\n"))
                    else:
                        commands = "@get -p -f " + _batch_quote(self.request.remote_path) + " " + _batch_quote(target) + "\n"
                    batch.write_text(commands, encoding="utf-8")
                    batch.chmod(0o600)
                    argv = [self.sftp, "-b", str(batch), "-B", "32768", "-R", "4",
                            "-l", str(8*self.bandwidth_kib), "-F", str(config),
                            "-S", self.ssh.executable, "swassh-target"]
                    if self.ssh.profiles.for_host(host).auth_method == 'password':
                        argv[1:1] = ['-o', 'BatchMode=no']
                await self.ssh._pacer.acquire()
                result = await self._run(argv, host, watched=stage)
                size = self.size
                if result.status == Status.SUCCESS and self.settings.verify_sha256:
                    if stage:
                        hashing = asyncio.create_task(asyncio.to_thread(digest_file, stage,
                            self.settings.max_file_mib * 1024**2))
                        try:
                            actual = await wait_owned(hashing)
                        except asyncio.CancelledError:
                            await finish_task(hashing)
                            raise
                        check = await self.ssh.execute(host, hash_command(tool, self.request.remote_path))
                        if (check.status != Status.SUCCESS or check.stdout_truncated
                                or parse_hash(tool, check.stdout) != expected or actual != expected):
                            return replace(result, status=Status.ERROR, error="SHA-256 mismatch; local file not published",
                                transfer=replace(receipt, backend=backend, fallback_reason=fallback))
                    else:
                        check = await self.ssh.execute(host, hash_command(tool, temporary))
                        if (check.status != Status.SUCCESS or check.stdout_truncated
                                or parse_hash(tool, check.stdout) != self.source_digest):
                            return replace(result, status=Status.ERROR, error="SHA-256 mismatch; remote file not published",
                                transfer=replace(receipt, backend=backend, fallback_reason=fallback, temporary_path=temporary))
                        publish = await self.ssh.execute(host, publish_command(tool, temporary,
                            self.request.remote_path, self.source_digest))
                        if publish.status != Status.SUCCESS:
                            return replace(publish, error="verified publish failed or ambiguous; inspect remote temporary, no replay",
                                transfer=replace(receipt, backend=backend, fallback_reason=fallback, temporary_path=temporary))
                if result.status == Status.SUCCESS and stage:
                    # Publication relative to the pinned host directory. The stage
                    # lives in its own private subdirectory; pin it before opening.
                    with PinnedDirectory(stage.parent, private=True) as origin:
                        # Windows fchmod (Python >=3.13) and FlushFileBuffers need
                        # write access. The Win32 adapter also rejects final-entry
                        # reparses; POSIX retains a descriptor-relative nofollow open.
                        flags = os.O_RDWR if os.name == 'nt' else os.O_RDONLY
                        descriptor = origin.open(stage.name, flags | getattr(os, 'O_NOFOLLOW', 0)
                                                 | getattr(os, 'O_NONBLOCK', 0))
                        try:
                            info = os.fstat(descriptor)
                            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > self.settings.max_file_mib * 1024**2:
                                raise ValueError("download exceeds file budget or is not a private regular file")
                            size = info.st_size
                            if hasattr(os, "fchmod"):
                                os.fchmod(descriptor, stat.S_IMODE(info.st_mode) & ~0o6000)
                            os.fsync(descriptor)
                        finally:
                            os.close(descriptor)
                        if os.name == 'posix':
                            os.replace(stage.name, final.name, src_dir_fd=origin.fd, dst_dir_fd=pinned.fd)
                            pinned.sync()
                        else:
                            os.replace(stage, pinned.path / final.name)
                if result.status == Status.SUCCESS:
                    # Never flood the console with -v/-P; detailed native output is bounded in failures.
                    message = (result.stdout if self.settings.dry_run else
                               "transfer complete; SHA-256 verified" if self.settings.verify_sha256 else "transfer complete")
                    result = replace(result, stdout=message, stderr="",
                                     stdout_truncated=False, stderr_truncated=False)
                    temporary = None
                return replace(result, duration=time.monotonic()-started,
                    transfer=replace(receipt, backend=backend, bytes_transferred=size if result.status == Status.SUCCESS and not self.settings.dry_run else None,
                                     fallback_reason=fallback, temporary_path=temporary))
        except (OSError, ValueError):
            return Result(host, Status.ERROR, error="transfer path or publish error", duration=time.monotonic()-started,
                          transfer=replace(receipt, backend=backend, fallback_reason=fallback, temporary_path=temporary))
        finally:
            if pinned:
                pinned.close()
            if staging:
                staging.cleanup()
