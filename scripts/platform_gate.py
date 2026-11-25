"""Native platform probe: no network connections and no external Python packages."""
import argparse
import asyncio
import json
import os
import platform
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from swassh import Host, Options, Result, Status, Swarm
from swassh.infrastructure.resources import resource_plan
from swassh.infrastructure.schedule_store import SQLiteScheduleStore
from swassh.infrastructure.ssh import _config
from swassh.infrastructure.transfers import _modern_rsync

SYSTEMS = {'linux':'Linux', 'solaris':'SunOS', 'aix':'AIX', 'macos':'Darwin', 'windows':'Windows'}



class EffectiveSSHConfiguration:
    """Verify the effective default-profile contract reported by native ssh -G.

    This checks a bounded UTF-8 configuration report, not binary provenance,
    server identity or authentication. Unknown complete options are permitted;
    each required security option must occur exactly once with its safe value.
    """

    LIMIT = 131072
    REQUIRED = {
        'hostname': frozenset({'probe.invalid'}), 'port': frozenset({'22'}),
        'batchmode': frozenset({'yes', 'true'}),
        'stricthostkeychecking': frozenset({'yes', 'true'}),
        'clearallforwardings': frozenset({'yes', 'true'}),
        **{name: frozenset({'no', 'false'}) for name in (
            'forwardagent', 'forwardx11', 'permitlocalcommand',
            'passwordauthentication', 'kbdinteractiveauthentication',
            'controlmaster', 'requesttty', 'tunnel', 'updatehostkeys',
            'verifyhostkeydns', 'addkeystoagent')},
        'connectionattempts': frozenset({'1'}),
        'serveraliveinterval': frozenset({'5'}),
        'serveralivecountmax': frozenset({'2'}),
    }

    @classmethod
    def require(cls, payload):
        """Raise ValueError for absent, ambiguous or unsafe effective settings."""
        if not isinstance(payload, bytes) or not payload or len(payload) > cls.LIMIT:
            raise ValueError('native OpenSSH configuration report is missing or oversized')
        try:
            text = payload.decode('utf-8')
        except UnicodeError:
            raise ValueError('native OpenSSH configuration report is not UTF-8') from None
        if any((ord(char) < 32 and char not in '\t\r\n') or 127 <= ord(char) <= 159 for char in text):
            raise ValueError('native OpenSSH configuration report contains control characters')
        found = set()
        for line in text.splitlines():
            parts = line.split(None, 1)
            if len(parts) != 2:
                raise ValueError('native OpenSSH configuration report is malformed')
            name, value = parts[0].lower(), parts[1].strip().lower()
            if name in cls.REQUIRED:
                if name in found or value not in cls.REQUIRED[name]:
                    raise ValueError('native OpenSSH effective configuration violates the strict contract')
                found.add(name)
        if found != cls.REQUIRED.keys():
            raise ValueError('native OpenSSH effective configuration is incomplete')


async def storage_probe(directory):
    class Transport:
        async def execute(self, host, command):
            return Result(host, Status.SUCCESS, stdout='native platform probe')
    root = Path(directory)
    report, audit = root/'report.json', root/'audit.jsonl'
    summary = await Swarm(Options(log_file=str(audit)), transport=Transport()).run_to_file(
        ['probe-one','probe-two'], 'platform-probe', report)
    if not summary.ok or summary.report_worker_pid == os.getpid():
        raise ValueError('separate report process probe failed')
    if json.loads(report.read_text())['total'] != 2:
        raise ValueError('report contents probe failed')
    records = [json.loads(line) for line in audit.read_text().splitlines()]
    if not {'canary_started','fleet_started'} <= {record['event'] for record in records}:
        raise ValueError('audit admission probe failed')
    store = SQLiteScheduleStore(root/'state')
    try:
        if store.list():
            raise ValueError('fresh SQLite probe is not empty')
    finally:
        store.close()
    return {'separate_report_process':True, 'audit_fsync':True, 'sqlite':sqlite3.sqlite_version}


def probe(expected=None, require_rsync=False):
    system = platform.system()
    if expected is not None and system != SYSTEMS[expected]:
        raise ValueError('native OS does not match requested certification platform')
    if sys.version_info < (3, 11) or struct.calcsize('P') != 8:
        raise ValueError('native certification requires Python 3.11+ 64-bit')
    ssh, sftp, rsync = (shutil.which(name) for name in ('ssh','sftp','rsync'))
    if not ssh or not sftp:
        raise ValueError('native OpenSSH ssh and sftp must be available')
    rsync_supported = False
    if rsync and os.name == 'posix':
        result = subprocess.run([rsync,'--version'], capture_output=True, text=True, timeout=10)
        rsync_supported = result.returncode == 0 and _modern_rsync(result.stdout)
    if require_rsync and not rsync_supported:
        raise ValueError('complete rsync profile requires POSIX rsync 3.5.0+ locally')
    with tempfile.TemporaryDirectory(prefix='swassh-platform-') as directory:
        config = Path(directory)/'ssh-config'
        # Native configuration uses UTF-8 independently of Python's locale.
        config.write_text(_config(Host('probe.invalid'), Options()), encoding='utf-8')
        result = subprocess.run([ssh,'-G','-F',str(config),'swassh-target'], capture_output=True, timeout=10)
        if result.returncode:
            raise ValueError('native OpenSSH does not accept the strict configuration')
        EffectiveSSHConfiguration.require(result.stdout)
        storage = asyncio.run(storage_probe(directory))
    return {'system':system, 'release':platform.release(), 'python':platform.python_version(),
        'implementation':platform.python_implementation(), 'bits':64,
        'ssh_config_native':True, 'ssh':ssh, 'sftp':sftp,
        'rsync_profile_local':rsync_supported,
        'resource_plan':resource_plan(Options(), guarded=True).to_dict(), 'storage':storage,
        'network_connections':0, 'authenticated_remote_ssh':'not exercised by this probe'}


def main(argv=None):
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__)
    parser.add_argument('--expected', choices=tuple(SYSTEMS))
    parser.add_argument('--require-rsync', action='store_true')
    args = parser.parse_args(argv)
    try:
        value = probe(args.expected, args.require_rsync)
    except (ValueError, OSError, subprocess.SubprocessError, sqlite3.Error) as exc:
        print(json.dumps({'status':'failed','error':str(exc)}, ensure_ascii=True))
        return 2
    print(json.dumps({'status':'passed', **value}, ensure_ascii=True, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
