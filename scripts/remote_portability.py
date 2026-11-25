"""Certify an identical preprovisioned Solaris/AIX checkout through strict SSH."""
import argparse
import asyncio
import base64
import hashlib
import json
import shlex
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from swassh import Options, Swarm, FileTransfer, TransferDirection
from swassh.domain.inventory import parse_host


def source_manifest():
    paths = [ROOT/'pyproject.toml']
    for folder in ('src','tests','scripts','build_support'):
        paths.extend(path for path in (ROOT/folder).rglob('*.py') if '__pycache__' not in path.parts)
    return {path.relative_to(ROOT).as_posix():hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(paths)}


def remote_command(platform, python, checkout):
    if platform not in ('solaris','aix'):
        raise ValueError('this bridge targets Solaris and AIX')
    for path in (python,checkout):
        FileTransfer(TransferDirection.PUSH, 'validation', path)
    manifest = base64.b64encode(json.dumps(source_manifest(), separators=(',',':')).encode()).decode()
    expected_system = 'SunOS' if platform == 'solaris' else 'AIX'
    code = '\n'.join([
        'import base64,hashlib,json,os,platform,subprocess,sys',
        'from pathlib import Path',
        f'if platform.system() != {expected_system!r}: raise RuntimeError("wrong native OS")',
        'if sys.version_info < (3,11): raise RuntimeError("Python 3.11+ required")',
        f'root=Path({checkout!r})',
        'if root.is_symlink() or not root.is_dir(): raise RuntimeError("invalid checkout")',
        f'expected=json.loads(base64.b64decode({manifest!r}))',
        'actual={"pyproject.toml"}',
        'for folder in ("src","tests","scripts","build_support"):',
        '    actual.update(path.relative_to(root).as_posix() for path in (root/folder).rglob("*.py") if "__pycache__" not in path.parts)',
        'if actual != set(expected): raise RuntimeError("source file set drift")',
        'for name,digest in expected.items():',
        '    path=root/name',
        '    if not path.is_file() or path.is_symlink(): raise RuntimeError("missing or linked source")',
        '    if hashlib.sha256(path.read_bytes()).hexdigest()!=digest: raise RuntimeError("source drift: "+name)',
        'os.chdir(root)',
        f'steps=[("platform_gate.py",["--expected",{platform!r},"--require-rsync"]),',
        '       ("verify.py",[]),("coverage.py",[]),("build.py",[]),',
        '       ("validate_installation.py",[]),("package.py",[])]',
        'for script,arguments in steps:',
        '    result=subprocess.run([sys.executable,str(root/"scripts"/script),*arguments],timeout=1800)',
        '    if result.returncode: raise SystemExit(result.returncode)',
        'print("NATIVE_PORTABILITY_GATE=PASS",flush=True)',
    ])
    return shlex.join([python,'-c',code])


async def validate(host, command, report):
    report = Path(report).absolute()
    options = Options(concurrency=1, connect_rate=1, retries=0, command_timeout=3600,
        log_file=str(report.with_suffix('.audit.jsonl')))
    summary = await Swarm(options).run_to_file([parse_host(host)], command, report)
    return summary.ok


def main(argv=None):
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__)
    parser.add_argument('--platform', choices=('solaris','aix'), required=True)
    parser.add_argument('--host', required=True)
    parser.add_argument('--python', required=True, help='absolute interpreter path on target')
    parser.add_argument('--checkout', required=True, help='identical source tree already provisioned on target')
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        parse_host(args.host)
        command = remote_command(args.platform, args.python, args.checkout)
        ok = asyncio.run(validate(args.host, command, args.report))
    except (ValueError, OSError, RuntimeError):
        print('Native portability gate could not run; inspect paths, native clients and SSH credentials.', file=sys.stderr)
        return 2
    print(('PASS' if ok else 'FAIL') + ': native ' + args.platform + ' gate; report ' + str(args.report.absolute()))
    return 0 if ok else 1


if __name__ == '__main__':
    raise SystemExit(main())
