"""Exercise real pip index deployment using loopback and a disposable app venv."""
import functools
import hashlib
import http.server
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import threading
import tomllib

ROOT = Path(__file__).resolve().parents[1]


class QuietIndex(http.server.SimpleHTTPRequestHandler):
    """Serve only the temporary package index without logging local paths."""

    def log_message(self, format, *arguments):
        """The probe emits a sanitized result instead of request logs."""
        return


class DeploymentProbe:
    """Check actual pip installation, entrypoint discovery and repeat deployment."""

    def run(self):
        version = tomllib.loads((ROOT / 'pyproject.toml').read_text())['project']['version']
        with tempfile.TemporaryDirectory(prefix='swassh-deployment-') as directory:
            # The installer records canonical venv paths, including system aliases.
            root = Path(directory).resolve(strict=True)
            index = root / 'index' / 'simple' / 'swassh'
            index.mkdir(parents=True)
            backend = runpy.run_path(str(ROOT / 'build_support/swassh_build.py'))
            name = backend['build_wheel'](str(index))
            digest = hashlib.sha256((index / name).read_bytes()).hexdigest()
            (index / 'index.html').write_text(f'<a href="{name}#sha256={digest}">{name}</a>\n')
            handler = functools.partial(QuietIndex, directory=str(root / 'index'))
            server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                home, environment = root / 'home', root / 'app'
                home.mkdir(mode=0o700)
                env = dict(os.environ)
                for key in ('PYTHONPATH', 'PIP_EXTRA_INDEX_URL', 'PIP_NO_INDEX', 'PIP_TARGET', 'PIP_PREFIX', 'PIP_USER'):
                    env.pop(key, None)
                env.update(HOME=str(home), USERPROFILE=str(home), SHELL='/bin/sh',
                           PIP_CONFIG_FILE=os.devnull, PIP_INDEX_URL=f'http://127.0.0.1:{server.server_port}/simple',
                           PIP_DISABLE_PIP_VERSION_CHECK='1', PIP_CACHE_DIR=str(root / 'cache'))
                command = [sys.executable, str(ROOT / 'scripts/install.py'),
                           '--package-version', version, '--venv', str(environment)]
                # Native registry behavior is separately tested in a disposable
                # key. Never rewrite the test operator's real Windows user PATH.
                if os.name == 'nt':
                    command.append('--skip-path')
                first = subprocess.run(command, cwd=root, env=env, text=True, capture_output=True, timeout=120)
                if first.returncode:
                    raise AssertionError(first.stdout + first.stderr)
                python = environment / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
                observed = subprocess.check_output([str(python), '-m', 'swassh', '--version'],
                                                  cwd=root, env=env, text=True, timeout=30).strip()
                if not (observed == 'swassh ' + version):
                    raise AssertionError(observed)
                profile = home / '.profile'
                before = profile.read_bytes() if profile.exists() else None
                if os.name == 'posix':
                    if not (before is not None):
                        raise AssertionError()
                    shell = subprocess.check_output(['/bin/sh', '-c',
                        'set -eu; . "$1"; command -v swassh; swassh --version', 'probe', str(profile)],
                        cwd=root, env=env, text=True, timeout=30).splitlines()
                    if not (shell == [str(environment / 'bin/swassh'), observed]):
                        raise AssertionError(shell)
                repeated = subprocess.run(command, cwd=root, env=env, text=True, capture_output=True, timeout=120)
                if not (repeated.returncode == 0):
                    raise AssertionError(repeated.stdout + repeated.stderr)
                if not ((profile.read_bytes() if profile.exists() else None) == before):
                    raise AssertionError()
                missing = command.copy()
                missing[missing.index('--package-version') + 1] = '0.0.0.post99999999'
                failed = subprocess.run(missing, cwd=root, env=env, text=True, capture_output=True, timeout=60)
                if not (failed.returncode != 0):
                    raise AssertionError()
                if not ((profile.read_bytes() if profile.exists() else None) == before):
                    raise AssertionError()
                return {'status': 'EXÉCUTÉ', 'version': version, 'pip_index': 'isolated loopback',
                        'wheel_sha256': digest, 'fresh_app_venv': True, 'installed_entrypoint': True,
                        'repeat_deployment_idempotent': True, 'pip_failure_propagated': True,
                        'posix_path_in_real_shell': os.name == 'posix',
                        'windows_registry': 'separate disposable-key test; real user PATH untouched'}
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)


def main():
    result = DeploymentProbe().run()
    target = ROOT / 'validation'
    target.mkdir(exist_ok=True)
    (target / 'deployment.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
