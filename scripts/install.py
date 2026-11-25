"""Deploy SWASSH through pip, then configure the user's PATH when necessary."""

import argparse
from pathlib import Path
import subprocess
import sys
import re
import venv


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('wheel', type=Path, nargs='?', help='local SWASSH wheel for offline installation')
    parser.add_argument('--package-version', help='exact SWASSH version to install from the configured pip index')
    parser.add_argument('--user', action='store_true', help='install in the user site')
    parser.add_argument('--venv', type=Path, help='create or reuse a dedicated application environment')
    parser.add_argument('--skip-path', action='store_true', help='leave PATH management to the deployment environment')
    args = parser.parse_args()
    if (args.wheel is None) == (args.package_version is None):
        parser.error('choose a local wheel or --package-version, exclusively')
    if args.user and args.venv:
        parser.error('--user and --venv are mutually exclusive')
    executable = sys.executable
    command = [executable, '-m', 'pip', 'install', '--disable-pip-version-check', '--no-deps']
    if args.wheel is not None:
        wheel = args.wheel.resolve(strict=True)
        if wheel.suffix != '.whl' or not wheel.name.startswith('swassh-'):
            parser.error('a local SWASSH wheel is required')
        command.append('--no-index')
        requirement = str(wheel)
    else:
        # An exact version keeps deployments reproducible and cannot introduce
        # pip options, URLs or another distribution through the requirement.
        if not re.fullmatch(r'[0-9]+(?:\.[0-9]+)*(?:(?:a|b|rc)[0-9]+)?(?:\.post[0-9]+)?(?:\.dev[0-9]+)?', args.package_version):
            parser.error('package version must be an exact numeric Python release version')
        requirement = 'swassh==' + args.package_version
    if args.venv:
        environment = args.venv.expanduser().absolute()
        if environment.exists():
            if not (environment / 'pyvenv.cfg').is_file():
                parser.error('existing application directory is not a Python virtual environment')
        else:
            venv.EnvBuilder(with_pip=True).create(environment)
        executable = str(environment / ('Scripts/python.exe' if sys.platform == 'win32' else 'bin/python'))
        if not Path(executable).is_file():
            parser.error('application environment interpreter is missing')
        command[0] = executable
    if args.user:
        command.append('--user')
    result = subprocess.run([*command, requirement], check=False)
    if result.returncode or args.skip_path:
        return result.returncode
    configure = [executable, '-m', 'swassh', 'setup-path']
    if args.venv:
        configure.append('--app-venv')
    return subprocess.run(configure, check=False).returncode


if __name__ == '__main__':
    raise SystemExit(main())
