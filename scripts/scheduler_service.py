"""Generate concrete service definitions; activation remains an operator action."""
import argparse
import getpass
import os
import plistlib
import shlex
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def absolute(value):
    path = str(Path(value).expanduser().absolute())
    if any(ord(c) < 32 or ord(c) == 127 for c in path):
        raise ValueError('control characters are forbidden in service paths')
    return path


def systemd_quote(value):
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"').replace('%', '%%').replace('$', '$$') + '"'


def windows_arguments(values):
    # Native Windows CreateProcess quoting, independently of the host platform.
    result = []
    for value in values:
        piece = '"'
        backslashes = 0
        for c in value:
            if c == '\\':
                backslashes += 1
            else:
                piece += '\\' * (backslashes * (2 if c == '"' else 1))
                if c == '"':
                    piece += '\\'
                piece += c
                backslashes = 0
        piece += '\\' * (2 * backslashes) + '"'
        result.append(piece)
    return ' '.join(result)


def worker_script(python, state_dir, *, background=False):
    arguments = [absolute(python), '-m', 'swassh', 'schedule', '--worker', '--state-dir', absolute(state_dir)]
    command = shlex.join(arguments)
    if not background:
        return ('#!/bin/sh\numask 077\nexec ' + command + '\n').encode('utf-8')
    return ('#!/bin/sh\numask 077\n'
        'unset SMF_FMRI SMF_METHOD SMF_RESTARTER SMF_ZONENAME\n'
        + command + ' &\nworker_pid=$!\nsleep 1\n'
        'if kill -0 "$worker_pid" 2>/dev/null; then\n    exit 0\nfi\n'
        'wait "$worker_pid"\nexit 1\n').encode('utf-8')


def generate(kind, python, state_dir, user=None, *, method_path=None):
    python, state_dir = absolute(python), absolute(state_dir)
    arguments = [python, '-m', 'swassh', 'schedule', '--worker', '--state-dir', state_dir]
    if kind == 'systemd':
        unit = '\n'.join([
            '[Unit]', 'Description=SWASSH persistent one-shot scheduler', '',
            '[Service]', 'Type=simple', 'ExecStart=' + ' '.join(map(systemd_quote, arguments)),
            'Restart=on-failure', 'RestartSec=5', 'TimeoutStopSec=30',
            'KillMode=control-group', 'UMask=0077', 'NoNewPrivileges=yes', '',
            '[Install]', 'WantedBy=default.target', ''])
        return 'swassh-scheduler.service', unit.encode('utf-8')
    if kind == 'launchd':
        return 'org.swassh.scheduler.plist', plistlib.dumps({
            'Label': 'org.swassh.scheduler', 'ProgramArguments': arguments,
            'RunAtLoad': True, 'KeepAlive': True, 'ThrottleInterval': 5,
            'ProcessType': 'Background', 'Umask': 0o077})
    if kind == 'src':
        return 'swassh-scheduler-src.sh', worker_script(python, state_dir)
    if kind == 'smf':
        if method_path is None:
            raise ValueError('SMF requires an explicit installed method path')
        identity = user or (str(os.geteuid()) if os.name == 'posix' else getpass.getuser())
        if not identity or any(ord(c) < 32 or ord(c) == 127 for c in identity):
            raise ValueError('invalid SMF user')
        bundle = ET.Element('service_bundle', type='manifest', name='site/swassh-scheduler')
        service = ET.SubElement(bundle, 'service', name='site/swassh-scheduler', type='service', version='1')
        ET.SubElement(service, 'create_default_instance', enabled='false')
        ET.SubElement(service, 'single_instance')
        dependency = ET.SubElement(service, 'dependency', name='filesystem-local',
            grouping='require_all', restart_on='none', type='service')
        ET.SubElement(dependency, 'service_fmri', value='svc:/system/filesystem/local:default')
        start = ET.SubElement(service, 'exec_method', type='method', name='start',
            exec=shlex.quote(absolute(method_path)).replace('%', '%%'), timeout_seconds='60')
        context = ET.SubElement(start, 'method_context')
        ET.SubElement(context, 'method_credential', user=identity, group=':default')
        ET.SubElement(service, 'exec_method', type='method', name='stop', exec=':kill', timeout_seconds='60')
        group = ET.SubElement(service, 'property_group', name='startd', type='framework')
        ET.SubElement(group, 'propval', name='duration', type='astring', value='contract')
        template = ET.SubElement(service, 'template')
        common = ET.SubElement(template, 'common_name')
        ET.SubElement(common, 'loctext', {'{http://www.w3.org/XML/1998/namespace}lang':'C'}).text = 'SWASSH persistent queue worker'
        header = b'<?xml version="1.0" encoding="utf-8"?>\n<!DOCTYPE service_bundle SYSTEM "/usr/share/lib/xml/dtd/service_bundle.dtd.1">\n'
        return 'swassh-scheduler-smf.xml', header + ET.tostring(bundle, encoding='utf-8') + b'\n'
    if kind != 'windows':
        raise ValueError('unknown service platform')
    namespace = 'http://schemas.microsoft.com/windows/2004/02/mit/task'
    ET.register_namespace('', namespace)
    def element(parent, name, text=None, **attrs):
        node = ET.SubElement(parent, '{' + namespace + '}' + name, attrs)
        node.text = text
        return node
    task = ET.Element('{' + namespace + '}Task', version='1.3')
    info = element(task, 'RegistrationInfo')
    element(info, 'Description', 'SWASSH persistent queue worker (current account)')
    identity = user or ((os.environ.get('USERDOMAIN', '') + '\\' if os.environ.get('USERDOMAIN') else '') + getpass.getuser())
    principals = element(task, 'Principals')
    principal = element(principals, 'Principal', id='Operator')
    element(principal, 'UserId', identity)
    element(principal, 'LogonType', 'InteractiveToken')
    element(principal, 'RunLevel', 'LeastPrivilege')
    triggers = element(task, 'Triggers')
    logon = element(triggers, 'LogonTrigger')
    element(logon, 'Enabled', 'true')
    element(logon, 'UserId', identity)
    settings = element(task, 'Settings')
    element(settings, 'MultipleInstancesPolicy', 'IgnoreNew')
    element(settings, 'DisallowStartIfOnBatteries', 'false')
    element(settings, 'StopIfGoingOnBatteries', 'false')
    element(settings, 'ExecutionTimeLimit', 'PT0S')
    element(settings, 'Enabled', 'true')
    restart = element(settings, 'RestartOnFailure')
    element(restart, 'Interval', 'PT1M')
    element(restart, 'Count', '3')
    actions = element(task, 'Actions', Context='Operator')
    execution = element(actions, 'Exec')
    element(execution, 'Command', python)
    element(execution, 'Arguments', windows_arguments(arguments[1:]))
    return 'swassh-scheduler.xml', ET.tostring(task, encoding='utf-8', xml_declaration=True)



class ServicePathOutput:
    """Print generated paths on legacy streams without changing file names or bytes.

    This standalone generator needs no installed application. Its display uses
    the same explicit backslash escaping as SWASSH text reports; real stream
    errors remain observable after the exclusive file creation succeeds.
    """

    def __init__(self, stream):
        self.stream = stream

    def write(self, path):
        """Write one absolute path; preserve Unicode on capable output streams."""
        text = str(path.absolute()) + '\n'
        encoding = getattr(self.stream, 'encoding', None)
        if encoding:
            text = text.encode(encoding, errors='backslashreplace').decode(encoding)
        self.stream.write(text)


def main(argv=None):
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__)
    parser.add_argument('--platform', choices=('systemd', 'launchd', 'windows', 'smf', 'src'), required=True)
    parser.add_argument('--python', default=sys.executable)
    parser.add_argument('--state-dir', required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--user', help='SMF account or Windows DOMAIN\\user; defaults to current account')
    args = parser.parse_args(argv)
    method = args.output_dir.absolute() / 'swassh-scheduler-smf.sh'
    name, data = generate(args.platform, args.python, args.state_dir, args.user, method_path=method)
    args.output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    files = [(args.output_dir / name, data)]
    if args.platform == 'smf':
        files.insert(0, (method, worker_script(args.python, args.state_dir, background=True)))
    written = []
    try:
        for path, contents in files:
            # Never follow links or overwrite an existing definition or method.
            with path.open('xb') as stream:
                written.append(path)
                stream.write(contents)
            if os.name == 'posix':
                path.chmod(0o700 if path.suffix == '.sh' else 0o600)
    except BaseException:
        for path in reversed(written):
            path.unlink()
        raise
    output = ServicePathOutput(sys.stdout)
    for path, _ in files:
        output.write(path)


if __name__ == '__main__':
    main()
