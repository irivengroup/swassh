"""Ephemeral native authentication fixtures, only inside the private QA namespace."""
import os
from pathlib import Path
import secrets
import shlex
import subprocess
import socket
import time
import shutil

# This entry point can also be called directly inside the QA namespace.
_SYSTEM_TOOL_PATH = '/usr/sbin:/usr/bin:/sbin:/bin'


def provision_realm(workspace):
    mounts = Path('/proc/self/mountinfo').read_text()
    if not any(' /etc ' in line and ' - overlay ' in line for line in mounts.splitlines()) or not any(' /root ' in line and ' - tmpfs ' in line for line in mounts.splitlines()):
        raise RuntimeError('authentication fixtures require private /etc and /root mounts')
    root = Path(workspace)/'authentication'
    root.mkdir(mode=0o700)
    def run(argv, *, data=None, env=None):
        environment = dict(os.environ if env is None else env, PATH=_SYSTEM_TOOL_PATH)
        result = subprocess.run(argv, input=data, env=environment, capture_output=True, timeout=30)
        if result.returncode:
            raise RuntimeError('isolated authentication provisioning failed: '+argv[0]+' '+result.stderr.decode(errors='replace'))
        return result.stdout
    username = 'swassh_' + secrets.token_hex(4)
    password = secrets.token_urlsafe(24)
    secret = root/'password'
    secret.write_text(password)
    secret.chmod(0o600)
    home = Path(workspace)/'password-home'
    home.mkdir(mode=0o700)
    # /etc is an overlay and this workspace is temporary; no host account changes.
    run(['useradd', '-M', '-d', str(home), '-s', '/bin/sh', username])
    run(['chpasswd'], data=(username+':'+password+'\nroot:'+password+'\n').encode())
    import pwd
    account = pwd.getpwnam(username)
    os.chown(home, account.pw_uid, account.pw_gid)
    Path(workspace).chmod(0o711)
    helper = root/'askpass'
    # This script is consumed by a shell: the private path must remain literal,
    # and a changed QA PATH must not replace the reader of fixture credentials.
    helper.write_text('#!/bin/sh\nexec /bin/cat -- '+shlex.quote(str(secret))+'\n', encoding='utf-8')
    helper.chmod(0o700)
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    canonical = socket.getfqdn('localhost')
    config = root/'krb5.conf'
    config.write_text(f'''[libdefaults]
 default_realm = SWASSH.TEST
 dns_lookup_kdc = false
 dns_lookup_realm = false
 rdns = false
 dns_canonicalize_hostname = false
 qualify_shortname = ""
[domain_realm]
 {canonical} = SWASSH.TEST
 localhost = SWASSH.TEST
[realms]
 SWASSH.TEST = {{
  kdc = 127.0.0.1:{port}
 }}
''')
    kdcconfig = root/'kdc.conf'
    kdcconfig.write_text(f'''[kdcdefaults]
 kdc_ports = {port}
 kdc_tcp_ports = {port}
[realms]
 SWASSH.TEST = {{
  database_name = {root}/principal
  key_stash_file = {root}/stash
  acl_file = {root}/acl
 }}
''')
    env = dict(os.environ, PATH=_SYSTEM_TOOL_PATH, KRB5_CONFIG=str(config), KRB5_KDC_PROFILE=str(kdcconfig),
               KRB5CCNAME='FILE:'+str(root/'ccache'), KRB5_KTNAME=str(root/'keytab'))
    run(['kdb5_util', 'create', '-s', '-r', 'SWASSH.TEST'], data=(password+'\n'+password+'\n').encode(), env=env)
    run(['kadmin.local', '-q', 'addprinc root'], data=(password+'\n'+password+'\n').encode(), env=env)
    for host in sorted({'localhost', canonical}):
        run(['kadmin.local', '-q', 'addprinc -randkey host/'+host], env=env)
        run(['kadmin.local', '-q', 'ktadd -k '+str(root/'keytab')+' host/'+host], env=env)
    daemon_path = shutil.which('krb5kdc', path=_SYSTEM_TOOL_PATH)
    if daemon_path is None:
        raise RuntimeError('authentication prerequisite unavailable: krb5kdc')
    log = (root/'kdc.log').open('wb')
    daemon = subprocess.Popen([daemon_path, '-n'], env=env, stdout=log, stderr=log)
    for _ in range(100):
        if daemon.poll() is not None:
            raise RuntimeError('isolated KDC exited')
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=0.1):
                break
        except OSError:
            time.sleep(0.05)
    kinit = next(path for path in Path('/usr/bin').glob('kinit*') if path.is_file())
    run([str(kinit), 'root'], data=(password+'\n').encode(), env=env)
    return {key: env[key] for key in ('KRB5_CONFIG', 'KRB5_KDC_PROFILE', 'KRB5CCNAME', 'KRB5_KTNAME')} | {
        'SWASSH_TEST_PASSWORD_USER': username, 'SWASSH_TEST_ASKPASS': str(helper),
        'SWASSH_TEST_REMOTE_HOME': str(home), 'SWASSH_TEST_KERBEROS': '1'}
