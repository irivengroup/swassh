"""Deterministic OpenSSH process fixture; never opens a network connection."""

import os
import sys
import time
from pathlib import Path

# Emit the same protocol bytes on every client OS. Captured remote output is
# intentionally not newline-normalized by the production transport.
sys.stdout.reconfigure(newline='\n')
sys.stderr.reconfigure(newline='\n')

args = sys.argv[1:]
diagnostic = Path(args[args.index("-E") + 1])
command = args[-1]
if path := os.environ.get("SWASSH_TEST_CALLS"):
    with open(path, "a") as stream:
        stream.write(command + "\n")
started = "Authenticated to test\ndebug1: Sending command: fixture\n"
if command == "unreachable":
    diagnostic.write_text("ssh: connect to host test port 22: Connection refused\n")
    sys.exit(255)
if command == "auth":
    diagnostic.write_text("Permission denied (publickey).\n")
    sys.exit(255)
if command == "key":
    diagnostic.write_text("Host key verification failed.\n")
    sys.exit(255)
if command == "unknown":
    diagnostic.write_text("Invalid configuration\n")
    sys.exit(255)
if command == "interrupt":
    diagnostic.write_text(started)
    sys.exit(255)
if command == "diagnostic":
    diagnostic.write_text(started + "x" * 200000)
    time.sleep(3)
if command == "sleep":
    diagnostic.write_text(started)
    print("partial", flush=True)
    if ready := os.environ.get("SWASSH_TEST_READY"):
        Path(ready).write_text("ready")
    time.sleep(3)
if command == "large":
    sys.stdout.buffer.write(b"a" * 300000)
    sys.stderr.buffer.write(b"b" * 300000)
if command == "binary":
    sys.stdout.buffer.write(b"bad\xff")
if command == 'stdin-echo':
    sys.stdout.buffer.write(sys.stdin.buffer.read())
if command == 'latin1':
    sys.stdout.buffer.write(b'caf\xe9\n')
if command == 'live':
    print('early', flush=True)
    if release := os.environ.get('SWASSH_TEST_RELEASE'):
        while not Path(release).exists():
            time.sleep(0.01)
    print('late', flush=True)
if command == "ok":
    print("Linux")
if command == "failed":
    print("failure", file=sys.stderr)
    diagnostic.write_text(started + "debug1: Exit status 7\n")
    sys.exit(7)
if command == "remote255":
    print("ssh: connect to host test port 22: Connection refused", file=sys.stderr)
    diagnostic.write_text(started + "debug1: Exit status 255\n")
    sys.exit(255)
diagnostic.write_text(started + "debug1: Exit status 0\n")
