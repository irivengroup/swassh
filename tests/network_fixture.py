"""Local protocol simulator for SSH integration tests, never a device driver."""
import json
import sys
import time
from pathlib import Path


def main():
    prompt = sys.argv[1]
    state_path = Path(sys.argv[3]) if len(sys.argv) > 3 else None
    state = json.loads(state_path.read_text()) if state_path else {}
    if state_path:
        state['connections'] = state.get('connections', 0) + 1
        if state.get('booted') and state.get('unready', 0):
            state['unready'] -= 1
            state_path.write_text(json.dumps(state), encoding='utf-8')
            # An authenticated SSH connection without a CLI prompt models a
            # booting management plane, not a failed verification command.
            time.sleep(10)
            return
        state_path.write_text(json.dumps(state), encoding='utf-8')
    sys.stdout.write(prompt)
    sys.stdout.flush()
    for line in sys.stdin:
        command = line.rstrip('\r\n')
        if len(sys.argv) > 2:
            with Path(sys.argv[2]).open('a', encoding='utf-8') as stream:
                stream.write(command + '\n')
        if not sys.stdin.isatty():
            print(command)
        if state_path and command == 'activate':
            if state.get('mode') == 'reject':
                print('% Invalid input detected')
            else:
                state['booted'] = True
                state_path.write_text(json.dumps(state), encoding='utf-8')
                print('activation-accepted', flush=True)
                return
        elif state_path and command == 'verify':
            if state.get('mode') == 'verification-disconnect':
                return
            print('fixture-model')
            print('fixture-old' if state.get('mode') == 'wrong-version' else 'fixture-new')
        elif state_path and command == 'identify':
            print('fixture-model\nfixture-old')
        elif state_path and command in ('backup', 'transfer'):
            print(command + '-complete')
        elif state_path and command == 'checksum':
            print('a'*64)
        elif command == 'disconnect':
            return
        elif command == 'wait':
            time.sleep(60)
        elif command == 'fail':
            print('% Invalid input detected')
        elif command == 'flood':
            print('x'*131072)
        elif command == 'question':
            print('ready')
            sys.stdout.write('Destination?')
            sys.stdout.flush()
            continue
        else:
            print('SWASSH fixture-version')
        sys.stdout.write(prompt)
        sys.stdout.flush()


if __name__ == '__main__':
    main()
