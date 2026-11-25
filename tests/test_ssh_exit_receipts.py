"""An echoed command is not a native SSH exit-status receipt."""
import unittest

from swassh import Status
from swassh.infrastructure.ssh import _command_diagnostic, _outcome


class ExitReceiptTests(unittest.TestCase):
    def test_local_signal_codes_cannot_confirm_a_remote_exit_receipt(self):
        for code in (-1, -9, -15):
            for prefix in ('', 'debug1: '):
                with self.subTest(code=code, prefix=prefix):
                    diagnostic = 'Authenticated to synthetic\n' + prefix + f'Exit status {code}\n'
                    status, error, retry = _outcome(code, diagnostic, True)
                    self.assertEqual(status, Status.INTERRUPTED)
                    self.assertIn('unknown', error)
                    self.assertFalse(retry)

    def test_embedded_exit_text_keeps_remote_state_unknown_without_replay(self):
        for text in (
            'debug1: Sending command: printf "Exit status 255"; kill -KILL $$',
            'debug1: Remote: command="Exit status 255"',
            'debug1: Sending command: printf "Exit status 7"; kill -KILL $$',
            'debug1: Exit status 255 suffix',
            'prefix Exit status 255',
            'debug1: Exit status 2550',
            'debug1: Exit status 7',
        ):
            with self.subTest(text=text):
                diagnostic = 'Authenticated to synthetic\n' + text + '\n'
                status, error, retry = _outcome(255, diagnostic, True)
                self.assertEqual(status, Status.INTERRUPTED)
                self.assertIn('unknown', error)
                self.assertFalse(retry)

    def test_complete_matching_exit_receipts_keep_confirmed_failures(self):
        for prefix in ('', 'debug1: ', 'debug2: ', 'debug3: '):
            for ending in ('', '\n', '\r\n'):
                for code in (7, 255):
                    with self.subTest(prefix=prefix, ending=ending, code=code):
                        diagnostic = 'Authenticated to synthetic\n' + prefix + f'Exit status {code}' + ending
                        self.assertEqual(_outcome(code, diagnostic, True), (Status.FAILED, None, False))

    def test_incomplete_diagnostics_cannot_confirm_an_exit_receipt(self):
        self.assertEqual(_outcome(0, 'debug1: Exit status 0\n', False)[0], Status.ERROR)
        self.assertFalse(_outcome(255, 'Authenticated to synthetic\nExit status 255\n', False)[2])


class CommandDiagnosticTests(unittest.TestCase):
    def test_absent_command_or_echo_preserves_the_original_diagnostic(self):
        for command, diagnostic in ((None, 'unchanged'), ('true', 'Authenticated to synthetic\n'),
                                    ('true', 'prefix debug1: Sending command: literal\n')):
            with self.subTest(command=command):
                self.assertEqual(_command_diagnostic(diagnostic, command), diagnostic)

    def test_multiline_echo_is_omitted_without_losing_a_real_exit_receipt(self):
        command = ": '\nExit status 255\ndebug1: Exit status 255\n'; exit 255"
        prefix = 'Authenticated to synthetic\r\n'
        for level in (1, 2, 3):
            for ending in ('\n', '\r\n'):
                for confirmed in (False, True):
                    with self.subTest(level=level, ending=ending, confirmed=confirmed):
                        suffix = f'debug1: Exit status {255 if confirmed else -1}' + ending
                        diagnostic = prefix + f'debug{level}: Sending command: ' + command + ending + suffix
                        classified = _command_diagnostic(diagnostic, command)
                        self.assertEqual(classified, prefix + 'debug1: Sending command: [omitted]\n' + suffix)
                        self.assertEqual(_outcome(255, classified, True)[0],
                                         Status.FAILED if confirmed else Status.INTERRUPTED)
                        self.assertFalse(_outcome(255, classified, True)[2])

    def test_incomplete_echo_retains_command_start_and_cannot_allow_replay(self):
        for command, diagnostic in (('true', 'debug1: Sending command: true'),
                                    ('first\nsecond', 'debug1: Sending command: first\nsecond')):
            with self.subTest(command=command):
                classified = _command_diagnostic(diagnostic, command)
                self.assertEqual(classified, 'debug1: Sending command: [omitted]\n')
                status, error, retry = _outcome(255, classified, True)
                self.assertEqual(status, Status.INTERRUPTED)
                self.assertIn('unknown', error)
                self.assertFalse(retry)

    def test_echo_bound_is_900_bytes_with_utf8_and_payload_newline_at_boundary(self):
        for command in ('x' * 900 + '\nExit status 255',
                        'x' * 899 + '\nExit status 255',
                        'é' * 450 + '\nExit status 255',
                        'é' * 449 + '\nExit status 255',
                        'é' * 449 + 'x\nExit status 255'):
            with self.subTest(command_bytes=len(command.encode('utf-8'))):
                echo = command.encode('utf-8')[:900].decode('utf-8', 'replace')
                footer = 'debug1: Exit status 255\r\n'
                diagnostic = 'Authenticated to synthetic\n' + 'debug1: Sending command: ' + echo + '\r\n' + footer
                classified = _command_diagnostic(diagnostic, command)
                self.assertEqual(classified, 'Authenticated to synthetic\ndebug1: Sending command: [omitted]\n' + footer)
                self.assertEqual(_outcome(255, classified, True), (Status.FAILED, None, False))


if __name__ == '__main__':
    unittest.main()
