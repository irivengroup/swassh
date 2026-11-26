"""Public channel construction rejects invalid options before acquiring I/O."""
import unittest
from unittest.mock import patch

from swassh import LocalForward,Options,SSHChannel,SSHTunnel


class ChannelInputTests(unittest.TestCase):
    def test_all_scopes_reject_invalid_option_objects_with_a_controlled_type_error(self):
        for options in (False,{},'options',object()):
            for construct in (lambda:SSHChannel('one','true',options),
                    lambda:SSHTunnel('one',LocalForward(12345,'remote',443),options)):
                with self.subTest(kind=type(options).__name__),self.assertRaisesRegex(TypeError,'Options'):construct()

    def test_channel_uses_validated_options_timeout_and_does_not_construct_a_native_scope(self):
        with patch('swassh.interfaces.channels.NativeSSHScope') as native:
            for options in (None,Options(command_timeout=0.3,concurrency=2)):
                channel=SSHChannel('one','true',options)
                self.assertEqual(channel.lifetime,channel.options.command_timeout)
                self.assertEqual(channel.options.concurrency,1)
                self.assertEqual(channel.command,'true')
            native.assert_not_called()


if __name__=='__main__':unittest.main()
