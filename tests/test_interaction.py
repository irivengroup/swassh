"""Live interaction contracts: bounded I/O, task ownership and safe errors."""
import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from swassh import AsyncClient, Host, Options, Status
from swassh.infrastructure.interaction import Interaction
from swassh.infrastructure.ssh import _Buffer


class Writer:
    def __init__(self):
        self.data = bytearray()
        self.closed = False

    def write(self, data):
        self.data.extend(data)

    async def drain(self):
        await asyncio.sleep(0)

    def close(self):
        self.closed = True


class InteractionTests(unittest.IsolatedAsyncioTestCase):
    async def test_async_callable_object_rejects_text_without_consuming_its_byte_budget(self):
        writer=Writer();test=self;events=[]
        class Handler:
            async def __call__(self,event,channel):
                events.append(event.stream)
                with test.assertRaisesRegex(ValueError,'input must be bytes'):await channel.send('abc')
                await channel.send(b'abc');channel.close()
        interaction=Interaction(Host('one'),writer,3,Handler())
        await interaction.emit('start')
        self.assertEqual(events,['start']);self.assertEqual(writer.data,b'abc');self.assertTrue(writer.closed)
        with self.assertRaisesRegex(ValueError,'closed or outside'):await interaction.input.send(b'')

    async def test_input_is_bounded_owned_and_revoked(self):
        writer = Writer()
        async def callback(event, channel):
            with self.assertRaises(ValueError):
                await channel.send(b'x' * 16385)
            with self.assertRaises(ValueError):
                await asyncio.create_task(channel.send(b'x'))
            await channel.send(b'ab')
            with self.assertRaises(ValueError):
                await channel.send(b'cd')
            channel.close()
            with self.assertRaises(ValueError):
                await channel.send(b'x')
        interaction = Interaction(Host('host'), writer, 3, callback)
        with self.assertRaises(ValueError):
            await interaction.input.send(b'x')
        await interaction.emit('start')
        interaction.input.invalidate()
        self.assertEqual(writer.data, b'ab')
        self.assertTrue(writer.closed)

    async def test_serial_callbacks_preserve_host_and_hide_exception_details(self):
        active = 0
        async def handler(event, channel):
            nonlocal active
            active += 1
            self.assertEqual(active, 1)
            self.assertEqual(event.host, Host('host'))
            await asyncio.sleep(0)
            active -= 1
        interaction = Interaction(Host('host'), Writer(), 9, handler)
        await asyncio.gather(interaction.emit('stdout', b'a'), interaction.emit('stderr', b'b'))
        async def broken(event, channel):
            raise RuntimeError('sensitive test text')
        interaction.handler = broken
        with self.assertRaisesRegex(ValueError, '^interactive callback failed$'):
            await interaction.emit('stdout', b'c')
        self.assertIsNone(interaction.input._active)

    async def test_byte_fragments_arrive_before_eof_and_output_overflow_stops(self):
        stream = asyncio.StreamReader()
        events = []
        arrived = asyncio.Event()
        async def observe(data, **flags):
            events.append((data, flags['eof']))
            arrived.set()
        buffer = _Buffer(8, observer=observe)
        task = asyncio.create_task(buffer.consume(stream))
        try:
            stream.feed_data(b'prompt?')
            async with asyncio.timeout(2):
                await arrived.wait()
            self.assertFalse(task.done())
            stream.feed_eof()
            await task
            self.assertEqual(events, [(b'prompt?', False), (b'', True)])
            self.assertEqual(buffer.text, 'prompt?')
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        stream = asyncio.StreamReader()
        stream.feed_data(b'123456789')
        stream.feed_eof()
        buffer = _Buffer(8, observer=observe)
        with self.assertRaises(ValueError):
            await buffer.consume(stream)
        self.assertTrue(buffer.truncated)
        self.assertEqual(buffer.data, b'12345678')

    async def test_invalid_modes_rejected_before_connecting(self):
        async def handler(event, channel):
            return None
        for settings in ({'retries': 1}, {'stdin_file': 'unused'}, {'check': 'true'}):
            with self.assertRaises((ValueError, TypeError)):
                await AsyncClient('host').interact('x', lambda host: handler, **settings)
        with self.assertRaises(TypeError):
            AsyncClient('host').interact_stream('x', None)
        with self.assertRaises(ValueError):
            Interaction(Host('host'), Writer(), 9, lambda event, channel: None)

    async def test_invalid_callback_never_launches_remote_command(self):
        from swassh.infrastructure.ssh import SSHTransport
        with patch('swassh.infrastructure.ssh.LocalPreflight.transport', return_value='ssh'):
            transport = SSHTransport(Options(), interaction_factory=lambda host: None)
        with patch('swassh.infrastructure.ssh.launch_native', new_callable=AsyncMock, side_effect=OSError('unexpected launch')) as launch:
            result = await transport.execute(Host('host'), 'mutation')
        launch.assert_not_awaited()
        self.assertEqual(result.status, Status.ERROR)
