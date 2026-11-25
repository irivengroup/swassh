"""Isolated early-exit probe; its parent bounds and reaps the entire test run."""
import asyncio
from pathlib import Path
import sys
from unittest.mock import patch

from swassh import SSHChannel, Options
from swassh.infrastructure.process_guard import launch_native


async def main(directory):
    async def peer(executable,*arguments,**kwargs):
        from swassh.infrastructure.process_guard import native_relay
        with native_relay(None,kwargs.get('max_native_seconds')):
            return await launch_native(sys.executable,str(Path(__file__).with_name('channel_peer.py')),*arguments,**kwargs)
    options=Options(command_timeout=30,max_output_bytes=1048576,budget_dir=str(Path(directory)/'budget'))
    with patch('swassh.infrastructure.channels.launch_native',side_effect=peer):
        async with SSHChannel('synthetic','large-output',options) as channel:
            await asyncio.sleep(0.2)
            process=channel.native.process
        if process.returncode is None or process._swassh_guardian is not None:
            raise AssertionError('native scope was released before cleanup')


if __name__=='__main__': asyncio.run(main(sys.argv[1]))
