"""Bounded local measurements of the actual new cores; no external SSH target.

Convergence and workflows use real private SQLite/OS locks and fake remote
execution boundaries. Channels use real guarded native synthetic peers. Relay
tests use real loopback TCP and child interpreters. None measures SSH crypto,
hardware fleet capacity, child RSS, or a performance improvement over rc4.
"""
from __future__ import annotations

import argparse
import asyncio
from datetime import UTC, datetime
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import tracemalloc
import uuid
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
os.environ['PYTHONPATH']=str(ROOT/'src')+os.pathsep+os.environ.get('PYTHONPATH','')

from swassh import DesiredState, Host, Options, Result, Status, SSHChannel, Workflow, WorkflowStep, __version__
from swassh.application.convergence import ConvergentTransport
from swassh.application.contracts import RunSummary
from swassh.application.schedule_contracts import ScheduledInvocation
from swassh.application.workflow_contracts import PreparedWorkflow
from swassh.application.workflows import WorkflowService
from swassh.infrastructure.audit import AuditTrail
from swassh.infrastructure.bastion import specification
from swassh.infrastructure.convergence import SQLiteConvergenceJournal
from swassh.infrastructure.process_guard import launch_native
from swassh.infrastructure.resources import resource_plan
from swassh.infrastructure.workflow_store import SQLiteWorkflowStore


class Measurements:
    def __init__(self,name,unit):
        self.name,self.unit=name,unit
        self.samples=[]
        self.started=time.monotonic()

    def finish(self,**fields):
        elapsed=time.monotonic()-self.started
        ordered=sorted(self.samples)
        if not ordered: raise ValueError('empty benchmark sample')
        return {'component':self.name,'unit':self.unit,'completed':len(ordered),'errors':0,
            'elapsed_seconds':elapsed,'units_per_second':len(ordered)/elapsed,
            'latency_seconds':{'median':statistics.median(ordered),
                'p99_nearest_rank':ordered[math.ceil(0.99*len(ordered))-1],
                'minimum':ordered[0],'maximum':ordered[-1]},**fields}


class RemoteState:
    """The simulated boundary only; the measured convergence logic is real."""
    def __init__(self): self.states=set(); self.mutations=0

    async def execute(self,host,command):
        await asyncio.sleep(0)
        if command=='apply':
            self.states.add(host); self.mutations+=1
        code=0 if host in self.states else 1
        return Result(host,Status.SUCCESS if code==0 else Status.FAILED,exit_code=code)


class LoopbackEcho:
    """Exactly workers connections, finite waits and no public listener."""
    def __init__(self,workers):
        self.workers=workers; self.connections=[]; self.threads=[]; self.errors=[]
        self.ready=threading.Event(); self.stopped=threading.Event()
        self.socket=socket.socket()
        self.socket.bind(('127.0.0.1',0)); self.socket.listen(workers); self.socket.settimeout(8)
        self.port=self.socket.getsockname()[1]
        self.owner=threading.Thread(target=self._accept,daemon=True); self.owner.start()

    def _accept(self):
        try:
            for _ in range(self.workers):
                connection,_=self.socket.accept(); connection.settimeout(8)
                self.connections.append(connection)
                task=threading.Thread(target=self._echo,args=(connection,),daemon=True)
                self.threads.append(task); task.start()
            self.ready.set()
        except OSError as error:
            if not self.stopped.is_set(): self.errors.append(type(error).__name__)

    def _echo(self,connection):
        try:
            while data:=connection.recv(16384): connection.sendall(data)
        except OSError as error:
            if not self.stopped.is_set(): self.errors.append(type(error).__name__)
        finally: connection.close()

    def close(self):
        self.stopped.set(); self.socket.close()
        for connection in self.connections:
            try: connection.shutdown(socket.SHUT_RDWR)
            except OSError: pass
            connection.close()
        self.owner.join(timeout=9)
        for task in self.threads: task.join(timeout=9)


class CoreBenchmarks:
    def __init__(self,root,operations,workers):
        self.root=Path(root)
        self.operations,self.workers=operations,workers
        self.options=Options(budget_dir=str(self.root/'budget'),command_timeout=10,
                             connect_timeout=3,report_timeout=3)

    async def convergence(self):
        measured=Measurements('ConvergentTransport + SQLiteConvergenceJournal','check/apply/verify followed by no-change check')
        remote=RemoteState()
        journal=SQLiteConvergenceJournal(self.options,directory=self.root/'intents')
        action=DesiredState('benchmark-state','check','apply')
        adapter=ConvergentTransport(remote,action,journal)
        async def worker(number):
            for index in range(number,self.operations,self.workers):
                host=Host('synthetic-'+str(index))
                start=time.monotonic()
                first=await adapter.execute(host,action.descriptor)
                second=await adapter.execute(host,action.descriptor)
                if not first.ok or not first.changed or not second.ok or second.changed:
                    raise AssertionError('convergence contract failed')
                measured.samples.append(time.monotonic()-start)
        try:
            await asyncio.gather(*(worker(number) for number in range(self.workers)))
            if remote.mutations!=self.operations: raise AssertionError('mutation repeated or omitted')
        finally: await adapter.aclose()
        return measured.finish(workers=self.workers,remote_boundary='in-memory synthetic state',
            storage='real private SQLite and OS locks',mutations=remote.mutations)

    async def workflows(self):
        measured=Measurements('WorkflowService + SQLiteWorkflowStore + audit outbox','two-step workflow completed')
        store=SQLiteWorkflowStore(self.root/'workflows')
        registered={}; active=peak=0
        completed_ids=asyncio.Queue(maxsize=self.operations)
        async def execute(id,step,invocation):
            nonlocal active,peak
            active+=1; peak=max(peak,active)
            try:
                await asyncio.sleep(0)
                counts={status.value:0 for status in Status}; counts['success']=1
                now=datetime.now(UTC)
                if step.id=='second': completed_ids.put_nowait(id)
                return RunSummary(1,counts,now,now,resource_plan(invocation.options),uuid.uuid4().hex)
            finally: active-=1
        async def registrar(number):
            for index in range(number,self.operations,self.workers):
                id=uuid.UUID(int=index+1).hex
                workflow=Workflow('benchmark',(
                    WorkflowStep('first',('synthetic',),command='true'),
                    WorkflowStep('second',('synthetic',),command='true',needs=('first',))))
                prepared=PreparedWorkflow(workflow,tuple(ScheduledInvocation(step.descriptor,step.hosts,self.options,
                    str(self.root/'reports'/id/step.id/'report.json')) for step in workflow.ordered_steps))
                registered[id]=time.monotonic()
                await asyncio.to_thread(store.create,id,prepared,datetime.now(UTC))
        try:
            await asyncio.gather(*(registrar(number) for number in range(self.workers)))
            service=WorkflowService(store,execute,audit_factory=AuditTrail,
                audit_path=str(store.directory/'audit.jsonl'))
            for _ in range(self.operations):
                if await service.serve(once=True)!=1: raise AssertionError('workflow omitted')
                id=completed_ids.get_nowait()
                if store.get(id).state.value!='succeeded': raise AssertionError('workflow completion mismatch')
                measured.samples.append(time.monotonic()-registered.pop(id))
            if peak!=1 or store.events(): raise AssertionError('worker overlap or audit not acknowledged')
        finally: store.close()
        return measured.finish(registration_workers=self.workers,peak_fleet_executions=peak,
            remote_boundary='in-memory successful fleet summaries',storage='real SQLite and synchronized audit',
            latency_boundary='registration through queue and execution; includes queue waiting')

    async def channels(self):
        measured=Measurements('SSHChannel + native guardian','binary command scope completed')
        async def synthetic(executable,*arguments,**kwargs):
            # This peer is a Python binary-protocol fixture, not OpenSSH.
            # Keep the real guardian, admission and lifetime; only SSH relay
            # metadata belongs to the replaced transport boundary.
            from swassh.infrastructure.process_guard import native_relay
            with native_relay(None,kwargs.get('max_native_seconds')):
                return await launch_native(sys.executable,str(ROOT/'tests/channel_peer.py'),*arguments,**kwargs)
        async def worker(number):
            for index in range(number,self.operations,self.workers):
                start=time.monotonic()
                async with SSHChannel('synthetic','echo',self.options) as channel:
                    payload=bytes(range(256))*16
                    await channel.send(payload); channel.close_input()
                    capture=await channel.wait()
                    if not capture.ok or capture.stdout!=payload or capture.stderr!=b'synthetic-stderr':
                        raise AssertionError('binary channel contract failed')
                measured.samples.append(time.monotonic()-start)
        with patch('swassh.infrastructure.channels.launch_native',side_effect=synthetic):
            await asyncio.gather(*(worker(number) for number in range(self.workers)))
        return measured.finish(requested_scope_workers=self.workers,native_boundary='real guardian and synthetic subprocess peer',
            payload_bytes_per_scope=4096,ssh_crypto_measured=False)

    def relay(self):
        measured=Measurements('TCPRelay + SQLiteByteBudget','loopback binary roundtrip')
        options=Options(budget_dir=str(self.root/'relay-budget'),bastion_bandwidth_kib=64)
        spec=specification(options)
        server=LoopbackEcho(self.workers); peers=[]
        payload=bytes(range(256))*64
        try:
            for _ in range(self.workers):
                args=[sys.executable,'-m','swassh.infrastructure.tcp_proxy','--host','127.0.0.1',
                    '--port',str(server.port),'--budget-root',spec['directory'],
                    '--connections',str(spec['policy'][0]),'--connect-rate',str(spec['policy'][1]),
                    '--memory-bytes',str(spec['policy'][2]),'--bandwidth-kib',str(spec['policy'][3]),
                    '--connect-timeout','3','--lifetime','15']
                peers.append(subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE))
            if not server.ready.wait(8): raise AssertionError('relay connection barrier not reached')
            byte_start=time.monotonic()
            def exchange(peer):
                start=time.monotonic()
                stdout,stderr=peer.communicate(payload,timeout=12)
                if peer.returncode!=0 or stdout!=payload or stderr: raise AssertionError('relay bytes or status mismatch')
                return time.monotonic()-start
            from concurrent.futures import ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=self.workers) as workers:
                tasks=[workers.submit(exchange,peer) for peer in peers]
                measured.samples.extend(task.result(timeout=14) for task in tasks)
            byte_elapsed=time.monotonic()-byte_start
            if server.errors: raise AssertionError('loopback peer failed')
            total=self.workers*len(payload)*2
            if total>16384+byte_elapsed*64*1024+1024:
                raise AssertionError('aggregate payload allowance exceeded')
            return measured.finish(workers=self.workers,combined_bytes=total,byte_flow_seconds=byte_elapsed,
                combined_bytes_per_second=total/byte_elapsed,configured_bytes_per_second=64*1024,
                initial_shared_burst_bytes=16384,network='real loopback TCP; not SSH encryption or NIC capacity')
        finally:
            server.close()
            for peer in peers:
                if peer.poll() is None: peer.kill()
                peer.communicate(timeout=5)

    async def run(self):
        results=[]
        async with asyncio.timeout(90):
            for operation in (self.convergence,self.workflows,self.channels):
                results.append(await operation())
            results.append(await asyncio.to_thread(self.relay))
        return results


def main(argv=None):
    parser=argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument('--operations',type=int,default=16)
    parser.add_argument('--workers',type=int,default=2)
    parser.add_argument('--output',type=Path)
    args=parser.parse_args(argv)
    if not 1<=args.operations<=128 or not 1<=args.workers<=4 or args.workers>args.operations:
        parser.error('operations must be 1..128 and workers 1..min(4,operations)')
    started=time.monotonic()
    tracemalloc.start()
    try:
        with tempfile.TemporaryDirectory(prefix='swassh-core-bench-') as directory:
            results=asyncio.run(CoreBenchmarks(directory,args.operations,args.workers).run())
        _,peak=tracemalloc.get_traced_memory()
    finally: tracemalloc.stop()
    report={'schema_version':1,'version':__version__,'python':sys.version,'os':platform.system(),
        'benchmark_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'machine':platform.machine(),'cpu_count':os.cpu_count(),'operations':args.operations,'workers':args.workers,
        'arrival_model':'closed bounded workers; no warmup; queue waiting included as labeled',
        'seconds':time.monotonic()-started,'peak_parent_python_bytes':peak,'results':results,
        'source_sha256':{path.relative_to(ROOT).as_posix():hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted((ROOT/'src/swassh').rglob('*.py'))},
        'limits':['no SSH encryption or authenticated server','no remote hardware or external load',
                  'no child-process RSS measurement','small-sample P99, not a capacity SLO','no before/after performance claim']}
    text=json.dumps(report,ensure_ascii=True,indent=2)+'\n'
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding='utf-8')
    else:
        sys.stdout.write(text)


if __name__=='__main__': main()
