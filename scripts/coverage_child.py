"""Measurement-only CPython child bootstrap; append first observations eagerly.

Journals contain unit identifiers, never arguments, values, credentials or I/O.
One small write per unit survives os._exit and native process-tree termination;
no application exit hook or signal handler is replaced.
"""
import hashlib
import json
import os
import struct
import sys
import threading
import time
import types

RECORD=struct.Struct('!I')


def constant_signature(code):
    """Match the parent's exact immutable literal identity, including lambdas."""
    def literal(value):
        if isinstance(value,types.CodeType):
            return ('code',value.co_qualname,value.co_firstlineno,value.co_code,
                    tuple(literal(item) for item in value.co_consts))
        if type(value) is float:return ('float',value.hex())
        if type(value) is complex:return ('complex',value.real.hex(),value.imag.hex())
        if type(value) is tuple:return ('tuple',tuple(literal(item) for item in value))
        if type(value) is frozenset:return ('frozenset',tuple(sorted((literal(item) for item in value),key=repr)))
        return (type(value).__name__,value)
    return repr(tuple(literal(value) for value in code.co_consts))


class ChildObserver:
    """Load only catalogs for source modules actually entered by this child."""
    def __init__(self,descriptor):
        self.profile=bool(os.environ.get('SWASSH_COVERAGE_PROFILE'))
        self.entered=time.monotonic()
        raw=open(descriptor,'rb').read(1024*1024+1)
        if len(raw)>1024*1024:
            raise ValueError('child coverage descriptor too large')
        self.descriptor=json.loads(raw)
        version = self.descriptor['schema_version']
        if version not in (2, 3) or self.descriptor['python']!=list(sys.version_info[:3]):
            raise ValueError('child coverage runtime mismatch')
        if version == 3 and self.descriptor.get('extensions') != ['async_iteration_edges_v1']:
            raise ValueError('unsupported source coverage extension')
        self.token=hashlib.sha256(raw).hexdigest()
        self.root=self.descriptor['root']
        self.directory=os.path.dirname(descriptor)
        self.cache={}
        self.filenames={}
        self.catalogs={}
        self.hits=set()
        self.active={}
        self.source_pending={}
        self.pending={}
        self.lock=threading.RLock()
        journal=os.path.join(self.directory,'process-'+str(os.getpid())+'-'+os.urandom(8).hex()+'.events')
        temporary=journal+'.initializing'
        descriptor=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_BINARY',0),0o600)
        header=json.dumps({'schema_version':1,'catalog':self.token,'pid':os.getpid()},separators=(',',':')).encode()+b'\n'
        try:
            if os.write(descriptor,header)!=len(header):
                raise OSError('child coverage header incomplete')
        finally:
            os.close(descriptor)
        # A killed bootstrap has not installed monitoring or entered application
        # code. Publish only its complete header; published corruption remains
        # fatal. Closing first also permits atomic renaming on Windows.
        os.replace(temporary,journal)
        self.fd=os.open(journal,os.O_WRONLY|os.O_APPEND|getattr(os,'O_BINARY',0)|getattr(os,'O_NOFOLLOW',0))

    def timing(self,event,**values):
        if self.profile:
            path=os.path.join(self.directory,'process-'+str(os.getpid())+'.profile')
            fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_APPEND|getattr(os,'O_BINARY',0),0o600)
            try:
                raw=json.dumps({'event':event,'clock':time.monotonic(),**values}).encode()+b'\n'
                if os.write(fd,raw)!=len(raw):
                    raise OSError('child profiling metadata incomplete')
            finally:
                os.close(fd)

    @staticmethod
    def identity(code):
        # Compare the exact interpreter-owned position table bytes. The same
        # CPython runtime is required by the descriptor; no layout is decoded or
        # approximated, and columns/duplicated source sites remain distinct.
        return (code.co_qualname,code.co_firstlineno,code.co_linetable,code.co_code,constant_signature(code))

    def info(self,code):
        identity=id(code)
        if identity in self.cache:
            return self.cache[identity][1]
        filename=code.co_filename
        if filename not in self.filenames:
            name=os.path.normcase(os.path.abspath(filename))
            if name not in self.descriptor['modules'] and not filename.startswith('<'):
                name=os.path.normcase(os.path.realpath(filename))
            self.filenames[filename]=name
        name=self.filenames[filename]
        module=self.descriptor['modules'].get(name)
        info=None
        if module:
            if name not in self.catalogs:
                started=time.monotonic()
                with open(name,'rb') as stream:
                    digest=hashlib.file_digest(stream,'sha256').hexdigest()
                if digest!=module['source_sha256']:
                    raise ValueError('child coverage source changed')
                with open(os.path.join(self.directory,module['file']),'rb') as stream:
                    raw=stream.read(8*1024**2+1)
                if len(raw)>8*1024**2 or hashlib.sha256(raw).hexdigest()!=module['sha256']:
                    raise ValueError('child coverage module catalog mismatch')
                records=json.loads(raw)
                catalog={}
                lines={int(k):v for k,v in records['lines'].items()}
                for row in records['codes']:
                    key=(row['name'],row['line'],bytes.fromhex(row['linetable']),bytes.fromhex(row['bytecode']),row['constants'])
                    row['lines']=lines
                    row['statements']={int(k):v for k,v in row['statements'].items()}
                    row['jumps']={int(k):v for k,v in row['jumps'].items()}
                    if 'source_events' in row:
                        if self.descriptor['schema_version'] != 3:
                            raise ValueError('source events require a bound source coverage extension')
                        data = row['source_events']
                        row['source_events'] = {'ready': {int(k): v for k, v in data['ready'].items()},
                                                'end': {int(k): v for k, v in data['end'].items()},
                                                'after': {v[0] for v in data['end'].values()}}
                    catalog[key]=row
                self.catalogs[name]=catalog
                self.timing('catalog',module=os.path.basename(name),seconds=time.monotonic()-started,bytes=len(raw))
            info=self.catalogs[name].get(self.identity(code))
            if info is None:
                raise ValueError('child coverage code differs from source catalog')
        # Keep the object alive so a recycled id cannot acquire another frame's map.
        self.cache[identity]=(code,info)
        return info

    def hit(self,unit):
        self.hit_many((unit,))

    def hit_many(self,units):
        """One eager write per event, still recording every distinct unit ID."""
        with self.lock:
            unseen=set(units)-self.hits-{None}
            for unit in unseen:
                if type(unit) is not int or not 0<=unit<self.descriptor['units']:
                    raise ValueError('child coverage unit outside inventory')
            if unseen:
                raw=b''.join(RECORD.pack(unit) for unit in unseen)
                if os.write(self.fd,raw)!=len(raw):
                    raise OSError('child coverage observation incomplete')
                self.hits.update(unseen)

    def started(self,code,offset):
        info=self.info(code)
        if info is None:
            return self.monitor.DISABLE
        self.hit(info['function'])
        self.hit(info['legacy_function'])
        self.hit_many(info['entry'])
        if id(code) not in self.active:
            self.active[id(code)]=code
            self.monitor.set_local_events(self.tool,code,self.local_events)
        return self.monitor.DISABLE

    def instruction(self,code,offset,frame=None):
        info=self.info(code)
        self.hit_many(info['statements'].get(offset,()))
        source = info.get('source_events')
        if source is not None:
            frame = frame if frame is not None else sys._getframe(1)
            if frame.f_code is not code:
                raise ValueError('child source monitoring frame ownership mismatch')
            identity = id(frame)
            pending = self.source_pending.get(identity)
            if pending is not None and (offset == pending[1] if self.monitor is None else offset >= pending[1]):
                self.hit(pending[2])
                self.source_pending.pop(identity)
            if offset in source['ready']:
                self.hit(source['ready'][offset])
                return None
            if offset in source['end']:
                following, unit = source['end'][offset]
                self.source_pending[identity] = (frame, following, unit)
                return None
            return None
        return self.monitor.DISABLE if self.monitor is not None else None

    def source_clear(self, code, *unused):
        frame = sys._getframe(1)
        if frame.f_code is code:
            self.source_pending.pop(id(frame), None)

    def line(self,code,line):
        info=self.info(code)
        self.hit(info['lines'].get(line))
        # Keep source LINE sites active so CPython also delivers the actual
        # INSTRUCTION callback for control-transfer opcodes. No inferred hits.
        return None

    def branch(self,code,offset,destination):
        entry=self.info(code)['jumps'].get(offset)
        if entry is not None:
            target,no,yes,condition_no,condition_yes,truth_on_jump,iteration=entry
            taken=destination>=target if iteration else destination==target
            self.hit_many((yes if taken else no,condition_yes if taken==truth_on_jump else condition_no))
            if self.monitor is not None and (hasattr(self.monitor.events,'BRANCH_LEFT') or no in self.hits and yes in self.hits):
                return self.monitor.DISABLE
        # 3.12's single BRANCH event must retain both outcomes at this site.

    def trace(self,frame,event,arg):
        """Journal real opcode edges on CPython without sys.monitoring."""
        info=self.info(frame.f_code)
        if info is None:
            return None
        identity=id(frame)
        if event=='call':
            frame.f_trace=self.trace
            frame.f_trace_opcodes=True
            self.hit_many((info['function'],info['legacy_function']))
        elif event=='line':
            self.line(frame.f_code,frame.f_lineno)
        elif event=='opcode':
            previous=self.pending.pop(identity,None)
            if previous is not None and info['jumps'].get(previous) != info['jumps'].get(frame.f_lasti):
                self.branch(frame.f_code,previous,frame.f_lasti)
            self.instruction(frame.f_code,frame.f_lasti,frame)
            if frame.f_lasti in info['jumps']:
                self.pending[identity]=frame.f_lasti
        elif event in ('exception','return'):
            self.pending.pop(identity,None)
            self.source_pending.pop(identity,None)
        return self.trace

    def start(self):
        self.monitor=getattr(sys,'monitoring',None)
        if self.monitor is None:
            if sys.gettrace() is not None or threading.gettrace() is not None:
                raise RuntimeError('child opcode measurement requires an unoccupied trace hook')
            threading.settrace(self.trace)
            sys.settrace(self.trace)
            self.timing('ready',seconds=time.monotonic()-self.entered)
            return
        self.tool=next((item for item in (1,3,4,0,2,5) if self.monitor.get_tool(item) is None),None)
        if self.tool is None:
            raise RuntimeError('no free child monitoring tool')
        self.monitor.use_tool_id(self.tool,'swassh-child-unit-journal')
        events=self.monitor.events
        callbacks={events.PY_START:self.started,events.LINE:self.line,events.INSTRUCTION:self.instruction}
        if hasattr(events,'BRANCH_LEFT'):
            callbacks.update({events.BRANCH_LEFT:self.branch,events.BRANCH_RIGHT:self.branch})
        else:
            callbacks[events.BRANCH]=self.branch
        self.local_events=sum(event for event in callbacks if event!=events.PY_START)
        global_events = events.PY_START
        if self.descriptor['schema_version'] == 3:
            callbacks.update({getattr(events, name): self.source_clear
                              for name in ('RAISE', 'RERAISE', 'PY_UNWIND')})
            global_events |= sum(getattr(events, name) for name in ('RAISE', 'RERAISE', 'PY_UNWIND'))
        for event,callback in callbacks.items():
            self.monitor.register_callback(self.tool,event,callback)
        self.monitor.set_events(self.tool,global_events)
        self.timing('ready',seconds=time.monotonic()-self.entered)


def bootstrap(descriptor):
    """Keep the observer alive until the OS closes its process-owned descriptor."""
    observer=ChildObserver(descriptor)
    observer.start()
    return observer
