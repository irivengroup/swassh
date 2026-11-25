"""Observe the unchanged approved benchmark; never grant release authority."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import traceback
import threading
from unittest.mock import patch

parser=argparse.ArgumentParser(allow_abbrev=False)
parser.add_argument('--single',action='store_true')
parser.add_argument('--root',type=Path,required=True)
parser.add_argument('--review',type=Path,required=True)
parser.add_argument('--output',type=Path,required=True)
args=parser.parse_args()
root=args.root.resolve(strict=True)
output=args.output.resolve()
output.mkdir(exist_ok=False)
review_data=args.review.read_bytes()
assert hashlib.sha256(review_data).hexdigest()=='02927b0c27010c5c8f884735d6d7b528d24d84d5bfaa2280046ff6b6714c7d41'
review=json.loads(review_data)
gate_path=root/'scripts/sast_gate.py'
assert hashlib.sha256(gate_path.read_bytes()).hexdigest()=='e5b75446872bd89952d63b280e8e097341f22e538ae1a14f93a22a98d0b54803'
gate=runpy.run_path(str(gate_path))
before=gate['SourceSnapshot'].capture(root)
assert before==review['source_files'] and all(r['approved'] for r in review['records'])
benchmark=root/'benchmarks/core.py'
assert hashlib.sha256(benchmark.read_bytes()).hexdigest()==before['benchmarks/core.py']
sys.path[:0]=[str(root/'src')]
os.environ['PYTHONPATH']=str(root/'src')
os.environ['PYTHONDONTWRITEBYTECODE']='1'
operator=runpy.run_path(str(benchmark))
original=subprocess.Popen
peers=[]
launches=[]
current_sample=0

# An explicit trace side channel retains exceptions before the relay translates
# them. Its private file is separate from stdin/stdout/stderr, so every original
# byte/status assertion and every original deadline remains effective. This
# observation adds overhead and is not a performance measurement.
entry=r'''import json,os,runpy,sys
path=sys.argv[1]
sys.argv=['swassh.infrastructure.tcp_proxy',*sys.argv[2:]]
fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
count=0
def observe(frame,event,arg):
    global count
    relevant=frame.f_code.co_filename.replace(chr(92),'/').endswith(('/tcp_proxy.py','/bandwidth.py','/bastion.py','/filesystem.py'))
    if not relevant:
        return None
    frame.f_trace_lines=False
    if event=='exception' and count<128:
        count+=1
        error=arg[1]
        record={'module':frame.f_code.co_filename.rsplit('/',1)[-1],'function':frame.f_code.co_name,'line':frame.f_lineno,'type':type(error).__name__,'errno':getattr(error,'errno',None),'message':str(error)[:512]}
        if frame.f_code.co_name=='open':
            directory=frame.f_locals.get('self')
            descriptor=getattr(directory,'fd',None)
            record.update(descriptor=descriptor,name=frame.f_locals.get('name'),flags=frame.f_locals.get('flags'),path=str(getattr(directory,'path','')))
            for label,inspect in (('descriptor_stat',lambda:os.fstat(descriptor)),('path_stat',lambda:os.stat(directory.path,follow_symlinks=False))):
                try:
                    info=inspect()
                    record[label]={'device':info.st_dev,'inode':info.st_ino,'mode':info.st_mode,'links':info.st_nlink}
                except (OSError,TypeError) as observed_error:
                    record[label]={'error':type(observed_error).__name__,'errno':getattr(observed_error,'errno',None)}
        os.write(fd,json.dumps(record,ensure_ascii=True).encode('ascii')+bytes([10]))
    return observe
sys.settrace(observe)
runpy.run_module('swassh.infrastructure.tcp_proxy',run_name='__main__')
'''

class ObservedPeer(original):
    """Retain exactly what the original benchmark receives; never suppress it."""
    def communicate(self,*args,**kwargs):
        try:
            value=super().communicate(*args,**kwargs)
        except BaseException as error:
            peers.append({'sample':self.sample,'pid':self.pid,'communication_error':type(error).__name__})
            raise
        peers.append({'sample':self.sample,'pid':self.pid,'returncode':self.returncode,
                      'stdout_bytes':len(value[0] or b''),'stderr':(value[1] or b'')[:8192].decode('utf-8',errors='backslashreplace'),
                      'exception_side_channel':self.exception_path.name})
        return value

def launch(argv,*args,**kwargs):
    if isinstance(argv,list) and argv[1:3]==['-m','swassh.infrastructure.tcp_proxy']:
        path=output/f'exceptions-{current_sample}-{len(launches)}.jsonl'
        launches.append(path.name)
        observed=[argv[0],'-c',entry,str(path),*argv[3:]]
        peer=ObservedPeer(observed,*args,**kwargs)
        peer.sample=current_sample
        peer.exception_path=path
        return peer
    return original(argv,*args,**kwargs)

if not args.single:
    outcomes=[]
    for index in range(20):
        child_output=output/f'sample-{index}'
        log=output/f'sample-{index}.log'
        with log.open('xb') as stream:
            child=subprocess.run([sys.executable,'-B',__file__,'--single','--root',str(root),
                                  '--review',str(args.review),'--output',str(child_output)],
                                 cwd=root,stdout=stream,stderr=subprocess.STDOUT,timeout=120,check=False)
        outcomes.append({'sample':index,'returncode':child.returncode,'receipt':f'sample-{index}/receipt.json'})
        print(json.dumps(outcomes[-1]),flush=True)
        (output/'supervisor.json').write_text(json.dumps({'diagnostic_only':True,'publication_authorized':False,
             'planned_iterations':20,'outcomes':outcomes,'source_unchanged':gate['SourceSnapshot'].capture(root)==before},indent=2)+'\n',encoding='utf-8')
    raise SystemExit(0 if all(r['returncode']==0 for r in outcomes) else 1)

parent_events=[]
def parent_trace(frame,event,arg):
    if not frame.f_code.co_filename.replace(chr(92),'/').endswith('/filesystem.py'):
        return None
    frame.f_trace_lines=False
    if event=='exception' and isinstance(arg[1],OSError) and frame.f_code.co_name=='open' and len(parent_events)<128:
        directory=frame.f_locals.get('self')
        descriptor=getattr(directory,'fd',None)
        record={'type':type(arg[1]).__name__,'errno':getattr(arg[1],'errno',None),
                'name':frame.f_locals.get('name'),'flags':frame.f_locals.get('flags'),
                'descriptor':descriptor,'path':str(getattr(directory,'path',''))}
        for label,observe in (('descriptor_stat',lambda:os.fstat(descriptor)),
                              ('path_stat',lambda:os.stat(directory.path,follow_symlinks=False))):
            try:
                info=observe()
                record[label]={'device':info.st_dev,'inode':info.st_ino,'mode':info.st_mode,'links':info.st_nlink}
            except (OSError,TypeError) as error:
                record[label]={'error':type(error).__name__,'errno':getattr(error,'errno',None)}
        parent_events.append(record)
    return parent_trace
sys.settrace(parent_trace)
threading.settrace(parent_trace)
results=[]
with patch.object(subprocess,'Popen',side_effect=launch):
    for index in range(1):
        current_sample=index
        record={'sample':index,'operations':8,'workers':2,'succeeded':False}
        try:
            operator['main'](['--operations','8','--workers','2','--output',str(output/f'benchmark-{index}.json')])
            record['succeeded']=True
        except BaseException as error:
            record.update(error=type(error).__name__,message=str(error),traceback=traceback.format_exc())
            trace=error.__traceback__
            while trace is not None:
                if trace.tb_frame.f_code.co_name=='relay' and 'server' in trace.tb_frame.f_locals:
                    server=trace.tb_frame.f_locals['server']
                    record['server']={'accepted_connections':len(server.connections),'errors':server.errors}
                trace=trace.tb_next
        results.append(record)
        print(json.dumps({k:v for k,v in record.items() if k!='traceback'}),flush=True)
        assert gate['SourceSnapshot'].capture(root)==before
receipt={'diagnostic_only':True,'publication_authorized':False,'python':sys.version,'iterations':1,
         'source_unchanged':True,'source_files':before,'approved_review_sha256':hashlib.sha256(review_data).hexdigest(),
         'original_benchmark_sha256':before['benchmarks/core.py'],'parameters_unchanged':True,
         'results':results,'peers':peers,'parent_descriptor_events':parent_events,'observation_overhead_not_performance_evidence':True,
         'exception_limit_per_peer':128,'truncated_if_event_count_reaches_limit':True,
         'all_original_assertions_succeeded':all(r['succeeded'] for r in results)}
(output/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n',encoding='utf-8')
raise SystemExit(0 if receipt['all_original_assertions_succeeded'] else 1)
