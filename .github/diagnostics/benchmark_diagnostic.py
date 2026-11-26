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
from unittest.mock import patch

parser=argparse.ArgumentParser(allow_abbrev=False)
parser.add_argument('--root',type=Path,required=True)
parser.add_argument('--review',type=Path,required=True)
parser.add_argument('--output',type=Path,required=True)
args=parser.parse_args()
root=args.root.resolve(strict=True)
output=args.output.resolve()
output.mkdir(exist_ok=False)
review_data=args.review.read_bytes()
assert hashlib.sha256(review_data).hexdigest()=='62e93faf3de43884f6fa8b0c2e0fe7dc7a3ad78d9958130a42967f74649e60f6'
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
        os.write(fd,json.dumps(record,ensure_ascii=True).encode('ascii')+bytes([10]))
    return observe
import faulthandler
stack=os.open(path+'.stack.log',os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
faulthandler.dump_traceback_later(6,file=stack)
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

fresh=[]
for index in range(20):
    log=output/f'fresh-{index}.log'
    with log.open('xb') as stream:
        result=subprocess.run([sys.executable,'-B',str(benchmark),'--operations','8','--workers','2',
                               '--output',str(output/f'fresh-benchmark-{index}.json')],
                              cwd=root,stdout=stream,stderr=subprocess.STDOUT,timeout=110,check=False)
    fresh.append({'sample':index,'returncode':result.returncode,'log':log.name})
    print(json.dumps({'fresh_original_process':index,'returncode':result.returncode}),flush=True)
    assert gate['SourceSnapshot'].capture(root)==before
results=[]
with patch.object(subprocess,'Popen',side_effect=launch):
    for index in range(10):
        current_sample=index
        record={'sample':index,'operations':8,'workers':2,'succeeded':False}
        try:
            operator['main'](['--operations','8','--workers','2','--output',str(output/f'benchmark-{index}.json')])
            record['succeeded']=True
        except BaseException as error:
            record.update(error=type(error).__name__,message=str(error),traceback=traceback.format_exc())
        results.append(record)
        print(json.dumps({k:v for k,v in record.items() if k!='traceback'}),flush=True)
        assert gate['SourceSnapshot'].capture(root)==before
receipt={'diagnostic_only':True,'publication_authorized':False,'python':sys.version,'iterations':10,
         'source_unchanged':True,'source_files':before,'approved_review_sha256':hashlib.sha256(review_data).hexdigest(),
         'original_benchmark_sha256':before['benchmarks/core.py'],'parameters_unchanged':True,
         'fresh_original_process_runs':fresh,'results':results,'peers':peers,'observation_overhead_not_performance_evidence':True,
         'exception_limit_per_peer':128,'truncated_if_event_count_reaches_limit':True,
         'all_original_assertions_succeeded':all(r['succeeded'] for r in results) and all(r['returncode']==0 for r in fresh)}
(output/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n',encoding='utf-8')
raise SystemExit(0 if receipt['all_original_assertions_succeeded'] else 1)
