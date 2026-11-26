"""Bounded local SQLite-spool experiment, never a replacement for fleet gates."""
import argparse
import cProfile
import csv
import hashlib
import io
import json
import math
import os
from pathlib import Path
import platform
import pstats
import runpy
import sqlite3
import sys
import tempfile
import time
import tracemalloc

here=Path(__file__).resolve().parent
work=here.parents[1]
source=Path(os.environ['SWASSH_DIAG_SOURCE']).resolve(strict=True)
review_bytes=Path(os.environ['SWASSH_DIAG_REVIEW']).read_bytes()
assert hashlib.sha256(review_bytes).hexdigest()=='62e93faf3de43884f6fa8b0c2e0fe7dc7a3ad78d9958130a42967f74649e60f6'
review=json.loads(review_bytes)
assert len(review['records'])==181 and all(row['approved'] for row in review['records'])
gate=source/'scripts/sast_gate.py'
assert hashlib.sha256(gate.read_bytes()).hexdigest()=='e5b75446872bd89952d63b280e8e097341f22e538ae1a14f93a22a98d0b54803'
capture=runpy.run_path(str(gate))['SourceSnapshot'].capture
assert capture(source)==review['source_files']
inputs={'sha256':'2b4ebbd8672d07c278b4acf4b813e0543e56a2ce27e701baebe645cac9746014','source_files':review['source_files']}
assert all(hashlib.sha256((source/n).read_bytes()).hexdigest()==s for n,s in inputs['source_files'].items())
runpy.run_path(str(source/'scripts/ci_shell.py'))['WindowsObjectOwner'].configure()
sys.path.insert(0,str(source/'src'))
from swassh import Host,Result,Status
from swassh.infrastructure.spool import ReportStore

def quantile(values,p):
    return sorted(values)[max(0,math.ceil(len(values)*p)-1)]

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--operations',type=int,default=5000)
    parser.add_argument('--batch',type=int,default=14)
    parser.add_argument('--repeats',type=int,default=3)
    args=parser.parse_args()
    assert 1<=args.operations<=5000 and 1<=args.batch<=32 and 1<=args.repeats<=4
    output=Path(os.environ['SWASSH_DIAG_OUTPUT']).resolve();output.mkdir()
    records=[]
    for repeat in range(args.repeats):
        for mode in (('NORMAL','EXCLUSIVE') if repeat%2==0 else ('EXCLUSIVE','NORMAL')):
            with tempfile.TemporaryDirectory(prefix='swassh-spool-profile-') as directory:
                store=ReportStore(directory,64*1024*1024)
                try:
                    assert store.db.execute('PRAGMA journal_mode=DELETE').fetchone()[0].lower()=='delete'
                    actual=store.db.execute('PRAGMA locking_mode='+mode).fetchone()[0]
                    assert actual.lower()==mode.lower()
                    assert store.db.execute('PRAGMA synchronous').fetchone()[0]==2
                    measurements=[];sql=[]
                    store.db.set_trace_callback(sql.append)
                    profile=cProfile.Profile()
                    cpu=time.process_time();started=time.perf_counter()
                    tracemalloc.start();profile.enable()
                    for offset in range(0,args.operations,args.batch):
                        batch=[Result(Host('host-'+str(i)),Status.SUCCESS,stdout='host-'+str(i),exit_code=0,phase='fleet')
                               for i in range(offset,min(args.operations,offset+args.batch))]
                        before=time.perf_counter();store.append(batch);measurements.append(time.perf_counter()-before)
                    profile.disable();elapsed=time.perf_counter()-started;cpu=time.process_time()-cpu
                    current,peak=tracemalloc.get_traced_memory();tracemalloc.stop()
                    store.db.set_trace_callback(None)
                    assert store.counts['success']==args.operations
                    assert {r.host.hostname for r in store._results()}=={'host-'+str(i) for i in range(args.operations)}
                    assert store.db.execute('SELECT COUNT(*) FROM results').fetchone()[0]==args.operations
                    assert store.db.execute('PRAGMA integrity_check').fetchone()[0]=='ok'
                    assert sum(line=='COMMIT' for line in sql)==math.ceil(args.operations/args.batch)
                    stream=io.StringIO();store._csv(stream);stream.seek(0)
                    assert len(list(csv.DictReader(stream)))==args.operations
                    assert sum(not line.strip() for line in stream.getvalue().splitlines())==args.operations
                    journal=Path(str(store.path)+'-journal')
                    row={'repeat':repeat,'mode':mode,'operations':args.operations,'batch_limit':args.batch,
                        'transactions':len(measurements),'seconds':elapsed,'cpu_seconds':cpu,'operations_per_second':args.operations/elapsed,
                        'append_p50_seconds':quantile(measurements,.5),'append_p95_seconds':quantile(measurements,.95),
                        'append_p99_seconds':quantile(measurements,.99),'append_seconds':measurements,'parent_tracemalloc_peak_bytes':peak,
                        'sqlite_synchronous':2,'journal_bytes_after_commit':journal.stat().st_size if journal.exists() else 0,
                        'spool_rows_and_unique_hosts_and_csv_records_verified':True,'errors':0}
                    records.append(row)
                    with (output/(str(repeat)+'-'+mode+'.txt')).open('x',encoding='utf-8') as report:
                        pstats.Stats(profile,stream=report).strip_dirs().sort_stats('cumulative').print_stats(30)
                    print(json.dumps({k:v for k,v in row.items() if k!='append_seconds'}),flush=True)
                finally:
                    store.close()
    unchanged=all(hashlib.sha256((source/n).read_bytes()).hexdigest()==s for n,s in inputs['source_files'].items())
    assert unchanged and capture(source)==review['source_files']
    receipt={'source_archive_sha256':inputs['sha256'],'source_unchanged':True,'python':sys.version,'platform':platform.platform(),
        'sqlite':sqlite3.sqlite_version,'cpu_count':os.cpu_count(),'parameters':vars(args),'profile_overhead_included_in_both_modes':True,
        'scope':'ReportStore.append transactions only; no claim about total SSH or end-to-end fleet latency',
        'production_sources_modified':False,'full_fleet_test_not_modified_or_replaced':True,'records':records,'publication_authorized':False}
    (output/'receipt.json').open('x',encoding='utf-8').write(json.dumps(receipt,indent=2)+'\n')

if __name__=='__main__':main()
