"""Prepare exact source catalogs and strictly merge child observation journals."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import sys
import tempfile

PAIRS={'statements':('statement_total','statement_hits'),
       'lines':('line_total','line_hits'),'functions':('function_total','function_hits'),
       'branches':('branch_total','branch_hits'),'boolean_conditions':('condition_total','condition_hits'),
       'legacy_code_entries':('legacy_function_total','legacy_function_hits'),
       'legacy_ast_statements':('legacy_statement_total','statement_hits')}
RECORD=struct.Struct('!I')


class ChildCampaign:
    """Bind every child unit to this campaign's exact source and runtime."""
    def __init__(self,observer,directory):
        self.observer=observer
        self.directory=Path(tempfile.mkdtemp(prefix='child-coverage-',dir=directory)).resolve()
        self.directory.chmod(0o700)
        self.units=[]
        self.index={}
        pairs = dict(PAIRS)
        if hasattr(observer, 'source_catalogs'):
            pairs['source_events'] = ('source_event_total', 'source_event_hits')
        for name,row in observer.rows.items():
            for metric,(total,hits) in pairs.items():
                for unit in row[total]:
                    self.index[(name,metric,unit)]=len(self.units)
                    self.units.append((row[hits],unit))
        modules={}
        for number,(name,row) in enumerate(observer.rows.items()):
            def unit(metric,key):
                return self.index[(name,metric,key)]
            def statement_units(value):
                result=[unit('legacy_ast_statements',value)]
                if value in row['statement_total']:result.append(unit('statements',value))
                return result
            codes=[]
            for (filename,key),(_,_,jumps) in observer.catalog.items():
                if filename!=name:
                    continue
                qualname,line,positions,bytecode,constants=key.value
                mapping={}
                for offset,(target,branch,condition,truth,iteration) in jumps.items():
                    mapping[offset]=[target,unit('branches',(branch,False)),unit('branches',(branch,True)),
                        unit('boolean_conditions',(condition,False)) if condition is not None else None,
                        unit('boolean_conditions',(condition,True)) if condition is not None else None,truth,iteration]
                code_record = {'name':qualname,'line':line,'linetable':key.linetable.hex(),'bytecode':bytecode.hex(),'constants':constants,
                    'entry':[identity for value in
                             observer.statement_maps[(name,key)].get(min(observer.statement_maps[(name,key)]),())
                             for identity in statement_units(value)]
                            if observer.statement_maps[(name,key)] else [],
                    'function':unit('functions',key) if key in row['function_total'] else None,
                    'legacy_function':unit('legacy_code_entries',key) if key in row['legacy_function_total'] else None,
                    'statements':{offset:[identity for value in values for identity in statement_units(value)]
                        for offset,values in observer.statement_maps[(name,key)].items()},'jumps':mapping}
                asynchronous = getattr(observer, 'async_maps', {}).get((name, key))
                if asynchronous is not None:
                    code_record['source_events'] = {
                        'ready': {offset: unit('source_events', value) for offset, value in asynchronous['ready'].items()},
                        'end': {offset: [following, unit('source_events', value)]
                                for offset, (following, value) in asynchronous['end'].items()}}
                codes.append(code_record)
            raw=json.dumps({'lines':{value:unit('lines',value) for value in row['line_total']},
                            'codes':codes},separators=(',',':')).encode()
            if len(raw)>8*1024**2:
                raise ValueError('module catalog exceeds child budget')
            filename=str(number)+'.json'
            (self.directory/filename).write_bytes(raw)
            modules[name]={'file':filename,'sha256':hashlib.sha256(raw).hexdigest(),'source_sha256':row['sha256']}
        descriptor={'schema_version':2,'python':list(sys.version_info[:3]),'root':str(observer.root),
                    'nonce':os.urandom(32).hex(),'units':len(self.units),'modules':modules}
        if hasattr(observer, 'source_catalogs'):
            descriptor['schema_version'] = 3
            descriptor['extensions'] = ['async_iteration_edges_v1']
        raw=json.dumps(descriptor,separators=(',',':')).encode()
        self.token=hashlib.sha256(raw).hexdigest()
        self.descriptor=self.directory/'campaign.json'
        self.descriptor.write_bytes(raw)
        shutil.copy2(Path(__file__).with_name('coverage_child.py'),self.directory/'coverage_child.py')
        (self.directory/'sitecustomize.py').write_text(
            'import os\n'
            'if os.environ.get("SWASSH_COVERAGE_CAMPAIGN"):\n'
            '    try:\n'
            '        from coverage_child import bootstrap\n'
            '        _swassh_observer=bootstrap(os.environ["SWASSH_COVERAGE_CAMPAIGN"])\n'
            '    except BaseException:\n'
            '        os.write(2,b"swassh: child coverage bootstrap failed\\n")\n'
            '        os._exit(126)\n',encoding='utf-8')

    def __enter__(self):
        self.previous={key:os.environ.get(key) for key in ('PYTHONPATH','SWASSH_COVERAGE_CAMPAIGN')}
        os.environ['PYTHONPATH']=str(self.directory)+os.pathsep+os.environ.get('PYTHONPATH','')
        os.environ['SWASSH_COVERAGE_CAMPAIGN']=str(self.descriptor)
        return self

    def __exit__(self,*error):
        for key,value in self.previous.items():
            if value is None: os.environ.pop(key,None)
            else: os.environ[key]=value

    def merge(self):
        """Reject corrupt, truncated, foreign or out-of-range journals atomically."""
        observed=set()
        children=[]
        files=sorted(self.directory.glob('*.events'))
        unpublished=sorted(self.directory.glob('*.events.initializing'))
        if len(files)+len(unpublished)>10000:
            raise ValueError('child coverage journal count exceeded')
        bootstraps=[]
        for path in unpublished:
            with path.open('rb') as stream:
                raw=stream.read(1025)
            if len(raw)>1024:
                raise ValueError('oversized unpublished child coverage header')
            # No unit observations can precede header publication. Preserve
            # metadata about interrupted startup, crediting no coverage at all.
            bootstraps.append({'file':path.name,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()})
        for path in files:
            with path.open('rb') as stream:
                header=stream.readline(1025)
                if len(header)>1024 or not header.endswith(b'\n'):
                    raise ValueError('invalid child coverage header')
                value=json.loads(header)
                if (set(value)!={'schema_version','catalog','pid'} or value['schema_version']!=1
                        or value['catalog']!=self.token or type(value['pid']) is not int or value['pid']<=0):
                    raise ValueError('foreign child coverage journal')
                raw=stream.read(2*1024**2+1)
            if len(raw)>2*1024**2 or len(raw)%RECORD.size:
                raise ValueError('truncated or oversized child coverage journal')
            units={value[0] for value in RECORD.iter_unpack(raw)}
            if any(value>=len(self.units) for value in units):
                raise ValueError('unknown child coverage unit')
            observed.update(units)
            children.append({'file':path.name,'pid':value['pid'],'observations':len(units),
                             'sha256':hashlib.sha256(header+raw).hexdigest()})
        # No partial acceptance: validate the entire campaign before any merge.
        for identity in observed:
            target,unit=self.units[identity]
            target.add(unit)
        return {'descriptor_sha256':self.token,'children':children,'units_observed':len(observed),
                'unpublished_bootstraps':bootstraps,
                'scope':'CPython children inheriting the measurement environment; isolated/external interpreters are not inferred'}
