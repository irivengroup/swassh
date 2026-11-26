"""Retain asyncio diagnostics separately from application stdout/stderr tests.

Instrumentation can make a callback cross asyncio's debug logging threshold.
The debug mode and threshold remain unchanged. Every accepted runtime record
is retained in a bounded journal, and logger ownership is restored on exit.
"""
import json
import logging


class RuntimeDiagnostics(logging.Handler):
    def __init__(self,stream,*,max_bytes=8*1024**2):
        super().__init__()
        if type(max_bytes) is not int or max_bytes < 1:
            raise ValueError('diagnostic journal budget must be a positive integer')
        self.stream,self.max_bytes=stream,max_bytes
        self.bytes=self.records=0

    def emit(self,record):
        line=json.dumps({'logger':record.name,'level':record.levelname,
                         'message':self.format(record)},ensure_ascii=True)+'\n'
        length=len(line.encode('utf-8'))
        if self.bytes+length > self.max_bytes:
            raise ValueError('coverage runtime diagnostic journal budget exceeded')
        self.stream.write(line)
        self.bytes+=length
        self.records+=1

    def __enter__(self):
        self.logger=logging.getLogger('asyncio')
        self.previous=list(self.logger.handlers),self.logger.propagate
        for handler in self.previous[0]:
            self.logger.removeHandler(handler)
        self.logger.addHandler(self)
        self.logger.propagate=False
        return self

    def __exit__(self,*error):
        self.logger.removeHandler(self)
        for handler in self.previous[0]:
            self.logger.addHandler(handler)
        self.logger.propagate=self.previous[1]
        self.stream.flush()
