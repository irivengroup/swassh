"""Observe CPython execution without rewriting application expressions.

Statements use source AST spans and instruction events; executable lines retain
the project's bytecode line-table definition. Functions use call events; branches use observed conditional and
iteration edges. Boolean conditions use conditional-test outcomes, separately
from iteration edges. A short-circuited test produces no observation.
"""
from __future__ import annotations

import ast
import dis
import hashlib
import os
from pathlib import Path
import sys
import threading
import types


METRICS = ('statements', 'branches', 'functions', 'lines', 'boolean_conditions')
_OPTIMIZED_BUILTINS={'any':any,'all':all,'tuple':tuple}


def constant_signature(code):
    """Retain literal identity when CPython omits lambda source columns.

    Constants are compiler-owned immutable data, never application values.
    Tags preserve bool/int and signed-zero distinctions. Nested code constants
    are traversed without filenames so short-path aliases remain equivalent.
    """
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


class _CodeIdentity:
    """Cache an exact structural hash without replacing equality by a digest."""
    __slots__=('value','hashed','linetable')

    def __init__(self,code):
        self.value=(code.co_qualname,code.co_firstlineno,tuple(code.co_positions()),code.co_code,constant_signature(code))
        self.linetable=code.co_linetable
        self.hashed=hash(self.value)

    def __hash__(self):
        return self.hashed

    def __eq__(self,other):
        return isinstance(other,_CodeIdentity) and self.value==other.value


class _Statements(ast.NodeVisitor):
    """Inventory every statement in its lexical execution scope, loaded or not."""
    def __init__(self,tree):
        self.scope='<module>'
        self.function_scope=False
        self.scopes={}
        self.metadata={}
        self.visit(tree)

    @staticmethod
    def key(node):
        return (node.lineno,node.col_offset,node.end_lineno,node.end_col_offset,type(node).__name__)

    def visit(self,node):
        if isinstance(node,ast.stmt):
            self.scopes.setdefault(self.scope,[]).append((self.key(node),node))
        return super().visit(node)

    def _definition(self,node,function):
        previous,was_function=self.scope,self.function_scope
        name=node.name if previous=='<module>' else previous+('.<locals>.' if was_function else '.')+node.name
        if function and node.body and isinstance(node.body[0],ast.Expr):
            expression=node.body[0]
            if isinstance(expression.value,ast.Constant) and isinstance(expression.value.value,str):
                self.metadata[self.key(node)]=self.key(expression)
        self.scope,self.function_scope=name,function
        for child in node.body:
            self.visit(child)
        self.scope,self.function_scope=previous,was_function

    def visit_FunctionDef(self,node):
        self._definition(node,True)

    visit_AsyncFunctionDef=visit_FunctionDef

    def visit_ClassDef(self,node):
        self._definition(node,False)

    def instructions(self,code):
        """Map only source-positioned instructions in the matching lexical scope.

        Statements on the same line retain different columns. Executing a
        function body never infers execution of its enclosing def statement.
        Optimized-away statements remain in the denominator and are reported.
        """
        scope=code.co_qualname
        if scope.endswith('.__annotate__'):
            scope=scope.rsplit('.',1)[0]
        entries=self.scopes.get(scope,())
        result={}
        for instruction in dis.get_instructions(code):
            position=instruction.positions
            if position.lineno is None or position.col_offset is None or instruction.opname in {'RESUME','RETURN_GENERATOR'}:
                continue
            start=(position.lineno,position.col_offset)
            end=(position.end_lineno,position.end_col_offset)
            hits=[]
            for key,node in entries:
                if (key[0],key[1])<=start and end<=(key[2],key[3]):
                    hits.append(key)
                    if instruction.opname=='MAKE_FUNCTION' and key in self.metadata:
                        hits.append(self.metadata[key])
            if hits:
                result[instruction.offset]=tuple(hits)
        return result


class _Definitions(ast.NodeVisitor):
    """Identify source functions and normative typing.Protocol declarations.

    Class bodies, implicit comprehensions and compiler annotation helpers are
    still inventoried and observed as legacy code entries, and keep every
    existing line/branch/boolean obligation. They are not source functions.
    Only verified Protocol methods with ellipsis/pass bodies are declarations;
    an empty ordinary application function remains a required implementation.
    """
    def __init__(self,tree):
        self.aliases=set()
        self.modules=set()
        for node in tree.body:
            if isinstance(node,ast.ImportFrom) and node.module=='typing':
                self.aliases.update(item.asname or item.name for item in node.names if item.name=='Protocol')
            if isinstance(node,ast.Import):
                self.modules.update(item.asname or item.name for item in node.names if item.name=='typing')
        rebound={node.id for node in ast.walk(tree) if isinstance(node,ast.Name) and isinstance(node.ctx,ast.Store)}
        rebound.update(node.name for node in ast.walk(tree) if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)))
        rebound.update(node.arg for node in ast.walk(tree) if isinstance(node,ast.arg))
        for node in ast.walk(tree):
            if isinstance(node,ast.ImportFrom) and node.module!='typing':
                rebound.update(item.asname or item.name for item in node.names)
        self.aliases-=rebound
        self.modules-=rebound
        self.scope='<module>';self.function_scope=False;self.protocol=False
        self.functions=set();self.lambdas=[];self.declarations=[];self.declaration_statements=set()
        self.visit(tree)

    def qualified(self,name):
        return name if self.scope=='<module>' else self.scope+('.<locals>.' if self.function_scope else '.')+name

    def is_protocol(self,node):
        for base in node.bases:
            if isinstance(base,ast.Subscript):base=base.value
            if isinstance(base,ast.Name) and base.id in self.aliases:return True
            if (isinstance(base,ast.Attribute) and base.attr=='Protocol' and isinstance(base.value,ast.Name)
                    and base.value.id in self.modules):return True
        return False

    @staticmethod
    def declaration_body(node):
        body=list(node.body)
        if body and isinstance(body[0],ast.Expr) and isinstance(body[0].value,ast.Constant) and isinstance(body[0].value.value,str):
            body=body[1:]
        if body and all(isinstance(item,ast.Pass) or isinstance(item,ast.Expr)
                        and isinstance(item.value,ast.Constant) and item.value.value is Ellipsis for item in body):
            return body
        return []

    def visit_ClassDef(self,node):
        previous=self.scope,self.function_scope,self.protocol
        for child in (*node.decorator_list,*node.bases):self.visit(child)
        for keyword in node.keywords:self.visit(keyword.value)
        self.scope,self.function_scope,self.protocol=self.qualified(node.name),False,self.is_protocol(node)
        for child in node.body:self.visit(child)
        self.scope,self.function_scope,self.protocol=previous

    def visit_FunctionDef(self,node):
        qualified=self.qualified(node.name)
        declaration=self.declaration_body(node) if self.protocol and not self.function_scope else []
        first=min([node.lineno,*[item.lineno for item in node.decorator_list]])
        if declaration:
            self.declarations.append({'qualname':qualified,'line':node.lineno,
                'reason':'typing.Protocol signature without a default implementation'})
            self.declaration_statements.update(_Statements.key(item) for item in declaration)
        else:
            self.functions.add((qualified,first))
        for name,value in ast.iter_fields(node):
            if name=='body':continue
            if isinstance(value,ast.AST):self.visit(value)
            elif isinstance(value,list):
                for child in value:
                    if isinstance(child,ast.AST):self.visit(child)
        previous=self.scope,self.function_scope,self.protocol
        self.scope,self.function_scope,self.protocol=qualified,True,False
        for child in node.body:self.visit(child)
        self.scope,self.function_scope,self.protocol=previous

    visit_AsyncFunctionDef=visit_FunctionDef

    def visit_Lambda(self,node):
        self.lambdas.append(node)
        self.generic_visit(node)

    def matches(self,code):
        if (code.co_qualname,code.co_firstlineno) in self.functions:return True
        if code.co_name!='<lambda>':return False
        for node in self.lambdas:
            if node.lineno!=code.co_firstlineno:continue
            for line,endline,column,endcolumn in code.co_positions():
                if (line is not None and column is not None
                        and (node.lineno,node.col_offset)<=(line,column)
                        and (endline,endcolumn)<=(node.end_lineno,node.end_col_offset)):
                    return True
            # 3.12 RETURN_CONST can carry only (line,0) for a constant lambda.
            # A real lambda code object on its source line still is a function;
            # literal identity distinguishes the two same-line oracle bodies.
            if all(column in (None,0) for _,_,column,_ in code.co_positions()):
                return True
        return False


class ExecutionCoverage:
    """Collect five independent counters for every source file, loaded or not.

    This CPython tracer observes interpreter jumps, not MC/DC, exception-path
    coverage or every possible input. Child processes need their own campaign;
    their unseen code remains uncovered in this report. Existing tracing hooks
    are restored on exit. Application values are never evaluated by the tracer.
    """

    def __init__(self, root):
        self.root = Path(root).resolve()
        self.rows = {}
        self.catalog = {}
        self.cache = {}
        self.filenames={}
        self.pending = {}
        self.chain_lengths = {}
        self.compiler_callees = {}
        self.statements = {}
        self.definitions={}
        self.statement_maps = {}
        self.instruction_cache={}
        self._trace_anchor = None
        for path in sorted(self.root.rglob('*.py')):
            source = path.read_bytes()
            name = os.path.normcase(str(path.resolve()))
            tree=ast.parse(source,filename=str(path))
            self.definitions[name]=_Definitions(tree)
            self.statements[name]=_Statements(tree)
            self.compiler_callees[name]={
                (node.func.lineno,node.func.col_offset,node.func.end_lineno,node.func.end_col_offset):node.func.id
                for node in ast.walk(tree) if isinstance(node,ast.Call)
                and isinstance(node.func,ast.Name) and node.func.id in {'any','all','tuple'}
                and len(node.args)==1 and isinstance(node.args[0],ast.GeneratorExp) and not node.keywords}
            self.chain_lengths[name] = {
                (node.lineno,node.col_offset,node.end_lineno,node.end_col_offset):len(node.ops)
                for node in ast.walk(tree)
                if isinstance(node,ast.Compare) and len(node.ops)>1}
            self.rows[name] = {
                'module': path.relative_to(self.root).as_posix(),
                'sha256': hashlib.sha256(source).hexdigest(),
                'line_total': set(), 'line_hits': set(),
                'function_total': set(), 'function_hits': set(),
                'legacy_function_total':set(),'legacy_function_hits':set(),
                'branch_total': set(), 'branch_hits': set(),
                'branch_positions':{},
                'condition_total': set(), 'condition_hits': set(),
                'compiler_guard_conditions':{},
                'legacy_statement_total':{key for entries in self.statements[name].scopes.values() for key,_ in entries},
                'statement_total': {key for entries in self.statements[name].scopes.values() for key,_ in entries}
                                   -self.definitions[name].declaration_statements,
                'statement_hits': set(),
            }
            self._inventory(compile(source, str(path), 'exec', dont_inherit=True), name)

    @staticmethod
    def _identity(code):
        # Columns distinguish two same-line lambdas/comprehensions.
        return _CodeIdentity(code)

    def _inventory(self, code, name):
        row = self.rows[name]
        key = self._identity(code)
        if (name,key) in self.catalog:
            raise ValueError('ambiguous compiler code identity; refusing to merge distinct source bodies')
        self.statement_maps[(name,key)]=self.statements[name].instructions(code)
        row['line_total'].update(line for _, line in dis.findlinestarts(code) if line and line > 0)
        if self.definitions[name].matches(code):
            row['function_total'].add(key)
        if code.co_name!='<module>':row['legacy_function_total'].add(key)
        jumps = {}
        chain_sites = {}
        previous=None
        instructions=list(dis.get_instructions(code))
        by_offset={instruction.offset:index for index,instruction in enumerate(instructions)}
        for index,instruction in enumerate(instructions):
            conditional = ('JUMP' in instruction.opname and 'IF' in instruction.opname)
            iteration = instruction.opname == 'FOR_ITER'
            if conditional or iteration:
                branch = (key, instruction.offset)
                row['branch_total'].update((branch, outcome) for outcome in (False, True))
                position = instruction.positions
                span = (position.lineno,position.col_offset,position.end_lineno,position.end_col_offset)
                row['branch_positions'][branch]=span
                if sys.version_info[:2] == (3, 11) and index:
                    # 3.11 can assign the entire if/while statement to both
                    # jumps of `a or b`. Their real value-producing operations
                    # retain separate source spans; do not merge those tests.
                    producer_index = index - 1
                    while producer_index > 0 and instructions[producer_index].opname == 'EXTENDED_ARG':
                        producer_index -= 1
                    producer = instructions[producer_index]
                    if producer.opname.startswith(('LOAD_', 'COMPARE_OP', 'IS_OP', 'CONTAINS_OP', 'CALL', 'BINARY_OP')):
                        point = producer.positions
                        span = (point.lineno, point.col_offset, point.end_lineno, point.end_col_offset)
                prefix=instructions[max(0,index-3):index]
                # CPython 3.14's any/all/tuple generator optimization tests
                # the callee's identity before choosing its implementation.
                # This is a real bytecode branch (still required below), but
                # is not an application-value boolean outcome. The compiler
                # gives it the SAME span as any/all's later data truth test;
                # merging them would invent an unobserved True outcome.
                callee=self.compiler_callees[name].get(span)
                compiler_guard=(callee is not None and instruction.opname=='POP_JUMP_IF_FALSE'
                    and len(prefix)==3 and [item.opname for item in prefix]==['COPY','LOAD_COMMON_CONSTANT','IS_OP']
                    and prefix[0].arg==1 and prefix[1].argrepr in {callee,repr(_OPTIMIZED_BUILTINS[callee])} and prefix[2].arg==0
                    and all(tuple(item.positions)==tuple(position) for item in prefix))
                # Chained comparisons share a compiler source span but are
                # distinct elementary tests. A duplicated while-condition
                # reuses those tests rather than inventing extra conditions.
                count = self.chain_lengths[name].get(span,1)
                element = chain_sites.get(span,0) % count
                condition = (key,*span,element)
                if conditional and not compiler_guard:
                    chain_sites[span] = chain_sites.get(span,0)+1
                    row['condition_total'].update((condition, outcome) for outcome in (False, True))
                truth_on_jump = ('FALSE' not in instruction.opname
                                 and 'NOT_NONE' not in instruction.opname)
                if compiler_guard:
                    row['compiler_guard_conditions'][branch]=(condition,truth_on_jump)
                jumps[instruction.offset] = (instruction.argval, branch,
                                             condition if conditional and not compiler_guard else None,
                                             truth_on_jump, iteration)
                prefix_index = index
                while prefix_index > 0 and instructions[prefix_index - 1].opname == 'EXTENDED_ARG':
                    prefix_index -= 1
                if prefix_index != index:
                    # Opcode tracing may report only the first extended-arg
                    # prefix. It is the same executable jump, not a new unit.
                    jumps[instructions[prefix_index].offset] = jumps[instruction.offset]
            elif instruction.opname=='NOT_TAKEN' and previous in jumps:
                # With INSTRUCTION enabled, CPython 3.14 reports a fall-through
                # event at its explicit NOT_TAKEN marker. It is the other edge
                # of the preceding test, not an additional source decision.
                jumps[instruction.offset]=jumps[previous]
            previous=instruction.offset
        for instruction in instructions:
            if instruction.opname=='FOR_ITER':
                index=by_offset[instruction.argval]
                tail=instructions[index:index+2]
                if len(tail)==2 and [item.opname for item in tail]==['END_FOR','POP_ITER']:
                    # INSTRUCTION monitoring exposes the exhausted iterator's
                    # POP_ITER edge in 3.14. Preserve the original FOR_ITER
                    # denominator and associate only its verified exit marker.
                    jumps[tail[1].offset]=jumps[instruction.offset]
        self.catalog[(name, key)] = (row, key, jumps)
        for value in code.co_consts:
            if isinstance(value, types.CodeType):
                self._inventory(value, name)

    def _info(self, code):
        identity=id(code)
        if identity not in self.cache:
            filename=code.co_filename
            if filename not in self.filenames:
                name=os.path.normcase(os.path.abspath(filename))
                if name not in self.rows and not filename.startswith('<'):
                    name=os.path.normcase(os.path.realpath(filename))
                self.filenames[filename]=name
            name=self.filenames[filename]
            # Retain the code object: its id cannot be reused during this run.
            self.cache[identity] = (code,self.catalog.get((name,self._identity(code)))
                                    if name in self.rows else None)
            if self.cache[identity][1] is not None:
                self.instruction_cache[identity]=self.statement_maps[(name,self.cache[identity][1][1])]
        return self.cache[identity][1]

    def _observe_statement(self,code,offset,info):
        info[0]['statement_hits'].update(self.instruction_cache[id(code)].get(offset,()))

    def _trace(self, frame, event, arg):
        info = self._info(frame.f_code)
        if info is None:
            return None
        row, key, jumps = info
        identity = id(frame)
        if event == 'call':
            # Publish the frame callback before enabling opcode events. On
            # newer CPython, enabling first and returning the callback later
            # can leave the first invocation without any opcode observations.
            frame.f_trace = self._trace
            frame.f_trace_opcodes = True
            frame.f_trace_lines = True
            if key in row['function_total']:
                row['function_hits'].add(key)
            if frame.f_code.co_name!='<module>':row['legacy_function_hits'].add(key)
        elif event == 'line':
            row['line_hits'].add(frame.f_lineno)
        elif event == 'opcode':
            self._observe_statement(frame.f_code,frame.f_lasti,info)
            previous = self.pending.pop(identity, None)
            if previous is not None and jumps.get(frame.f_lasti) != previous:
                target, branch, condition, truth_on_jump, iteration = previous
                taken = frame.f_lasti >= target if iteration else frame.f_lasti == target
                row['branch_hits'].add((branch, taken))
                if condition is not None:
                    row['condition_hits'].add((condition, taken == truth_on_jump))
            jump = jumps.get(frame.f_lasti)
            if jump is not None:
                self.pending[identity] = jump
        elif event in ('exception', 'return'):
            # A truth conversion that raises did not evaluate true or false.
            self.pending.pop(identity, None)
        return self._trace

    def _dispatch_trace(self, frame, event, arg):
        """Preserve an existing tracer alongside this opcode observer."""
        identity = id(frame)
        previous = self._previous_frames.pop(identity, None)
        callback = previous[1] if previous is not None else None
        lines, opcodes = previous[2:] if previous is not None else (True, False)
        if event == 'call':
            callback = self.previous if threading.get_ident() == self._trace_thread else self.previous_thread
        if callback is not None and (event not in ('line', 'opcode')
                                     or event == 'line' and lines or event == 'opcode' and opcodes):
            callback = callback(frame, event, arg)
            lines, opcodes = frame.f_trace_lines, frame.f_trace_opcodes
        ours = self._trace(frame, event, arg)
        if callback is not None and event != 'return':
            self._previous_frames[identity] = (frame, callback, lines, opcodes)
        if ours is not None or callback is not None:
            frame.f_trace = self._dispatch_trace
            return self._dispatch_trace
        return None

    def __enter__(self):
        self.monitoring = getattr(sys, 'monitoring', None)
        if self.monitoring is not None:
            self.tool_id = next((number for number in (1, 3, 4, 0, 2, 5)
                                 if self.monitoring.get_tool(number) is None), None)
            if self.tool_id is None:
                raise RuntimeError('no free CPython monitoring tool ID')
            self.monitoring.use_tool_id(self.tool_id, 'swassh-five-metric-coverage')
            self._active_codes={}
            events = self.monitoring.events
            self.callbacks = {events.PY_START: self._started,
                              events.LINE: self._line}
            self.monitoring.register_callback(self.tool_id,events.INSTRUCTION,self._instruction)
            if hasattr(events, 'BRANCH_LEFT'):
                self.callbacks[events.BRANCH_LEFT] = self._branch
                self.callbacks[events.BRANCH_RIGHT] = self._branch
            else:
                self.callbacks[events.BRANCH] = self._branch
            try:
                for event, callback in self.callbacks.items():
                    self.monitoring.register_callback(self.tool_id, event, callback)
                self.monitoring.set_events(self.tool_id, sum(self.callbacks))
            except BaseException:
                self._unmonitor()
                raise
            return self
        self.previous = sys.gettrace()
        self.previous_thread = threading.gettrace()
        self._previous_frames = {}
        self._trace_thread = threading.get_ident()
        # CPython 3.12 requires an opcode-enabled frame before settrace;
        # documented in /3.12/library/sys.html#sys.settrace. Keep its prior
        # flag and restore it, without warming or executing application code.
        if sys.version_info[:2] == (3,12):
            self._trace_anchor = sys._getframe()
            self._anchor_opcodes = self._trace_anchor.f_trace_opcodes
            self._trace_anchor.f_trace_opcodes = True
        try:
            threading.settrace(self._dispatch_trace)
            sys.settrace(self._dispatch_trace)
        except BaseException:
            threading.settrace(self.previous_thread)
            self._restore_anchor()
            raise
        return self

    def __exit__(self, *exception):
        if self.monitoring is not None:
            self._unmonitor()
            return
        try:
            sys.settrace(self.previous)
        finally:
            threading.settrace(self.previous_thread)
            self._restore_anchor()
            self.pending.clear()
            self._previous_frames.clear()

    def _restore_anchor(self):
        if self._trace_anchor is not None:
            self._trace_anchor.f_trace_opcodes = self._anchor_opcodes
            self._trace_anchor = None

    def _unmonitor(self):
        self.monitoring.set_events(self.tool_id, 0)
        for code in self._active_codes.values():
            self.monitoring.set_local_events(self.tool_id,code,0)
        self._active_codes.clear()
        self.monitoring.register_callback(self.tool_id,self.monitoring.events.INSTRUCTION,None)
        for event in self.callbacks:
            self.monitoring.register_callback(self.tool_id, event, None)
        self.monitoring.free_tool_id(self.tool_id)

    def _started(self, code, offset):
        info = self._info(code)
        if info is None:
            return self.monitoring.DISABLE
        row, key, _ = info
        mapping=self.instruction_cache[id(code)]
        if mapping:
            # PY_START is entry into the code's first statement. CPython 3.12
            # can already have fetched its first instruction when local events
            # are enabled here; retain that observed entry without crediting a
            # later statement, branch or boolean outcome.
            self._observe_statement(code,min(mapping),info)
        if id(code) not in self._active_codes:
            self._active_codes[id(code)]=code
            self.monitoring.set_local_events(self.tool_id,code,self.monitoring.events.INSTRUCTION)
        if key in row['function_total']:
            row['function_hits'].add(key)
        if code.co_name!='<module>':row['legacy_function_hits'].add(key)
        return self.monitoring.DISABLE

    def _instruction(self,code,offset):
        info=self._info(code)
        if info is not None:
            self._observe_statement(code,offset,info)
        # An instruction site always maps to the same source statements. Its
        # first observation suffices, independently of still-active decisions.
        return self.monitoring.DISABLE

    def _line(self, code, line):
        info = self._info(code)
        if info is None:
            return self.monitoring.DISABLE
        info[0]['line_hits'].add(line)
        # Disabling LINE can suppress the same site's INSTRUCTION callback
        # for NOP, jumps and bare re-raise instructions on supported CPython.
        # Keep source LINE sites active; statements still require an actual
        # instruction event, never an inference from line execution.
        return None

    def _branch(self, code, offset, destination):
        info = self._info(code)
        if info is None:
            return self.monitoring.DISABLE
        row, _, jumps = info
        if offset in jumps:
            target, branch, condition, truth_on_jump, iteration = jumps[offset]
            # CPython 3.14 monitoring can skip END_FOR/POP_ITER on exhaustion;
            # the edge is still the forward exit, never the body fall-through.
            taken = destination >= target if iteration else destination == target
            row['branch_hits'].add((branch, taken))
            if condition is not None:
                row['condition_hits'].add((condition, taken == truth_on_jump))
            if (hasattr(self.monitoring.events,'BRANCH_LEFT')
                    or {(branch,False),(branch,True)}<=row['branch_hits']):
                return self.monitoring.DISABLE

    @staticmethod
    def _measure(covered, total):
        return {'covered': covered, 'total': total,
                'percent': 100 * covered / total if total else None}

    def report(self):
        modules = []
        for row in self.rows.values():
            lines = row['line_hits'] & row['line_total']
            modules.append({
                'module': row['module'], 'sha256': row['sha256'],
                'metrics': {
                    'statements': self._measure(len(row['statement_hits'] & row['statement_total']),len(row['statement_total'])),
                    'lines': self._measure(len(lines), len(row['line_total'])),
                    'functions': self._measure(len(row['function_hits'] & row['function_total']), len(row['function_total'])),
                    'branches': self._measure(len(row['branch_hits']), len(row['branch_total'])),
                    'boolean_conditions': self._measure(len(row['condition_hits']), len(row['condition_total'])),
                },
                'missing_lines': sorted(row['line_total'] - lines),
                'missing_statements':sorted(row['statement_total']-row['statement_hits']),
                'declarations':self.definitions[os.path.normcase(str(self.root/row['module']))].declarations,
                'missing_functions':sorted((key.value[0],key.value[1]) for key in row['function_total']-row['function_hits']),
                'missing_branches':sorted((branch[0].value[0],branch[0].value[1],branch[1],outcome)
                    for branch,outcome in row['branch_total']-row['branch_hits']),
                'missing_branch_locations':sorted((
                    {'function':branch[0].value[0],'definition_line':branch[0].value[1],
                     'offset':branch[1],'position':row['branch_positions'][branch],'jump_taken':outcome}
                    for branch,outcome in row['branch_total']-row['branch_hits']),key=repr),
                'missing_boolean_conditions':sorted((
                    {'function':condition[0].value[0],'definition_line':condition[0].value[1],
                     'position':condition[1:5],'element':condition[5],'truth':outcome}
                    for condition,outcome in row['condition_total']-row['condition_hits']),key=repr),
            })
        def aggregate(rows):
            return {metric: self._measure(sum(row['metrics'][metric]['covered'] for row in rows),
                                         sum(row['metrics'][metric]['total'] for row in rows))
                    for metric in METRICS}
        components = sorted({row['module'].split('/')[0] for row in modules})
        def raw_conditions(row):
            total=set(row['condition_total'])
            hits=set(row['condition_hits'])
            for branch,(condition,truth) in row['compiler_guard_conditions'].items():
                total.update((condition,outcome) for outcome in (False,True))
                hits.update((condition,outcome==truth) for outcome in (False,True)
                            if (branch,outcome) in row['branch_hits'])
            return self._measure(len(hits & total),len(total))
        legacy=[{'module':row['module'],
                 'functions':self._measure(len(row['legacy_function_hits'] & row['legacy_function_total']),len(row['legacy_function_total'])),
                 'boolean_conditions':raw_conditions(row),
                 'statements':self._measure(len(row['statement_hits'] & row['legacy_statement_total']),len(row['legacy_statement_total']))}
                for row in self.rows.values()]
        return {'schema_version': 4, 'engine': 'stdlib CPython instruction/branch/line/call events',
                'python': sys.version, 'source_root': str(self.root),
                'definitions': {
                    'statements': 'AST statement spans; instruction/code-entry observations in lexical scope, function docstrings at MAKE_FUNCTION; Protocol signature-only bodies classified as declarations, ordinary empty functions remain required',
                    'branches': 'conditional-test and FOR_ITER jump edges, excluding exception-table edges',
                    'functions': 'observed calls of source def/async def/lambda implementations; verified Protocol signature declarations are separately listed; class/compiler/implicit code entries retained in legacy counters',
                    'boolean_conditions': 'observed source-positioned data conditional tests, with distinct chained-comparison elements; exact AST/opcode-verified compiler builtin-identity dispatch retained in raw counters and branches, never credited as application truth; no inference for short-circuit',
                    'processes': 'current process and threads created during measurement; children not traced',
                },
                'global': aggregate(modules),
                'legacy_all_bytecode_boolean_conditions':{'global':self._measure(sum(row['boolean_conditions']['covered'] for row in legacy),sum(row['boolean_conditions']['total'] for row in legacy)),
                    'modules':[{'module':row['module'],**row['boolean_conditions']} for row in legacy]},
                'legacy_nested_code_entries':{'global':self._measure(sum(row['functions']['covered'] for row in legacy),sum(row['functions']['total'] for row in legacy)),
                    'modules':[{ 'module':row['module'],**row['functions']} for row in legacy]},
                'legacy_all_ast_statements':{'global':self._measure(sum(row['statements']['covered'] for row in legacy),sum(row['statements']['total'] for row in legacy)),
                    'modules':[{ 'module':row['module'],**row['statements']} for row in legacy]},
                'components': {component: aggregate([row for row in modules
                    if row['module'].split('/')[0] == component]) for component in components},
                'modules': modules}


def gate(report, threshold=98):
    """Reject missing, malformed or insufficient metrics without rounding.

    Every file and component is checked as well as the global counters. Empty
    denominators are explicit and do not turn into invented percentages.
    """
    failures = []
    if type(threshold) is not int or not 98 <= threshold <= 100:
        raise ValueError('coverage threshold must be an integer between 98 and 100')
    scopes = [('global', report.get('global', {}))]
    scopes += list(report.get('components', {}).items())
    scopes += [(row['module'], row['metrics']) for row in report.get('modules', [])]
    if not report.get('modules') or not report.get('components'):
        failures.append('missing module or component inventory')
    for scope, metrics in scopes:
        for metric in METRICS:
            value = metrics.get(metric)
            if not isinstance(value, dict):
                failures.append(scope + ': missing ' + metric)
                continue
            covered, total = value.get('covered'), value.get('total')
            if (type(covered) is not int or type(total) is not int
                    or not 0 <= covered <= total):
                failures.append(scope + ': invalid ' + metric)
            elif total and covered * 100 < total * threshold:
                failures.append(scope + ': ' + metric + ' below ' + str(threshold) + '%')
    return failures
