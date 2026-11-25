"""Project observed CPython edges onto an independent source decision catalog.

The original observer, bytecode counters and child protocol remain intact.
Every source decision is inventoried before execution. Missing mappings remain
uncovered and explicitly block admission; a compiler edge is never evidence
that an application value had an unobserved truth outcome.
"""
import ast
import base64
import hashlib
import copy
import dis
import os
import sys
import types

from coverage_metrics import ExecutionCoverage, METRICS, _Definitions, gate as raw_gate


def span(node):
    """Use Python's UTF-8 source coordinates, not display-character columns."""
    return (node.lineno, node.col_offset, node.end_lineno, node.end_col_offset)


class SourceDecisions(ast.NodeVisitor):
    """Inventory control-flow truth tests and source iteration independently.

    Elementary short-circuit and chained-comparison tests are distinct. Literal
    constant guards have no runtime decision. Exception routing, context-manager
    suppression and compiler specialization stay in the separate raw report;
    this metric does not claim exception-path coverage or MC/DC.
    """

    def __init__(self, tree):
        self.tests = set()
        self.aliases = {}
        self.loops = {}
        self.loop_kinds = {}
        self.test_names = {}
        self.loop_aliases = {}
        self.none_tests = {}
        self.comprehension_none = []
        self.compound_negations = set()
        self.unsupported = []
        self.visit(tree)

    def test(self, node):
        if isinstance(node, ast.Constant):
            return
        if isinstance(node, ast.BoolOp):
            for value in node.values:
                self.test(value)
        elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            if (isinstance(node.operand, ast.BoolOp) or isinstance(node.operand, ast.Compare)
                    and len(node.operand.ops) > 1):
                self.compound_negations.add(span(node))
            self.test(node.operand)
            self.aliases[span(node)] = span(node.operand)
        elif isinstance(node, ast.NamedExpr):
            # The assignment preserves a value before this outer truth test.
            # Its value's short-circuit tests are inventoried by visit_BoolOp;
            # the returned last operand is not tested until the assignment.
            self.tests.add((*span(node), 0))
        else:
            count = len(node.ops) if isinstance(node, ast.Compare) else 1
            for element in range(count):
                self.tests.add((*span(node), element))
            if isinstance(node, ast.Name):
                self.test_names[(*span(node), 0)] = node.id
            if (isinstance(node, ast.Compare) and len(node.ops) == 1
                    and isinstance(node.ops[0], (ast.Is, ast.IsNot))
                    and any(isinstance(value, ast.Constant) and value.value is None
                            for value in (node.left, *node.comparators))):
                self.none_tests[span(node)] = isinstance(node.ops[0], ast.Is)
                other = node.comparators[0] if isinstance(node.left, ast.Constant) else node.left
                self.aliases[span(other)] = span(node)

    def visit_If(self, node):
        self.test(node.test)
        self.generic_visit(node)

    visit_While = visit_If
    visit_IfExp = visit_If
    visit_Assert = visit_If

    def visit_BoolOp(self, node):
        for value in node.values[:-1]:
            self.test(value)
        self.generic_visit(node)

    def visit_Compare(self, node):
        for element in range(len(node.ops) - 1):
            self.tests.add((*span(node), element))
        self.generic_visit(node)

    def visit_For(self, node):
        self.loops[span(node.iter)] = (span(node), False)
        self.loop_kinds[span(node.iter)] = 'For'
        self.generic_visit(node)

    def visit_AsyncFor(self, node):
        self.loops[span(node.iter)] = (span(node), True)
        self.loop_kinds[span(node.iter)] = 'AsyncFor'
        self.generic_visit(node)

    def _comprehension(self, node):
        for generator in node.generators:
            self.loops[span(generator.iter)] = (span(node), bool(generator.is_async))
            self.loop_kinds[span(generator.iter)] = type(node).__name__
            for condition in generator.ifs:
                self.test(condition)
                if (isinstance(condition, ast.Compare) and len(condition.ops) == 1
                        and isinstance(condition.ops[0], (ast.Is, ast.IsNot))):
                    values = (condition.left, *condition.comparators)
                    names = [value.id for value in values if isinstance(value, ast.Name)]
                    if len(names) == 1 and any(isinstance(value, ast.Constant) and value.value is None for value in values):
                        self.comprehension_none.append((span(node), names[0], (*span(condition), 0)))
        self.generic_visit(node)

    visit_ListComp = _comprehension
    visit_SetComp = _comprehension
    visit_DictComp = _comprehension
    visit_GeneratorExp = _comprehension

    def visit_Call(self, node):
        if (isinstance(node.func, ast.Name) and node.func.id in {'any', 'all', 'tuple'}
                and len(node.args) == 1 and isinstance(node.args[0], ast.GeneratorExp)
                and not node.keywords and len(node.args[0].generators) == 1):
            self.loop_aliases[span(node.func)] = span(node.args[0].generators[0].iter)
        self.generic_visit(node)

    def visit_Match(self, node):
        self.unsupported.append(('match', span(node)))
        self.generic_visit(node)

    def resolve_alias(self, position):
        while position in self.aliases:
            position = self.aliases[position]
        return position


class ImplementationLines:
    """Project bytecode line inventories onto the adopted source contract.

    Only verified typing.Protocol bodies without an implementation are omitted.
    Class creation, decorators, defaults, annotation helpers and every ordinary
    function remain executable. Unioning retained code entries preserves shared
    lines. The gate reconstructs this inventory from hash-verified source bytes;
    it never trusts a claimed list of excluded lines.
    """

    CONTRACT = 'source-implementation-lines-v1'
    MAX_SOURCE_BYTES = 2 * 1024 * 1024

    def __init__(self, source):
        if type(source) is not bytes or not source or len(source) > self.MAX_SOURCE_BYTES:
            raise ValueError('invalid or oversized line-projection source')
        self.source = source
        self.sha256 = hashlib.sha256(source).hexdigest()
        tree = ast.parse(source)
        self.definitions = _Definitions(tree)
        nodes = {node.lineno: node for node in ast.walk(tree)
                 if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
        declarations = {}
        for declaration in self.definitions.declarations:
            node = nodes[declaration['line']]
            first = min([node.lineno, *[item.lineno for item in node.decorator_list]])
            declarations[(declaration['qualname'], first)] = node.lineno
        self.raw_lines, self.lines, self.declaration_codes = set(), set(), []
        pending = [compile(source, '<coverage-line-inventory>', 'exec', dont_inherit=True)]
        while pending:
            code = pending.pop()
            key = (code.co_qualname, code.co_firstlineno)
            lines = {line for _, line in dis.findlinestarts(code) if line and line > 0}
            self.raw_lines.update(lines)
            if key in declarations:
                self.declaration_codes.append({'qualname': key[0], 'first_line': key[1],
                    'definition_line': declarations[key], 'lines': sorted(lines)})
            else:
                self.lines.update(lines)
            pending.extend(item for item in code.co_consts if isinstance(item, types.CodeType))
        self.declaration_codes.sort(key=lambda row: (row['first_line'], row['qualname']))

    def ledger(self):
        """Expose a reconstructible, lossless record; no execution is inferred."""
        return {'contract': self.CONTRACT, 'source_b64': base64.b64encode(self.source).decode('ascii'),
            'implementation_lines': sorted(self.lines),
            'declaration_only_lines': sorted(self.raw_lines - self.lines),
            'declaration_code_entries': copy.deepcopy(self.declaration_codes)}

    def measure(self, raw_module):
        """Use only the preserved actual line observations and verified inventory."""
        if raw_module.get('sha256') != self.sha256:
            raise ValueError('line-projection source identity mismatch')
        if raw_module.get('declarations') != self.definitions.declarations:
            raise ValueError('line-projection declaration inventory mismatch')
        missing = raw_module.get('missing_lines')
        if (type(missing) is not list or any(type(line) is not int or line <= 0 for line in missing)
                or missing != sorted(set(missing)) or not set(missing) <= self.raw_lines):
            raise ValueError('invalid raw missing-line observations')
        observed = self.raw_lines - set(missing)
        expected_raw = ExecutionCoverage._measure(len(observed), len(self.raw_lines))
        if raw_module.get('metrics', {}).get('lines') != expected_raw:
            raise ValueError('raw line observations disagree with source inventory')
        return (ExecutionCoverage._measure(len(self.lines & observed), len(self.lines)),
                sorted(self.lines - observed))


def _line_projection_failures(report, raw):
    """Rebuild schema-6 inventories instead of accepting arbitrary exclusions.

    The source bytes are bounded, never executed, and checked against the module
    hash. A report is checked on its measuring interpreter because bytecode line
    tables are runtime-specific. Legacy schema-5 evidence keeps its old strict
    line identity contract in gate().
    """
    failures = []
    runtime = report.get('line_projection_runtime')
    if (type(runtime) is not list or len(runtime) != 3
            or any(type(value) is not int for value in runtime) or runtime != list(sys.version_info[:3])):
        return ['line-projection measuring runtime missing or incompatible']
    originals = {row.get('module'): row for row in raw.get('modules', [])}
    rows = report.get('modules', [])
    if len(originals) != len(raw.get('modules', [])) or len({row.get('module') for row in rows}) != len(rows):
        return ['line-projection duplicate module inventory']
    projected = {}
    for module in rows:
        name = module.get('module')
        try:
            ledger = module.get('line_projection')
            if type(ledger) is not dict or ledger.get('contract') != ImplementationLines.CONTRACT:
                raise ValueError('line-projection evidence missing or incompatible')
            encoded = ledger.get('source_b64')
            maximum = 4 * ((ImplementationLines.MAX_SOURCE_BYTES + 2) // 3)
            if type(encoded) is not str or not encoded or len(encoded) > maximum:
                raise ValueError('invalid or oversized line-projection source encoding')
            source = base64.b64decode(encoded, validate=True)
            inventory = ImplementationLines(source)
            if inventory.sha256 != module.get('sha256') or inventory.ledger() != ledger:
                raise ValueError('line-projection source or catalog identity mismatch')
            metric, missing = inventory.measure(originals[name])
            if module.get('metrics', {}).get('lines') != metric or module.get('missing_lines') != missing:
                raise ValueError('source line observations disagree with verified projection')
            projected[name] = metric
        except (ValueError, TypeError, KeyError, SyntaxError, RecursionError, OverflowError) as error:
            failures.append('line projection in ' + str(name) + ': ' + str(error))
    if len(projected) != len(rows):
        return failures
    scopes = [('global', True, list(projected))]
    components = sorted({name.split('/')[0] for name in projected})
    if set(report.get('components', {})) != set(components) or set(raw.get('components', {})) != set(components):
        failures.append('line-projection component inventory mismatch')
    scopes.extend((component, False, [name for name in projected if name.split('/')[0] == component])
                  for component in components)
    for scope, global_scope, names in scopes:
        expected = ExecutionCoverage._measure(sum(projected[name]['covered'] for name in names),
                                               sum(projected[name]['total'] for name in names))
        expected_raw = ExecutionCoverage._measure(sum(originals[name]['metrics']['lines']['covered'] for name in names),
                                                   sum(originals[name]['metrics']['lines']['total'] for name in names))
        metrics = report.get('global', {}) if global_scope else report.get('components', {}).get(scope, {})
        raw_metrics = raw.get('global', {}) if global_scope else raw.get('components', {}).get(scope, {})
        if metrics.get('lines') != expected:
            failures.append('source line aggregate mismatch: ' + scope)
        if raw_metrics.get('lines') != expected_raw:
            failures.append('raw line aggregate mismatch: ' + scope)
    return failures


class SourceExecutionCoverage(ExecutionCoverage):
    """Keep raw observations, then compute source metrics without value access."""

    def __init__(self, root):
        super().__init__(root)
        self.implementation_lines = {}
        self.source_catalogs = {}
        self.source_maps = {}
        self.async_maps = {}
        self.async_pending = {}
        for name, row in self.rows.items():
            row['source_event_total'], row['source_event_hits'] = set(), set()
            source = (self.root / row['module']).read_bytes()
            self.implementation_lines[name] = ImplementationLines(source)
            catalog = SourceDecisions(ast.parse(source))
            self.source_catalogs[name] = catalog
            mappings = {}
            compiled = {}
            pending = [compile(source, str(self.root / row['module']), 'exec', dont_inherit=True)]
            while pending:
                code = pending.pop()
                compiled[self._identity(code)] = list(dis.get_instructions(code))
                pending.extend(value for value in code.co_consts if isinstance(value, types.CodeType))
            for (filename, key), (_, _, jumps) in self.catalog.items():
                if filename != name:
                    continue
                used_loops = set()
                instructions = compiled[key]
                by_offset = {item.offset: index for index, item in enumerate(instructions)}
                asynchronous = {'ready': {}, 'end': {}, 'after': set()}
                for site, (owner, is_async) in catalog.loops.items():
                    if not is_async:
                        continue
                    starts = [index for index, item in enumerate(instructions)
                              if item.opname == 'GET_ANEXT' and self._position(item) == owner]
                    ends = [index for index, item in enumerate(instructions)
                            if item.opname == 'END_ASYNC_FOR' and self._position(item) in (site, owner)]
                    if len(starts) == len(ends) == 1 and ends[0] + 1 < len(instructions):
                        sends = [item for item in instructions[starts[0] + 1:starts[0] + 4] if item.opname == 'SEND']
                        if len(sends) == 1:
                            after = instructions[ends[0] + 1].offset
                            asynchronous['ready'][sends[0].argval] = (site, True)
                            asynchronous['end'][instructions[ends[0]].offset] = (after, (site, False))
                            asynchronous['after'].add(after)
                            row['source_event_total'].update((site, value) for value in (False, True))
                if asynchronous['ready']:
                    self.async_maps[(name, key)] = asynchronous
                for offset, (_, branch, condition, truth, iteration) in jumps.items():
                    if branch in mappings:
                        continue
                    position = row['branch_positions'][branch]
                    if iteration:
                        inlined_generator = position in catalog.loop_aliases
                        position = catalog.loop_aliases.get(position, position)
                        candidates = [site for site, (owner, asynchronous) in catalog.loops.items()
                                      if not asynchronous and (site == position or owner == position)]
                        helper = key.value[0].rsplit('.', 1)[-1]
                        helper_kind = {'<genexpr>': 'GeneratorExp', '<dictcomp>': 'DictComp',
                                       '<listcomp>': 'ListComp', '<setcomp>': 'SetComp'}.get(helper)
                        if helper_kind is not None:
                            own = [site for site in candidates if catalog.loop_kinds[site] == helper_kind]
                            if own:
                                candidates = own
                        elif not inlined_generator:
                            candidates = [site for site in candidates if catalog.loop_kinds[site] != 'GeneratorExp']
                        exact = [site for site in candidates if site == position]
                        owners = [site for site in candidates if catalog.loops[site][0] == position
                                  and site not in used_loops]
                        # A completed inlined comprehension and the outer for
                        # can share an owner span in later 3.12 compilers.
                        # Never reuse the inner loop to hide the outer one.
                        if sys.version_info[:2] == (3, 12) and owners:
                            candidates = owners
                        elif exact:
                            candidates = exact
                        available = [site for site in candidates if site not in used_loops]
                        if len(available) > 1 and all(catalog.loops[site][0] == position for site in available):
                            # 3.12 gives nested comprehension FOR_ITER sites one
                            # shared owner span. Both AST generator order and
                            # bytecode FOR_ITER order are lexical outer-to-inner.
                            available = [min(available)]
                        if len(available) == 1:
                            site = available[0]
                            mappings[branch] = ('iteration', site, False)
                            used_loops.add(site)
                    elif condition is not None:
                        if position in self.compiler_callees[name]:
                            # Inlined any/all reduction truth is a compiler
                            # implementation detail. Its earlier False items
                            # cannot stand in for a whole-call False result,
                            # nor for another comparison in the generator.
                            continue
                        position = catalog.resolve_alias(position)
                        site = (*position, condition[-1])
                        instruction = instructions[by_offset[branch[1]]]
                        previous_index = by_offset[branch[1]] - 1
                        # EXTENDED_ARG extends the jump operand, not the value
                        # being tested. Large 3.11 functions need these prefixes.
                        while previous_index > 0 and instructions[previous_index].opname == 'EXTENDED_ARG':
                            previous_index -= 1
                        previous = instructions[previous_index]
                        # CPython may give an inlined comprehension jump the
                        # element span. Its immediately preceding truth/value
                        # instruction retains the actual filter expression.
                        producer_positions = [self._position(previous)]
                        if (previous.opname in {'STORE_FAST', 'STORE_NAME'} and previous_index > 0
                                and instructions[previous_index - 1].opname == 'COPY'
                                and instructions[previous_index - 1].arg == 1):
                            # A named assignment copies the tested value before
                            # storing it. COPY retains the assignment's own
                            # truth-conversion boundary on CPython 3.11.
                            previous_index -= 1
                            previous = instructions[previous_index]
                            producer_positions.append(self._position(previous))
                        # Value-preserving `a or b` / `a and b` use COPY then
                        # TO_BOOL before jumping, with the whole BoolOp span.
                        # Follow only these verified stack-transparent steps;
                        # the real value producer keeps the operand's span.
                        negations = 0
                        unsupported_negation = None
                        while previous_index > 0 and (previous.opname in {'TO_BOOL', 'UNARY_NOT'}
                                or previous.opname == 'COPY' and previous.arg == 1):
                            negations += previous.opname == 'UNARY_NOT'
                            if previous.opname == 'UNARY_NOT' and self._position(previous) in catalog.compound_negations:
                                unsupported_negation = self._position(previous)
                            previous_index -= 1
                            previous = instructions[previous_index]
                            producer_positions.append(self._position(previous))
                        if unsupported_negation is not None:
                            # The value may be an earlier short-circuited
                            # comparison. Aggregate bytecode edge hits cannot
                            # prove which comparison supplied it. Refuse this
                            # unsupported correlation instead of inventing a hit.
                            catalog.unsupported.append(('value-preserving compound negation', unsupported_negation))
                            continue
                        for producer in producer_positions:
                            producer = catalog.resolve_alias(producer)
                            candidate = (*producer, condition[-1])
                            if candidate in catalog.tests:
                                site = candidate
                                break
                        if site not in catalog.tests and previous.opname in {
                                'STORE_FAST_LOAD_FAST', 'LOAD_FAST_BORROW_LOAD_FAST_BORROW', 'LOAD_FAST_LOAD_FAST'}:
                            loaded = previous.argval
                            if type(loaded) is tuple and len(loaded) == 2:
                                candidates = [value for value, operand in catalog.test_names.items()
                                              if operand == loaded[1] and position[:2] <= value[:2]
                                              and value[2:4] <= position[2:]]
                                if len(candidates) == 1:
                                    site = candidates[0]
                        if site not in catalog.tests and instruction.opname.endswith(('IF_NONE', 'IF_NOT_NONE')):
                            # A fused STORE_FAST_LOAD_FAST can retain only the
                            # target span. Its exact interpreter-supplied name
                            # tuple still identifies a unique explicit None
                            # filter in this comprehension. Ambiguity refuses
                            # the mapping instead of choosing a favourable hit.
                            loaded = previous.argval
                            if previous.opname == 'STORE_FAST_LOAD_FAST' and type(loaded) is tuple and len(loaded) == 2:
                                loaded = loaded[1]
                            elif previous.opname not in {'LOAD_FAST', 'LOAD_FAST_BORROW', 'LOAD_NAME'}:
                                loaded = None
                            candidates = [value for owner, operand, value in catalog.comprehension_none
                                          if operand == loaded and owner[:2] <= position[:2] and position[2:] <= owner[2:]]
                            if len(candidates) == 1:
                                site = candidates[0]
                        if site in catalog.tests:
                            none_is_true = catalog.none_tests.get(site[:4])
                            if none_is_true is not None and instruction.opname.endswith(('IF_NONE', 'IF_NOT_NONE')):
                                truth = none_is_true == instruction.opname.endswith('IF_NONE')
                            if negations % 2:
                                truth = not truth
                            mappings[branch] = ('truth', site, truth)
            self.source_maps[name] = mappings

    @staticmethod
    def _position(instruction):
        value = instruction.positions
        return (value.lineno, value.col_offset, value.end_lineno, value.end_col_offset)

    def _async_observation(self, frame, code, offset):
        info = self._info(code)
        if info is None:
            return False
        row, key, _ = info
        metadata = self.async_maps.get((self.filenames[code.co_filename], key))
        if metadata is None:
            return False
        identity = id(frame)
        if frame.f_code is not code:
            raise ValueError('source monitoring frame ownership mismatch')
        pending = self.async_pending.get(identity)
        if pending is not None and (offset == pending[1] if self.monitoring is None else offset >= pending[1]):
            # Instruction monitoring may skip a fused LOAD_FAST on 3.14. The
            # first observed normal instruction after END_ASYNC_FOR suffices;
            # RAISE/RERAISE/UNWIND clear the marker on an exceptional path.
            row['source_event_hits'].add(pending[2])
            self.async_pending.pop(identity)
        ready = metadata['ready'].get(offset)
        if ready is not None:
            row['source_event_hits'].add(ready)
        end = metadata['end'].get(offset)
        if end is not None:
            # Keep the frame only until the next normal instruction or unwind.
            # Seeing END_ASYNC_FOR alone is insufficient: a non-StopAsyncIteration
            # exception must propagate without inventing an exhaustion outcome.
            self.async_pending[identity] = (frame, *end)
        # Keep events active in these few async-loop code objects so a later
        # invocation cannot lose its post-END instruction to earlier DISABLEs.
        return True

    def _instruction(self, code, offset):
        result = super()._instruction(code, offset)
        if self._async_observation(sys._getframe(1), code, offset):
            return None
        return result

    def _async_clear(self, code, *unused):
        frame = sys._getframe(1)
        if frame.f_code is code:
            self.async_pending.pop(id(frame), None)

    def _trace(self, frame, event, arg):
        result = super()._trace(frame, event, arg)
        if event == 'opcode':
            self._async_observation(frame, frame.f_code, frame.f_lasti)
        elif event in ('exception', 'return'):
            self.async_pending.pop(id(frame), None)
        return result

    def __enter__(self):
        super().__enter__()
        if self.monitoring is not None:
            for name in ('RAISE', 'RERAISE', 'PY_UNWIND'):
                event = getattr(self.monitoring.events, name)
                self.callbacks[event] = self._async_clear
                self.monitoring.register_callback(self.tool_id, event, self._async_clear)
            self.monitoring.set_events(self.tool_id, sum(self.callbacks))
        return self

    def __exit__(self, *exception):
        try:
            return super().__exit__(*exception)
        finally:
            self.async_pending.clear()

    def report(self):
        raw = super().report()
        result = copy.deepcopy(raw)
        result['raw_python'] = raw
        result['line_projection_runtime'] = list(sys.version_info[:3])
        incomplete = []
        for module in result['modules']:
            name = os.path.normcase(str(self.root / module['module']))
            row = self.rows[name]
            lines = self.implementation_lines[name]
            module['metrics']['lines'], module['missing_lines'] = lines.measure(module)
            module['line_projection'] = lines.ledger()
            catalog = self.source_catalogs[name]
            mappings = self.source_maps[name]
            branch_total = {('truth', site, value) for site in catalog.tests for value in (False, True)}
            branch_total.update(('iteration', site, value) for site in catalog.loops for value in (False, True))
            condition_total = {(site, value) for site in catalog.tests for value in (False, True)}
            branch_hits, condition_hits, mapped = set(), set(), set()
            for branch, (kind, site, truth_on_jump) in mappings.items():
                mapped.add((kind, site))
                for outcome in (False, True):
                    if (branch, outcome) in row['branch_hits']:
                        value = not outcome if kind == 'iteration' else outcome == truth_on_jump
                        branch_hits.add((kind, site, value))
                        if kind == 'truth':
                            condition_hits.add((site, value))
            for site, value in row['source_event_total']:
                mapped.add(('iteration', site))
                if (site, value) in row['source_event_hits']:
                    branch_hits.add(('iteration', site, value))
            required = {(kind, site) for kind, site, _ in branch_total}
            missing_mapping = sorted(required - mapped)
            incomplete.extend((module['module'], *entry) for entry in missing_mapping)
            incomplete.extend((module['module'], *entry) for entry in catalog.unsupported)
            module['metrics']['branches'] = self._measure(len(branch_hits), len(branch_total))
            module['metrics']['boolean_conditions'] = self._measure(len(condition_hits), len(condition_total))
            module['missing_branches'] = sorted(branch_total - branch_hits)
            module['missing_branch_locations'] = [
                {'kind': kind, 'position': site[:4], 'element': site[4] if kind == 'truth' else None,
                 'outcome': value} for kind, site, value in sorted(branch_total - branch_hits)]
            module['missing_boolean_conditions'] = sorted(condition_total - condition_hits)
            module['unmapped_source_decisions'] = missing_mapping
            module['source_branch_units'] = [
                {'kind': kind, 'site': site, 'observed': [value for value in (False, True)
                                                       if (kind, site, value) in branch_hits]}
                for kind, site in sorted(required)]
            module['source_boolean_units'] = [
                {'site': site, 'observed': [value for value in (False, True) if (site, value) in condition_hits]}
                for site in sorted(catalog.tests)]
        def aggregate(modules):
            return {metric: self._measure(sum(row['metrics'][metric]['covered'] for row in modules),
                                          sum(row['metrics'][metric]['total'] for row in modules))
                    for metric in METRICS}
        result['global'] = aggregate(result['modules'])
        result['components'] = {component: aggregate([row for row in result['modules']
                                                     if row['module'].split('/')[0] == component])
                                for component in result['components']}
        result['schema_version'] = 6
        result['definitions']['lines'] = 'runtime executable-line union of source implementations; verified typing.Protocol declaration bodies distinguished; actual line events only; raw Python evidence retained unchanged'
        result['definitions']['branches'] = 'source control-flow truth-test and iteration outcomes; AST inventory; actual edge observations; compiler-only edges retained separately'
        result['definitions']['boolean_conditions'] = 'source elementary truth-test outcomes; chained comparisons and short-circuit operands distinct; no inference for skipped evaluations; not MC/DC'
        result['source_mapping_complete'] = not incomplete
        result['unmapped_source_decisions'] = incomplete
        result['raw_python_gate_failures'] = raw_gate(raw)
        return result


def gate(report, threshold=98):
    """Preserve the five original checks and also refuse incomplete mappings."""
    failures = raw_gate(report, threshold)
    if report.get('source_mapping_complete') is not True or report.get('unmapped_source_decisions') != []:
        failures.append('source decision mapping incomplete or absent')
    raw = report.get('raw_python')
    if not isinstance(raw, dict) or raw.get('schema_version') != 4:
        failures.append('raw Python observation evidence missing or incompatible')
    else:
        # The user selected source decisions for admission, while raw Python
        # counters must remain complete and well formed. Their lower coverage
        # remains visible; malformed counters are never silently accepted.
        raw_failures = raw_gate(raw, threshold)
        endings = tuple(': ' + metric + ' below ' + str(threshold) + '%' for metric in METRICS)
        failures.extend('raw Python: ' + failure for failure in raw_failures if not failure.endswith(endings))
        pairs = [('global', report.get('global', {}), raw.get('global', {}))]
        for component, metrics in report.get('components', {}).items():
            pairs.append((component, metrics, raw.get('components', {}).get(component, {})))
        raw_modules = {row.get('module'): row for row in raw.get('modules', [])}
        for row in report.get('modules', []):
            pairs.append((row.get('module'), row.get('metrics', {}),
                          raw_modules.get(row.get('module'), {}).get('metrics', {})))
        for scope, primary, original in pairs:
            for metric in (('statements', 'functions') if report.get('schema_version') == 6 else ('statements', 'lines', 'functions')):
                if primary.get(metric) != original.get(metric):
                    failures.append('source/raw observation mismatch: ' + metric + ' in ' + scope)
        if report.get('schema_version') == 6:
            failures.extend(_line_projection_failures(report, raw))
        elif report.get('schema_version') != 5:
            failures.append('source coverage schema missing or incompatible')
        expected = {(row.get('module'), row.get('sha256')) for row in report.get('modules', [])}
        actual = {(row.get('module'), row.get('sha256')) for row in raw.get('modules', [])}
        if expected != actual:
            failures.append('source/raw module identity mismatch')
    return failures
