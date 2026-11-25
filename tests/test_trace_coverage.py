"""An opcode observer must preserve each pre-existing trace event mask."""
import importlib.util
from pathlib import Path
import runpy
import sys
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
ExecutionCoverage = runpy.run_path(str(ROOT / 'scripts/coverage_metrics.py'))['ExecutionCoverage']


class TraceCompositionOracles(unittest.TestCase):
    def exercise(self, *, threads=False):
        path = ROOT / 'tests/coverage_cases/choice.py'
        spec = importlib.util.spec_from_file_location('trace_composition_oracle', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        events = []

        def previous(frame, event, arg):
            if frame.f_code.co_filename == str(path):
                events.append(event)
                frame.f_trace_lines = False
                frame.f_trace_opcodes = False
                return previous
            return None

        old, old_thread = sys.gettrace(), threading.gettrace()
        try:
            if threads:
                threading.settrace(previous)
            else:
                sys.settrace(previous)
            with patch.object(sys, 'monitoring', None, create=True):
                with ExecutionCoverage(path.parent) as observer:
                    if threads:
                        values = []
                        worker = threading.Thread(target=lambda: values.append(module.choice(True, False)))
                        worker.start()
                        worker.join(timeout=5)
                        self.assertFalse(worker.is_alive())
                        self.assertEqual(values, [1])
                    else:
                        self.assertEqual(module.choice(True, False), 1)
            self.assertEqual(events, ['call', 'return'], 'the previous tracer did not request line/opcode events')
            self.assertEqual(observer.report()['global']['branches']['covered'], 1)
            self.assertEqual(observer.report()['global']['boolean_conditions']['covered'], 1)
            self.assertIs(threading.gettrace() if threads else sys.gettrace(), previous)
        finally:
            sys.settrace(old)
            threading.settrace(old_thread)

    def test_existing_main_thread_tracer_keeps_its_requested_events(self):
        self.exercise()

    def test_existing_new_thread_tracer_keeps_its_requested_events(self):
        self.exercise(threads=True)
