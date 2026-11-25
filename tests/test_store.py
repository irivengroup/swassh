import json
import os
import tempfile
import threading
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from swassh import Host, Result, Status
from swassh.infrastructure.spool import ReportStore, initialize_store, store_operation
from swassh.application.contracts import RunSummary
from swassh.application.contracts import ResourcePlan


class StoreTests(unittest.TestCase):
    def test_bounded_json_values_preserve_unicode_line_separators(self):
        import io
        # These code points are legal JSON string content, not structural LF.
        value='prefix'+''.join(chr(code) for code in (0x85,0x2028,0x2029))+'suffix'
        store=object.__new__(ReportStore)
        for item in (value, {'nested':[value,'escaped\nline']}, [value,None,True,3]):
            with self.subTest(kind=type(item).__name__):
                stream=io.StringIO()
                store._value(stream,item,3)
                self.assertEqual(json.loads(stream.getvalue()),item)
                self.assertIn(value,stream.getvalue())

    def test_json_value_preserves_nested_pretty_indentation_and_escaped_newlines(self):
        import io
        store=object.__new__(ReportStore)
        stream=io.StringIO()
        store._value(stream,{'nested':[1,2]},3)
        self.assertEqual(stream.getvalue(),'{\n        "nested": [\n          1,\n          2\n        ]\n      }')
        stream=io.StringIO()
        store._value(stream,'escaped\nline',3)
        self.assertEqual(stream.getvalue(),'"escaped\\nline"')

    def test_bounded_json_write_failure_remains_visible(self):
        from unittest.mock import Mock
        stream=Mock()
        stream.write.side_effect=OSError('synthetic no space')
        with self.assertRaisesRegex(OSError,'synthetic no space'):
            object.__new__(ReportStore)._value(stream,{'one':[1,2]},2)

    def test_worker_protocol_and_formats(self):
        with tempfile.TemporaryDirectory() as directory:
            initialize_store(directory, 1024*1024, threading.Event())
            try:
                path, pid = store_operation("identity")
                self.assertEqual(pid, os.getpid())
                store_operation("append", [Result(Host("a", label="=cmd()"), Status.SUCCESS, stdout="@cmd"),
                                           Result(Host("b"), Status.FAILED, stderr="bad", exit_code=7, stderr_truncated=True),
                                           Result(Host("c"), Status.FAILED, stderr="other", exit_code=8)])
                counts = store_operation("summary")
                now = datetime.now(UTC)
                summary = RunSummary(3, counts, now, now, ResourcePlan(1, 1, 1, 1, 1), "run", pid, show_output=False)
                for format in ("json", "csv", "text"):
                    destination = Path(directory)/format
                    store_operation("export", destination, format, "x", summary)
                    self.assertTrue(destination.stat().st_size)
                data = json.loads((Path(directory)/"json").read_text())
                self.assertEqual(data["groups"]["failed"], ["b:22", "c:22"])
                self.assertIn("additional response groups", (Path(directory)/"text").read_text())
                self.assertIn("'=cmd()", (Path(directory)/"csv").read_text())
                with self.assertRaises(ValueError):
                    store_operation("not-an-operation")
                with self.assertRaises(ValueError):
                    store_operation("export", Path(directory)/"bad", "bad", "x", summary)
            finally:
                store_operation("close")

    def test_cancel_and_atomic_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ReportStore(directory, 1024*1024)
            try:
                store.append([Result(Host("a"), Status.SUCCESS)])
                now = datetime.now(UTC)
                summary = RunSummary(1, store.counts, now, now, ResourcePlan(1,1,1,1,1))
                destination = Path(directory)/"out"
                destination.write_text("previous")
                with patch("os.replace", side_effect=OSError), self.assertRaises(OSError):
                    store.export(destination, "json", "x", summary)
                self.assertEqual(destination.read_text(), "previous")
                store.cancel()
                with self.assertRaises(InterruptedError):
                    store.append([Result(Host("b"), Status.SUCCESS)])
                with self.assertRaises(InterruptedError):
                    store.export(destination, "json", "x", summary)
            finally:
                store.close()
