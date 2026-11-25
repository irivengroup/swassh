import csv
import io
import json
import os
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

from swassh import (
    Host,
    Options,
    Report,
    Result,
    Status,
    load_inventory,
    normalize_hosts,
    parse_host,
)


class DomainTests(unittest.TestCase):
    def test_inventory_formats(self):
        cases = {
            "txt": "# comment\nnode\nalice@other:2222\nnode # duplicate\n",
            "csv": "hostname,port,username,label\nnode,22,,\nother,2222,alice,\n",
            "json": '{"hosts":["node",{"hostname":"other","port":2222,"username":"alice"}]}',
            "yaml": "hosts:\n  - node\n  - hostname: other\n    port: 2222\n    username: alice\n",
        }
        with tempfile.TemporaryDirectory() as directory:
            for suffix, content in cases.items():
                with self.subTest(suffix=suffix):
                    path = Path(directory) / f"hosts.{suffix}"
                    path.write_text(content, encoding="utf-8-sig")
                    self.assertEqual(
                        load_inventory(path),
                        (Host("node"), Host("other", 2222, "alice")),
                    )

    def test_inventory_rejects_unsafe_or_ambiguous(self):
        cases = [
            ("txt", "node extra"),
            ("yaml", "!!python/object/apply:os.system ['bad']"),
            ("yaml", "hosts: foo"),
            ("yaml", "- &a [*a]"),
            ("yaml", "hosts:\n- hostname: node\n  username: admin\n  username: other"),
            ("yaml", "- hostname: node\n  unknown: foo"),
            ("json", "{bad"),
            ("json", '{"hosts":[{"hostname":"node","password":"secret"}]}'),
            ("ini", "[all]\nnode"),
            ("csv", "host\nnode"),
            ("csv", "hostname,port\nnode,xx"),
        ]
        with tempfile.TemporaryDirectory() as directory:
            for suffix, content in cases:
                with self.subTest(content=content):
                    path = Path(directory) / f"hosts.{suffix}"
                    path.write_text(content)
                    with self.assertRaises(ValueError):
                        load_inventory(path)

    def test_inventory_quotes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "hosts.yaml"
            path.write_text(
                "hosts:\n- hostname: 'node'\n  label: \"Prod # 1\"\n- 'bob@[::1]:2222'\n"
            )
            self.assertEqual(load_inventory(path)[0].label, "Prod # 1")
            self.assertEqual(load_inventory(path)[1], Host("::1", 2222, "bob"))

    def test_duplicate_targets(self):
        self.assertEqual(normalize_hosts(["node", "node"]), (Host("node"),))
        for hosts in ([], [1], [Host("node", label="a"), Host("node", label="b")]):
            with self.subTest(hosts=hosts), self.assertRaises(ValueError):
                normalize_hosts(hosts)

    def test_compact_report_and_exports(self):
        now = datetime.now(UTC)
        results = tuple(
            Result(
                Host(f"host-{i}", label="=formula"),
                Status.SUCCESS,
                stdout="z" * 1000 + "\x1b[31m",
                exit_code=0,
            )
            for i in range(10000)
        )
        report = Report("x", results, now, now, "trace-id", show_output=False)
        self.assertTrue(report.ok)
        self.assertEqual(len(report.response_groups()), 1)
        output = report.to_text()
        self.assertLess(len(output.splitlines()), 15)
        self.assertLess(len(output), 1000)
        self.assertNotIn("\x1b", output)
        row = next(csv.DictReader(io.StringIO(report.to_csv())))
        self.assertEqual(row["label"], "'=formula")
        with tempfile.TemporaryDirectory() as directory:
            for format in ("json", "csv", "text"):
                path = Path(directory) / format
                report.write(path, format)
                self.assertTrue(path.stat().st_size)
                if os.name == "posix":
                    self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(ValueError):
                report.write(Path(directory) / "bad", "bad")
        self.assertEqual(json.loads(report.to_json())["run_id"], "trace-id")


def case_method(function, value):
    def method(self):
        function(self, value)

    return method


def invalid_option(self, item):
    with self.assertRaises(ValueError):
        Options(**item)


OPTIONS = [
    {"concurrency": 0},
    {"concurrency": True},
    {"concurrency": 10001},
    {"retries": -1},
    {"retries": 11},
    {"max_output_bytes": 0},
    {"connect_timeout": 0},
    {"command_timeout": float("nan")},
    {"command_timeout": float("inf")},
    {"retry_delay": -1},
    {"retry_delay": "1"},
    {"client_keys": []},
    {"client_keys": ("",)},
    {"known_hosts": ""},
    {"username": ""},
    {"jump_host": "node"},
    {"log_file": ""},
    {"connect_rate": 0},
    {"memory_budget_mib": 0},
    {"max_report_mib": 0},
    {"ssh_executable": ""},
]
for index, item in enumerate(OPTIONS):
    setattr(
        DomainTests,
        f"test_invalid_option_{index:02}",
        case_method(invalid_option, item),
    )


def parse_case(self, pair):
    self.assertEqual(parse_host(pair[0]), pair[1])
    self.assertEqual(parse_host(pair[1].target), pair[1])


HOSTS = [
    ("node", Host("node")),
    ("alice@node:2222", Host("node", 2222, "alice")),
    ("[2001:db8::1]:2222", Host("2001:db8::1", 2222)),
    ("2001:db8::1", Host("2001:db8::1")),
    ("bob@[::1]", Host("::1", username="bob")),
]
for index, item in enumerate(HOSTS):
    setattr(DomainTests, f"test_host_{index:02}", case_method(parse_case, item))


def invalid_host(self, value):
    with self.assertRaises(ValueError):
        parse_host(value)


for index, item in enumerate(
    [
        "",
        "[::1",
        "[::1]bad",
        "[::1]:x",
        "host:x",
        "-o bad",
        "x:0",
        "a@@b",
        "x:65536",
        "a;bad@node",
    ]
):
    setattr(
        DomainTests, f"test_invalid_host_{index:02}", case_method(invalid_host, item)
    )
