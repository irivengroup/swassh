"""Strict inventory grammar, bounded records and file-kind integration."""
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from swassh import Host
from swassh.infrastructure import inventory


class InventoryGrammarBoundaryTests(unittest.TestCase):
    def test_a_leading_quote_protects_its_hash_but_does_not_create_an_implicit_list(self):
        self.assertEqual(inventory._yaml_content("'one # literal' # comment"), "'one # literal'")
        with self.assertRaisesRegex(ValueError, 'hosts list or a top-level list'):
            inventory._yaml_records("'one # literal' # comment")

    def test_yaml_quotes_scalar_records_indentation_and_duplicate_root_rules(self):
        cases=(('- one\n- "two"\n- \'three\'\n',['one','two','three']),
               ('hosts:\n  - hostname: one\n    port: 2222\n    label: \'owner\'\'s node\'\n',
                [{'hostname':'one','port':2222,'label':"owner's node"}]),
               ('# comment\n\n- hostname: one\n  label: "quoted # value"\n',
                [{'hostname':'one','label':'quoted # value'}]),
               ('- hostname: one\n  label: owner\'s  node # comment\n',
                [{'hostname':'one','label':"owner's  node"}]),
               ('- hostname: one\n  label: "escaped \\\"quote\\\" and #" # comment\n',
                [{'hostname':'one','label':'escaped "quote" and #'}]),
               ("- hostname: one\n  label: 'here''s to \"quotes\"'\n",[{'hostname':'one','label':'''here's to "quotes"'''}]))
        for text,expected in cases:
            with self.subTest(text=text):self.assertEqual(inventory._yaml_records(text),expected)
        invalid=('\t- one','hosts:\nhosts:\n- one','- one\nhosts:', ' hosts:\n - one',
                 '- one\n  - two','hostname: one','- hostname: one\nlabel: value',
                 '- hostname: one\n  malformed field','- hostname: one\n  label:',
                 '- unknown: value','- hostname: one\n  hostname: two',
                 "- hostname: one\n  label: 'quoted' trailing",'- hostname: one\n  label: [flow]',
                 "- hostname: one\n  label: 'quoted' 'trailing'","- 'one' 'two'",'- "unclosed',"- 'unclosed",
                 '- hostname: one\n  label: &anchor','- hostname: one\n  label: !tag',
                 '- hostname: one\n  label: {flow}','- hostname: one\n  port: invalid')
        for text in invalid:
            with self.subTest(text=text),self.assertRaises(ValueError):inventory._yaml_records(text)

    def test_yaml_capacity_applies_to_scalar_and_mapping_records_before_normalization(self):
        self.assertEqual(inventory.MAX_HOSTS,100000)
        with patch.object(inventory,'MAX_HOSTS',2):
            for text in ('- one\n- two\n- three', '- hostname: one\n- hostname: two\n- hostname: three'):
                with self.assertRaisesRegex(ValueError,'too many YAML'):inventory._yaml_records(text)


class InventoryFileBoundaryTests(unittest.TestCase):
    def test_json_csv_txt_and_encoding_reject_ambiguous_records_with_a_typed_error(self):
        cases=(('json',b'{"other":[]}'),('json',b'{"hosts":true}'),('json',b'{"hosts":[[]]}'),
               ('json',b'{"hosts":[{"port":22}]}'),('json',b'{"hosts":[{"hostname":"one","port":false}]}'),
               ('json',b'{"hosts":[{"hostname":"one","label":NaN}]}'),('json',b'{"hosts":[],"hosts":[]}'),
               ('csv',b''),('csv',b'port\n22'),('csv',b'hostname,hostname\none,two'),
               ('csv',b'hostname,unknown\none,value'),('csv',b'hostname,port\none'),
               ('csv',b'hostname\none,extra'),('csv',b'hostname,port\none,bad'),
               ('txt',b'one two'),('txt',b'"unclosed'),('txt',b'\xff'),('txt',b'# empty\n'))
        with tempfile.TemporaryDirectory() as directory:
            for extension,raw in cases:
                path=Path(directory)/('inventory.'+extension);path.write_bytes(raw)
                with self.subTest(extension=extension,raw=raw),self.assertRaises(inventory.InventoryError):inventory.load_inventory(path)
            path=Path(directory)/'valid.JSON';path.write_text('["EXAMPLE",{"hostname":"other","port":2222}]',encoding='utf-8')
            self.assertEqual(inventory.load_inventory(path),(Host('example'),Host('other',2222)))

    def test_byte_record_and_file_kind_limits_are_checked_before_admission(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            path=root/'inventory.json';path.write_text(json.dumps(['one','two','three']),encoding='utf-8')
            with patch.object(inventory,'MAX_HOSTS',2),self.assertRaisesRegex(ValueError,'structured inventory'):inventory.load_inventory(path)
            for extension,raw in (('csv','hostname\none\ntwo\nthree'),('txt','one\ntwo\nthree')):
                path=root/('inventory.'+extension);path.write_text(raw,encoding='utf-8')
                with patch.object(inventory,'MAX_HOSTS',2),self.assertRaisesRegex(ValueError,'too many'):inventory.load_inventory(path)
            with patch.object(inventory,'MAX_INVENTORY_BYTES',4),self.assertRaisesRegex(ValueError,'10 MiB'):inventory.load_inventory(path)
            fake_os=SimpleNamespace(**vars(os));fake_os.fstat=lambda fd:SimpleNamespace(st_mode=stat.S_IFSOCK)
            with patch.object(inventory,'os',fake_os),self.assertRaisesRegex(ValueError,'regular file'):inventory.load_inventory(path)
            # The rejected read still closes its descriptor (observable on
            # Windows, where a leaked open descriptor prevents this rename).
            moved=path.with_name('closed.txt');path.rename(moved);self.assertTrue(moved.is_file())


class InventoryPortPrivacyTests(unittest.TestCase):
    """Malformed inventory values must stay out of errors and exception chains."""

    def test_malformed_ports_are_absent_from_errors_and_default_tracebacks(self):
        import traceback
        from swassh.domain.inventory import parse_host
        marker = 'synthetic-confidential-port-value-27'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            operations = []
            cases = (('csv', 'hostname,port\nnode,' + marker + '\n'),
                     ('yaml', '- hostname: node\n  port: ' + marker + '\n'),
                     ('txt', 'node:' + marker + '\n'),
                     ('ipv6.txt', '[::1]:' + marker + '\n'),
                     ('json', json.dumps({'hosts': ['node:' + marker]})),
                     ('scalar.yaml', '- node:' + marker + '\n'))
            for extension, text in cases:
                path = root / ('inventory.' + extension)
                path.write_text(text, encoding='utf-8')
                operations.append((extension, lambda path=path: inventory.load_inventory(path)))
            operations.extend((('host-port', lambda: parse_host('node:' + marker)),
                               ('ipv6-port', lambda: parse_host('[::1]:' + marker))))
            for name, operation in operations:
                with self.subTest(case=name):
                    with self.assertRaises(inventory.InventoryError) as raised:
                        operation()
                    error = raised.exception
                    self.assertEqual(str(error), 'invalid SSH port')
                    self.assertNotIn(marker, ''.join(traceback.format_exception(error)))
                    self.assertIsNone(error.__cause__)
                    self.assertIsNone(error.__context__)

    def test_valid_numeric_spellings_and_host_range_checks_remain_unchanged(self):
        from swassh.domain.inventory import parse_host
        spellings = (('22', 22), ('0022', 22), ('+22', 22), (' 22', 22),
                     ('2_222', 2222), ('２２', 22), ('65535', 65535))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for text, expected in spellings:
                with self.subTest(port=text):
                    self.assertEqual(parse_host('node:' + text), Host('node', expected))
                    for extension, content in (
                            ('csv', 'hostname,port\nnode,' + text + '\n'),
                            ('yaml', '- hostname: node\n  port: ' + text + '\n')):
                        path = root / ('valid.' + extension)
                        path.write_text(content, encoding='utf-8')
                        self.assertEqual(inventory.load_inventory(path), (Host('node', expected),))
            for text in ('0', '-1', '65536'):
                with self.subTest(port=text), self.assertRaises(inventory.InventoryError):
                    parse_host('node:' + text)
            path = root / 'typed.json'
            path.write_text(json.dumps([{'hostname': 'node', 'port': '22'}]), encoding='utf-8')
            with self.assertRaises(inventory.InventoryError):
                inventory.load_inventory(path)
