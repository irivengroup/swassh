"""Public input bounds remain strict when redundant internal checks change."""
import unittest
from swassh import Host
from swassh.domain.inventory import MAX_HOSTS, InventoryError, normalize_hosts
from swassh.domain.transfers import host_directory


class SourceContractInvariantTests(unittest.TestCase):
    def test_record_cap_precedes_deduplication_at_the_actual_public_limit(self):
        self.assertEqual(MAX_HOSTS, 100000)
        host = Host('same')
        self.assertEqual(normalize_hosts(host for _ in range(MAX_HOSTS)), (host,))
        with self.assertRaisesRegex(InventoryError, 'too many input records'):
            normalize_hosts(host for _ in range(MAX_HOSTS + 1))
        with self.assertRaisesRegex(InventoryError, 'conflicting duplicate target'):
            normalize_hosts([Host('same', label='first'), Host('same', label='second')])

    def test_valid_endpoint_families_always_produce_a_nonempty_safe_directory_prefix(self):
        names = ('a', '_', '0', 'EXAMPLE.', 'café.example', '::', '::1',
                 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', 'fe80::1%eth0',
                 '.'.join(['a' * 63] * 3 + ['a' * 61]))
        directories = set()
        for name in names:
            with self.subTest(name=name):
                value = host_directory(Host(name))
                prefix, digest = value.rsplit('-', 1)
                self.assertTrue(prefix)
                self.assertLessEqual(len(prefix), 48)
                self.assertRegex(prefix, r'^[A-Za-z0-9_.-]+$')
                self.assertRegex(digest, r'^[0-9a-f]{32}$')
                directories.add(value)
        self.assertEqual(len(directories), len(names))
        for name in ('', '.', '..', 'bad host', '-bad', '/bad'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                Host(name)
