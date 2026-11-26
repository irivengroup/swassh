"""Public numeric validation must report invalid input before allocating I/O."""
from pathlib import Path
import unittest

from swassh import TransferSettings
from swassh.infrastructure.process_reporter import ProcessReportWriter


class TimeoutBoundaryTests(unittest.TestCase):
    def test_transfer_timeout_rejects_unrepresentable_integers_and_all_nonpositive_types(self):
        for value in (None,'1',True,0,-1,float('nan'),float('inf'),10**1000):
            with self.subTest(kind=type(value).__name__),self.assertRaisesRegex(ValueError,'finite and positive'):
                TransferSettings(timeout=value)
        for value in (1,0.125):self.assertEqual(TransferSettings(timeout=value).timeout,value)

    def test_reporter_timeout_rejects_unrepresentable_integers_before_starting_a_worker(self):
        for value in (None,'1',True,0,-1,float('nan'),float('inf'),10**1000):
            with self.subTest(kind=type(value).__name__),self.assertRaisesRegex(ValueError,'finite and positive'):
                ProcessReportWriter(Path('.'),1024,operation_timeout=value)
        writer=ProcessReportWriter(Path('.'),1024,operation_timeout=0.125)
        self.assertEqual(writer.operation_timeout,0.125);self.assertIsNone(writer._executor)
