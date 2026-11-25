"""Independent SAST-v2 decision examples: an authority is not a candidate flag.

These in-memory cases exercise the approved C66 contract. Integration with the
real scanner, locked wheels and the trusted bootstrap is checked separately.
"""

import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import runpy
import unittest

API = runpy.run_path(str(Path(__file__).resolve().parents[1]/'scripts/sast_gate.py'))
ReviewPolicy, Refusal = API['ReviewPolicy'], API['Refusal']
NOW = datetime(2026, 11, 9, 12, tzinfo=timezone.utc)


def encode(value):
    """Test-side wire encoder, independent from the verifier's serializer."""
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def hash_bytes(raw):
    return hashlib.sha256(raw).hexdigest()


class SastReviewPolicyTests(unittest.TestCase):
    """Neither benign warnings nor dangerous code can approve themselves."""

    def setUp(self):
        self.sources = {'src/encoder.py': hash_bytes(b'import subprocess\n'),
                        'src/caller.py': hash_bytes(b'print("plain")\n'),
                        '.github/workflows/ci.yml': hash_bytes(b'needs: security\n')}
        self.toolchain = {'bandit': {'version': '1.9.4', 'wheel_sha256': hash_bytes(b'locked wheel')}}
        self.signal = {'filename': 'src/encoder.py', 'test_id': 'B404', 'line_number': 1,
                       'issue_severity': 'LOW', 'issue_confidence': 'HIGH',
                       'code': '1 import subprocess\n', 'issue_text': 'review subprocess usage'}
        counts = {'loc': 1, 'nosec': 0, 'skipped_tests': 0,
                  'CONFIDENCE.HIGH': 1, 'CONFIDENCE.MEDIUM': 0, 'CONFIDENCE.LOW': 0,
                  'CONFIDENCE.UNDEFINED': 0, 'SEVERITY.HIGH': 0, 'SEVERITY.MEDIUM': 0,
                  'SEVERITY.LOW': 1, 'SEVERITY.UNDEFINED': 0}
        empty = {key: (1 if key == 'loc' else 0) for key in counts}
        totals = {key: value+empty[key] for key, value in counts.items()}
        self.report = {'generated_at': '2026-11-09T12:00:00Z', 'errors': [],
                       'metrics': {'src/encoder.py': counts, 'src/caller.py': empty, '_totals': totals},
                       'results': [self.signal]}
        self.record = {'signal': self.signal, 'signal_sha256': hash_bytes(encode(self.signal)),
                       'source_sha256': self.sources['src/encoder.py'],
                       'assessment': 'warning-without-confirmed-defect', 'approved': True,
                       'confirmed_defect': False, 'open_risk': False,
                       'trust_boundary': 'Fixture uses constant argv text only; no execution input.',
                       'data_flow': 'Import -> list2cmdline -> return encoded text.',
                       'rationale': 'No process-launching call in the complete reviewed source.',
                       'positive_evidence': ['encoder-no-spawn.json'],
                       'negative_evidence': ['unsafe-shell-refusal.json'],
                       'limits': 'Example qualification only, not approval of a project warning.'}
        self.review = {'schema': 'swassh-sast-review/2', 'contract': 'SAST-v2',
                       'source_files': self.sources, 'toolchain': self.toolchain,
                       'reviewer': 'detached test authority; synthetic example',
                       'issued_at': '2026-11-09T11:00:00+00:00', 'expires_at': '2026-11-10T11:00:00+00:00',
                       'evidence': {'encoder-no-spawn.json': hash_bytes(b'zero spawns'),
                                    'unsafe-shell-refusal.json': hash_bytes(b'unsafe case refused')},
                       'records': [self.record]}

    def evaluate(self, raw_exit=1, anchor=None):
        raw = encode(self.review)
        authority = hash_bytes(raw) if anchor is None else anchor
        return ReviewPolicy(raw, authority, NOW).evaluate(self.sources, self.report, raw_exit, self.toolchain)

    def refuse(self, change, expected, raw_exit=1):
        change()
        with self.assertRaisesRegex(Refusal, expected):
            self.evaluate(raw_exit)

    def test_reviewed_pure_encoder_qualifies_security_and_preserves_raw_failure(self):
        result = self.evaluate()
        self.assertEqual(result, {'contract': 'SAST-v2', 'security_qualified': True,
                                 'raw_exit': 1, 'raw_findings': 1, 'individually_approved': 1,
                                 'publication_authorized': False})

    def test_no_alerts_requires_complete_scan_and_zero_exit(self):
        self.report['results'] = []
        for counts in self.report['metrics'].values():
            for key in counts:
                if key.startswith(('SEVERITY.', 'CONFIDENCE.')):
                    counts[key] = 0
        self.review['records'] = []
        result = self.evaluate(0)
        self.assertTrue(result['security_qualified'])
        self.assertEqual(result['raw_exit'], 0)
        self.assertFalse(result['publication_authorized'])

    def test_pending_benign_warning_is_refused(self):
        self.refuse(lambda: self.record.update(approved=False), 'pending review')

    def test_confirmed_defect_cannot_pass_even_when_called_false_positive(self):
        self.refuse(lambda: self.record.update(confirmed_defect=True, assessment='false-positive'), 'confirmed defect')

    def test_unresolved_risk_and_risk_accepted_are_refused(self):
        for change in ({'open_risk': True}, {'assessment': 'risk-accepted'}, {'approved': 1},
                       {'confirmed_defect': 0}, {'open_risk': 0}):
            with self.subTest(change=change):
                prior = dict(self.record)
                self.record.update(change)
                with self.assertRaisesRegex(Refusal, 'pending review'):
                    self.evaluate()
                self.record.clear()
                self.record.update(prior)

    def test_new_finding_cannot_inherit_an_old_review(self):
        self.refuse(lambda: self.report['results'].append(dict(self.signal, test_id='B602')), 'contradict raw findings')

    def test_changed_context_is_not_matched_by_rule_or_line_only(self):
        self.report['results'] = [dict(self.signal, code='1 subprocess.run(command)\n')]
        with self.assertRaisesRegex(Refusal, 'unknown'):
            self.evaluate()

    def test_caller_and_control_changes_invalidate_review(self):
        for name in ('src/caller.py', '.github/workflows/ci.yml'):
            with self.subTest(path=name):
                review = copy.deepcopy(self.review)
                self.sources[name] = hash_bytes(b'changed validation or caller')
                # Preserve the authority's previous inventory, not a shared dict.
                self.review = review
                with self.assertRaisesRegex(Refusal, 'caller or control changed'):
                    self.evaluate()
                self.setUp()

    def test_missing_report_fields_and_analysis_errors_refuse(self):
        for key in ('metrics', 'results', 'errors', 'generated_at'):
            with self.subTest(field=key):
                original = self.report.pop(key)
                with self.assertRaisesRegex(Refusal, 'raw Bandit report'):
                    self.evaluate()
                self.report[key] = original
        self.refuse(lambda: self.report.update(errors=[{'filename': 'src/encoder.py', 'reason': 'syntax'}]), 'analysis errors')

    def test_duplicate_json_keys_truncated_json_and_nan_are_refused(self):
        for raw in (b'{"records":[],"records":[]}', b'{"records":', b'{"value":NaN}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                ReviewPolicy(raw, hash_bytes(raw), NOW)

    def test_changed_tool_or_dependency_invalidates_review(self):
        prior = copy.deepcopy(self.review)
        self.toolchain['bandit']['version'] = 'changed'
        self.review = prior
        with self.assertRaisesRegex(Refusal, 'toolchain differs'):
            self.evaluate()

    def test_raw_exit_is_strict_and_cannot_hide_a_warning(self):
        for value in (0, 2, -9, True, '1', None):
            with self.subTest(exit=value), self.assertRaises(Refusal):
                self.evaluate(value)

    def test_omitted_added_and_alias_python_paths_are_refused(self):
        for path in ('src/omitted.py', 'src/../outside.py', 'src\\alias.py', '/src/absolute.py'):
            with self.subTest(path=path):
                self.report['metrics'][path] = self.report['metrics'].pop('src/caller.py')
                with self.assertRaisesRegex(Refusal, 'omitted or substituted'):
                    self.evaluate()
                self.report['metrics']['src/caller.py'] = self.report['metrics'].pop(path)

    def test_source_added_since_review_is_refused(self):
        self.review = copy.deepcopy(self.review)
        self.sources['scripts/unknown.py'] = hash_bytes(b'new caller')
        with self.assertRaisesRegex(Refusal, 'source, caller or control changed'):
            self.evaluate()

    def test_missing_extra_duplicate_and_unmatched_decisions_refuse(self):
        for records in ([], [self.record, self.record], [dict(self.record, signal_sha256='0'*64)]):
            with self.subTest(count=len(records)):
                self.review['records'] = records
                with self.assertRaises(Refusal):
                    self.evaluate()

    def test_signal_source_hash_must_match_the_complete_source_snapshot(self):
        self.refuse(lambda: self.record.update(source_sha256='0'*64), 'signal source differs')

    def test_candidate_cannot_change_its_approved_flag_under_an_old_anchor(self):
        self.record['approved'] = False
        external_anchor = hash_bytes(encode(self.review))
        self.record['approved'] = True
        with self.assertRaisesRegex(Refusal, 'externally approved'):
            self.evaluate(anchor=external_anchor)

    def test_missing_untrusted_and_stale_authority_is_refused(self):
        for anchor in ('', '0'*64, 'not-a-digest'):
            with self.subTest(anchor=anchor), self.assertRaises(Refusal):
                self.evaluate(anchor=anchor)
        for field, value in (('expires_at', '2026-11-09T12:00:00+00:00'),
                             ('issued_at', '2026-11-09T13:00:00+00:00'),
                             ('issued_at', '2026-11-09T11:00:00'), ('reviewer', '')):
            with self.subTest(field=field, value=value):
                prior = self.review[field]
                self.review[field] = value
                with self.assertRaises(Refusal):
                    self.evaluate()
                self.review[field] = prior

    def test_no_filter_or_suppression_may_remove_required_raw_metrics(self):
        for field in ('skipped_tests', 'nosec'):
            with self.subTest(field=field):
                self.report['metrics']['_totals'][field] = 1
                with self.assertRaisesRegex(Refusal, 'filtered'):
                    self.evaluate()
                self.report['metrics']['_totals'][field] = 0

    def test_bad_metric_counts_cannot_supply_a_complete_scan(self):
        for value in (True, -1, 1.0, None):
            with self.subTest(value=value):
                self.report['metrics']['_totals']['loc'] = value
                with self.assertRaises(Refusal):
                    self.evaluate()
        self.report['metrics']['_totals']['loc'] = 123
        with self.assertRaisesRegex(Refusal, 'contradict file inventory'):
            self.evaluate()

    def test_each_decision_requires_context_and_positive_and_negative_evidence(self):
        for field, value in (('trust_boundary', ''), ('data_flow', ''), ('rationale', ''), ('limits', ''),
                             ('positive_evidence', []), ('negative_evidence', ['unknown-proof'])):
            with self.subTest(field=field):
                original = self.record[field]
                self.record[field] = value
                with self.assertRaises(Refusal):
                    self.evaluate()
                self.record[field] = original

    def test_extra_self_reported_publication_fields_do_not_grant_a_waiver(self):
        for value in (True, False):
            self.review['production_ready'] = value
            with self.assertRaisesRegex(Refusal, 'review schema differs'):
                self.evaluate()


if __name__ == '__main__':
    unittest.main()
