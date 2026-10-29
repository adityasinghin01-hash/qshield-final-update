"""Comparison must preserve source identity and never reward lost evidence."""
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from dashboard import compare_scans
from main import run_pipeline


class EvidenceComparisonTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir='/private/tmp')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.file = self.root/'source.py'

    def scan(self, source, **options):
        self.file.write_text(source)
        return run_pipeline(repo_path=str(self.root), **options)

    def test_line_changes_preserve_identity_and_duplicate_multiplicity(self):
        before = self.scan('def a():\n    hashlib.md5(data)\n    hashlib.md5(data)\n')
        after = self.scan('\n\ndef a():\n    hashlib.md5(data)\n')
        result = compare_scans(before, after)
        self.assertEqual(len(result['persistent_findings']), 1)
        self.assertEqual(len(result['resolved_findings']), 1)
        self.assertFalse(result['new_findings'])
        self.assertEqual(result['status'], 'improved')
        self.assertFalse(result['remediation_verified'])

    def test_different_functions_are_not_the_same_use(self):
        before = self.scan('def a():\n    hashlib.md5(data)\n')
        after = self.scan('def b():\n    hashlib.md5(data)\n')
        result = compare_scans(before, after)
        self.assertEqual(len(result['resolved_findings']), 1)
        self.assertEqual(len(result['new_findings']), 1)
        self.assertFalse(result['persistent_findings'])
        self.assertEqual(result['status'], 'changed')

    def test_function_reordering_and_generated_ids_do_not_change_identity(self):
        before = self.scan('def a():\n    hashlib.md5(data)\ndef b():\n    hashlib.sha1(data)\n')
        after = self.scan('def b():\n    hashlib.sha1(data)\ndef a():\n    hashlib.md5(data)\n')
        result = compare_scans(before, after)
        self.assertEqual(len(result['persistent_findings']), 2)
        self.assertFalse(result['resolved_findings'])
        self.assertFalse(result['new_findings'])

    def test_actual_same_scope_removal_can_improve_observed_findings(self):
        before = self.scan('hashlib.md5(data)')
        after = self.scan('print("No cryptographic call here")')
        result = compare_scans(before, after)
        self.assertEqual(result['status'], 'improved')
        self.assertTrue(result['scope_compatible'])
        self.assertIn('observ', result['status_note'].lower())

    def test_missing_source_file_never_establishes_improvement(self):
        before = self.scan('hashlib.md5(data)')
        self.file.unlink()
        after = run_pipeline(repo_path=str(self.root))
        result = compare_scans(before, after)
        self.assertEqual(result['status'], 'inconclusive')
        self.assertFalse(result['scope_compatible'])

    def test_incompatible_scope_settings_rules_and_demo_are_inconclusive(self):
        before = self.scan('hashlib.md5(data)')
        clean = self.scan('print("clean")')
        variants = []
        for key, value in [('scenario', 'relaxed'), ('is_demo', True),
                           ('ruleset_fingerprint', 'different')]:
            other = copy.deepcopy(clean)
            other['metadata'][key] = value
            variants.append(other)
        other = copy.deepcopy(clean)
        other['metadata']['targets']['repo'] = '/different/project'
        variants.append(other)
        other = copy.deepcopy(clean)
        other['modules']['code_scanner'] = None
        variants.append(other)
        other = copy.deepcopy(clean)
        other['modules']['code_scanner']['coverage']['settings']['quantum_only'] = True
        variants.append(other)
        other = copy.deepcopy(clean)
        other['modules']['code_scanner']['coverage']['capabilities'] = ['different analyzer']
        variants.append(other)
        for after in variants:
            with self.subTest(metadata=after['metadata']):
                result = compare_scans(before, after)
                self.assertEqual(result['status'], 'inconclusive')
                self.assertTrue(result['warnings'])

    def test_unknown_parameters_and_partial_evidence_block_improvement(self):
        before = self.scan('hashlib.md5(data)')
        for source in ('AESGCM(key)',
                       "hashlib.pbkdf2_hmac('sha256', password, salt, 600000)",
                       'def broken('):
            with self.subTest(source=source):
                result = compare_scans(before, self.scan(source))
                self.assertEqual(result['status'], 'inconclusive')

    def test_new_unsupported_file_blocks_improvement(self):
        before = self.scan('hashlib.md5(data)')
        (self.root/'New.java').write_text('class New {}')
        after = self.scan('print("clean")')
        self.assertEqual(compare_scans(before, after)['status'], 'inconclusive')

    def test_narrower_filter_cannot_look_like_remediation(self):
        before = self.scan('hashlib.md5(data)')
        after = self.scan('hashlib.md5(data)', quantum_only=True)
        self.assertEqual(compare_scans(before, after)['status'], 'inconclusive')

    def test_kdf_change_keeps_unknown_salt_inconclusive(self):
        before = self.scan("hashlib.pbkdf2_hmac('sha256', password, salt, 1)")
        after = self.scan("hashlib.pbkdf2_hmac('sha256', password, salt, 600000)")
        result = compare_scans(before, after)
        self.assertTrue(any(a['rule_id'] == 'WEAK_KDF_PARAMETERS' for a in result['resolved_findings']))
        self.assertEqual(result['status'], 'inconclusive')

    def test_legacy_reports_without_coverage_are_conservatively_matched(self):
        before = {'metadata': {'targets': {'repo': '/repo'}},
                  'risk_assessment': {'summary': {}, 'assessments': [
                      {'finding_id': 'code-1', 'asset': '/repo/a.py:1', 'algorithm': 'MD5', 'rule_id': 'MD5'}]}}
        after = copy.deepcopy(before)
        after['risk_assessment']['assessments'][0].update(asset='/repo/a.py:20', finding_id='code-9')
        result = compare_scans(before, after)
        self.assertEqual(len(result['persistent_findings']), 1)
        self.assertEqual(result['status'], 'inconclusive')
        self.assertTrue(result['warnings'])

    def test_context_records_effective_rules_and_scan_options(self):
        report = self.scan('hashlib.md5(data)', ignore_comments=True)
        self.assertRegex(report['metadata']['ruleset_fingerprint'], r'^[a-f0-9]{64}$')
        self.assertTrue(report['metadata']['scan_options']['ignore_comments'])

    def test_missing_tls_evidence_cannot_look_like_remediation(self):
        telemetry = {'scan_status': 'ok', 'target': {'host': 'fixture.example', 'port': 443},
                     'connection': {'tls_version': 'TLSv1.3'},
                     'cipher_suite': {'name': 'TLS_AES_256_GCM_SHA384', 'secret_bits': 256},
                     'certificate': {'public_key': {'algorithm': 'RSA', 'key_size_bits': 1024},
                                     'subject': {}, 'signature': {'algorithm': 'sha256WithRSAEncryption'}}}
        with patch('main.scan_tls', return_value=telemetry):
            before = run_pipeline(host='fixture.example')
        missing = copy.deepcopy(telemetry)
        missing.pop('certificate')
        with patch('main.scan_tls', return_value=missing):
            after = run_pipeline(host='fixture.example')
        result = compare_scans(before, after)
        self.assertEqual(result['status'], 'inconclusive')
        self.assertTrue(any('TLS' in warning for warning in result['warnings']))

    def test_missing_protocol_probe_is_not_a_negative_probe(self):
        telemetry = {'scan_status': 'ok', 'target': {'host': 'fixture.example', 'port': 443},
                     'connection': {'tls_version': 'TLSv1.3'},
                     'supported_protocols': {'TLSv1.0': True, 'TLSv1.2': True, 'TLSv1.3': True}}
        with patch('main.scan_tls', return_value=telemetry):
            before = run_pipeline(host='fixture.example')
        missing = copy.deepcopy(telemetry)
        missing['supported_protocols'].pop('TLSv1.0')
        with patch('main.scan_tls', return_value=missing):
            after = run_pipeline(host='fixture.example')
        self.assertEqual(compare_scans(before, after)['status'], 'inconclusive')
        supported = copy.deepcopy(telemetry)
        supported['supported_protocols']['TLSv1.0'] = False
        with patch('main.scan_tls', return_value=supported):
            after = run_pipeline(host='fixture.example')
        self.assertEqual(compare_scans(before, after)['status'], 'improved')

    def test_arrow_functions_have_distinct_comparison_identity(self):
        self.file = self.root/'source.js'
        before = self.scan("const a=()=>{crypto.createHash('md5');};")
        after = self.scan("const b=()=>{crypto.createHash('md5');};")
        result = compare_scans(before, after)
        self.assertFalse(result['persistent_findings'])
        self.assertEqual(len(result['new_findings']), 1)
        self.assertEqual(len(result['resolved_findings']), 1)

    def test_malformed_nested_coverage_is_a_client_error(self):
        report = self.scan('hashlib.md5(data)')
        for bad in (None, [], 'bad'):
            after = copy.deepcopy(report)
            after['modules']['code_scanner']['coverage'] = bad
            with self.subTest(value=bad), self.assertRaises(ValueError):
                compare_scans(report, after)

    def test_malformed_nested_tls_is_a_client_error(self):
        with patch('main.scan_tls', return_value={'scan_status': 'ok', 'connection': {'tls_version': 'TLSv1.3'}}):
            report = run_pipeline(host='fixture.example')
        for field in ('connection', 'cipher_suite', 'certificate', 'certificate_validation',
                      'key_exchange', 'supported_protocols'):
            after = copy.deepcopy(report)
            after['modules']['tls_scanner'][field] = 1
            with self.subTest(field=field), self.assertRaises(ValueError):
                compare_scans(report, after)


if __name__ == '__main__':
    unittest.main()
