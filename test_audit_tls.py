"""Controlled TLS observations: independent handshakes never share identity by assumption."""
import copy
import datetime as dt
import hashlib
import json
import ssl
import subprocess
import unittest
import warnings
from dataclasses import asdict
from types import SimpleNamespace
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

import tls_scanner as tls
from adapters import convert_tls_results_to_findings
from main import run_pipeline
from scan_comparison import compare_scans
from scan_results import render_markdown


def certificate(serial):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'fixture.example')])
    now = dt.datetime.now(dt.UTC)
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(serial)
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=20)).sign(key, hashes.SHA256()))


class Socket:
    def __init__(self, der, version='TLSv1.3', cipher='TLS_AES_256_GCM_SHA384', peer='192.0.2.1'):
        self.der, self.protocol, self.name, self.peer = der, version, cipher, peer

    def __enter__(self): return self
    def __exit__(self, *args): return False
    def getpeercert(self, binary_form=False): return self.der
    def getpeername(self): return self.peer, 443
    def version(self): return self.protocol
    def cipher(self): return self.name, self.protocol, 256
    def selected_alpn_protocol(self): return None


class TLSAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cert_a, cls.cert_b = certificate(1), certificate(2)
        cls.der_a = cls.cert_a.public_bytes(serialization.Encoding.DER)
        cls.der_b = cls.cert_b.public_bytes(serialization.Encoding.DER)

    def scan(self, trust_der=None, group_cert=True, group_der=None, deep=False):
        der = self.der_a if group_der is None else group_der
        pem = ssl.DER_cert_to_PEM_cert(der).encode() if group_cert else b''
        def command(cmd, **kwargs):
            if cmd[-1] == 'version':
                return SimpleNamespace(returncode=0, stdout=b'OpenSSL 3.5.0\n', stderr=b'')
            return SimpleNamespace(returncode=0, stdout=pem + b'\nNegotiated TLS1.3 group: X25519MLKEM768\n', stderr=b'')
        calls = [Socket(self.der_a), Socket(trust_der or self.der_a, peer='192.0.2.2')]
        calls += [Socket(self.der_a, version=v) for v in ('TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3')]
        with patch('tls_scanner._connect', side_effect=calls), patch('tls_scanner.shutil.which', return_value='/mock/openssl'), patch('tls_scanner.subprocess.run', side_effect=command):
            return tls.scan_tls('fixture.example', deep=deep)

    def test_independent_probes_match_only_observed_leaf_fingerprints(self):
        for trust, group, expected in ((self.der_a, self.der_a, 'matched'),
                                        (self.der_b, self.der_b, 'mismatched')):
            with self.subTest(correlation=expected):
                data = self.scan(trust, group_der=group)
                probes = {p['stage']: p for p in data['probes']}
                main, validation, group_probe = (probes[k] for k in ('inspection', 'system_trust', 'key_exchange'))
                self.assertEqual(validation['correlation_to_inspection'], expected)
                self.assertEqual(group_probe['correlation_to_inspection'], expected)
                self.assertEqual(main['certificate_fingerprint_sha256'], hashlib.sha256(self.der_a).hexdigest())
                self.assertEqual(validation['peer_address'], '192.0.2.2')
                self.assertNotEqual(main['id'], group_probe['id'])
                for probe in data['probes']:
                    for field in ('id', 'stage', 'timestamp', 'endpoint', 'client', 'outcome', 'attribution'):
                        self.assertIn(field, probe)
                self.assertIsNone(data['key_exchange']['post_quantum_or_hybrid_group'])
                self.assertTrue(data['key_exchange']['probe_post_quantum_or_hybrid_group'])
                self.assertTrue(data['supported_protocols']['TLSv1.0'])

    def test_missing_group_leaf_keeps_identity_unknown_and_main_kx_unassessed(self):
        data = self.scan(group_cert=False)
        self.assertEqual(data['key_exchange']['correlation_to_inspection'], 'unknown')
        findings = convert_tls_results_to_findings(data)
        main = next(f for f in findings if f.id == 'tls-kx-fixture.example')
        group = next(f for f in findings if f.attributes.get('probe_id') == data['key_exchange']['group_probe_id'])
        self.assertIn('Unknown', main.algorithm)
        self.assertIsNone(main.attributes['group'])
        self.assertIn('#', group.asset)
        self.assertEqual(group.attributes['correlation_to_inspection'], 'unknown')
        with patch('main.scan_tls', return_value=data):
            report = run_pipeline(host='fixture.example')
        pq = [a for a in report['risk_assessment']['assessments'] if a['rule_id'] == 'PQC_HYBRID_KEM_DEPLOYED']
        self.assertTrue(pq)
        self.assertTrue(all('#' in a['asset'] for a in pq))
        self.assertIsNone(report['risk_assessment']['summary']['readiness_score'])

    def test_certificate_boundaries_and_probe_diagnostics_reach_markdown(self):
        data = self.scan(trust_der=self.der_b)
        self.assertEqual(data['coverage']['certificate_inspection'], 'leaf_only')
        self.assertEqual(data['coverage']['full_chain_inventory'], 'unassessed')
        self.assertEqual(data['coverage']['revocation'], 'not_checked')
        with patch('main.scan_tls', return_value=data):
            report = run_pipeline(host='fixture.example')
        markdown = render_markdown(report)
        for phrase in ('leaf_only', 'system_trust', 'unassessed', 'not_checked', 'mismatched', 'key_exchange'):
            self.assertIn(phrase, markdown)
        self.assertNotIn('BEGIN CERTIFICATE', json.dumps(report))

    def test_openssl_unavailable_timeout_and_errors_have_safe_provenance(self):
        with patch('tls_scanner.shutil.which', return_value=None):
            missing = tls._openssl_probe('fixture.example', 443, .01)
        self.assertEqual(missing['outcome'], 'unknown')
        self.assertEqual(missing['error_category'], 'client_unavailable')
        for error, expected in ((subprocess.TimeoutExpired('SYNTHETIC_PRIVATE', 1), 'timeout'),
                                (OSError('SYNTHETIC_PRIVATE'), 'transport_error')):
            with patch('tls_scanner.shutil.which', return_value='/mock/openssl'), patch('tls_scanner.subprocess.run', side_effect=error):
                probe = tls._openssl_probe('fixture.example', 443, .01)
            self.assertEqual(probe['outcome'], 'unknown')
            self.assertEqual(probe['error_category'], expected)
            self.assertNotIn('SYNTHETIC_PRIVATE', json.dumps(probe))

    def test_protocol_remote_rejection_is_distinct_from_local_failure(self):
        for error, expected in ((ssl.SSLError('TLSV1_ALERT_PROTOCOL_VERSION'), False),
                                (ssl.SSLError('NO_CIPHERS_AVAILABLE'), None),
                                (ssl.SSLError('unexpected eof while reading'), None),
                                (TimeoutError(), None)):
            with self.subTest(error=error), patch('tls_scanner._connect', side_effect=error):
                self.assertTrue(all(v is expected for v in tls.probe_protocol_versions('fixture.example', 443, .01).values()))

    def test_legacy_probe_intent_does_not_emit_expected_deprecation_warning(self):
        with warnings.catch_warnings(record=True) as recorded:
            warnings.simplefilter('always')
            context = tls._make_context(False, 'TLSv1')
        self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1)
        self.assertFalse([w for w in recorded if issubclass(w.category, DeprecationWarning)])

    def enum(self, errors, **kwargs):
        candidates = [{'name': 'AES128-SHA', 'protocol': 'TLSv1.0', 'strength_bits': 128},
                      {'name': 'AES256-SHA', 'protocol': 'TLSv1.0', 'strength_bits': 256}]
        context = SimpleNamespace(get_ciphers=lambda: candidates)
        with patch('tls_scanner._make_context', return_value=context), patch('tls_scanner._connect', side_effect=errors):
            return tls.enumerate_tls12_ciphers('fixture.example', 443, .01, detailed=True, **kwargs)

    def test_enumeration_preserves_unknowns_remote_rejection_and_counts(self):
        for error, outcome, category in ((TimeoutError(), 'unknown', 'timeout'),
                (OSError('SYNTHETIC_PRIVATE'), 'unknown', 'transport_error'),
                (ssl.SSLError('NO_CIPHERS_AVAILABLE'), 'unknown', 'local_unsupported'),
                (ssl.SSLError('SSLV3_ALERT_HANDSHAKE_FAILURE'), 'rejected', 'remote_negotiation_refused')):
            with self.subTest(outcome=outcome, error=error):
                result = self.enum([Socket(self.der_a, 'TLSv1.2', 'AES128-SHA'), error])
                self.assertEqual(result['candidate_count'], 2)
                self.assertEqual(result['attempted_count'], 2)
                self.assertEqual(result['attempts'][1]['outcome'], outcome)
                self.assertEqual(result['attempts'][1]['error_category'], category)
                self.assertEqual(result['accepted'][0]['name'], 'AES128-SHA')
                self.assertEqual(result['status'], 'partial' if outcome == 'unknown' else 'complete')
                self.assertNotIn('SYNTHETIC_PRIVATE', json.dumps(result))

    def test_enumeration_budget_and_local_context_failure_are_partial(self):
        result = self.enum([TimeoutError()], max_attempts=1)
        self.assertEqual(result['attempted_count'], 1)
        self.assertEqual(result['candidate_count'], 2)
        self.assertEqual(result['status'], 'partial')
        with patch('tls_scanner._make_context', side_effect=ssl.SSLError('SYNTHETIC_PRIVATE')):
            failed = tls.enumerate_tls12_ciphers('fixture.example', 443, .01, detailed=True)
        self.assertEqual(failed['status'], 'partial')
        self.assertEqual(failed['error_category'], 'local_unsupported')
        self.assertNotIn('SYNTHETIC_PRIVATE', json.dumps(failed))

    def test_complete_deep_coverage_compares_but_narrow_or_unknown_does_not(self):
        data = self.scan()
        enumeration = self.enum([Socket(self.der_a, 'TLSv1.2', 'AES128-SHA'), ssl.SSLError('SSLV3_ALERT_HANDSHAKE_FAILURE')])
        data['cipher_enumeration'] = enumeration
        data['supported_tls12_ciphers'] = enumeration['accepted']
        with patch('main.scan_tls', return_value=data):
            report = run_pipeline(host='fixture.example', deep_tls=True)
        # Main KX remains unknown, so use assessments only to isolate enumeration comparability.
        report['risk_assessment']['summary'].update(unknown_count=0, coverage={'status': 'complete'})
        self.assertEqual(compare_scans(report, copy.deepcopy(report))['status'], 'unchanged')
        after = copy.deepcopy(report)
        after['modules']['tls_scanner']['supported_tls12_ciphers'] = []
        after_enum = after['modules']['tls_scanner']['cipher_enumeration']
        after_enum['accepted'] = []
        after_enum.update(accepted_count=0, rejected_count=2)
        after_enum['attempts'][0].update(outcome='rejected', error_category='remote_negotiation_refused')
        # Remove the risk attributable to an accepted weak suite. Full recorded
        # remote rejections, including an empty accepted list, can compare.
        weak = {'finding_id': 'weak-suite', 'asset': 'fixture.example:443', 'algorithm': 'AES-128-CBC',
                'rule_id': 'WEAK_SUITE', 'severity': 'high', 'track': 'conventional'}
        report['risk_assessment']['assessments'].append(weak)
        self.assertEqual(compare_scans(report, after)['status'], 'improved')
        for field, value in (('status', 'partial'), ('candidate_count', 1), ('attempted_count', 1)):
            after = copy.deepcopy(report)
            after['modules']['tls_scanner']['cipher_enumeration'][field] = value
            self.assertEqual(compare_scans(report, after)['status'], 'inconclusive')

    def test_nonzero_openssl_exit_does_not_promote_partial_group_output(self):
        output = b'Negotiated TLS1.3 group: X25519MLKEM768\n'
        with patch('tls_scanner.shutil.which', return_value='/mock/openssl'), patch('tls_scanner.subprocess.run', return_value=SimpleNamespace(returncode=1, stdout=output, stderr=b'SYNTHETIC_PRIVATE')):
            probe = tls._openssl_probe('fixture.example', 443, .01)
        section = tls._key_exchange_section({'protocol': 'TLSv1.3'}, probe)
        self.assertIsNone(section['post_quantum_or_hybrid_group'])
        self.assertIsNone(section['group'])
        self.assertNotIn('SYNTHETIC_PRIVATE', json.dumps(probe))

    def test_main_failure_preserves_safe_probe_diagnostic(self):
        with patch('tls_scanner._connect', side_effect=OSError('SYNTHETIC_PRIVATE')):
            data = tls.scan_tls('fixture.example')
        self.assertEqual(data['probes'][0]['error_category'], 'transport_error')
        self.assertNotIn('SYNTHETIC_PRIVATE', json.dumps(data))

    def test_inconclusive_or_different_identity_probes_propagate_partial_status(self):
        for data in (self.scan(trust_der=self.der_b), self.scan(group_cert=False),
                     self.scan(group_der=self.der_b)):
            self.assertEqual(data['scan_status'], 'partial')
            self.assertTrue(data['errors'])

    def test_probe_provenance_loss_unknown_and_invented_complete_enum_block_comparison(self):
        data = self.scan()
        with patch('main.scan_tls', return_value=data):
            report = run_pipeline(host='fixture.example')
        report['risk_assessment']['summary'].update(unknown_count=0, coverage={'status': 'complete'})
        for mutation in ('lost', 'unknown', 'mismatched'):
            after = copy.deepcopy(report)
            probes = after['modules']['tls_scanner']['probes']
            if mutation == 'lost':
                probes.pop()
            elif mutation == 'unknown':
                probes[-1]['outcome'] = 'unknown'
            else:
                probes[-1]['correlation_to_inspection'] = 'mismatched'
            self.assertEqual(compare_scans(report, after)['status'], 'inconclusive')
        for scan in (report,):
            scan['metadata']['scan_options']['deep_tls'] = True
            scan['modules']['tls_scanner']['cipher_enumeration'] = {
                'status': 'complete', 'candidate_names': ['AES128-SHA'],
                'candidate_count': 1, 'attempted_count': 1, 'unknown_count': 0,
                'attempts': [], 'scope': 'local_client_tls12_candidates', 'settings': {}}
        self.assertEqual(compare_scans(report, copy.deepcopy(report))['status'], 'inconclusive')

    def test_malformed_new_tls_records_are_rejected_as_client_input(self):
        with patch('main.scan_tls', return_value=self.scan()):
            report = run_pipeline(host='fixture.example')
        for field, bad in (('probes', [1]), ('probes', 'bad'), ('cipher_enumeration', []),
                           ('cipher_enumeration', {'attempts': [1]})):
            after = copy.deepcopy(report)
            after['modules']['tls_scanner'][field] = bad
            with self.subTest(field=field, value=bad), self.assertRaises(ValueError):
                compare_scans(report, after)


if __name__ == '__main__':
    unittest.main()
