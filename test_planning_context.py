"""Business assumptions must change planning only, using stored server evidence."""
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import dashboard
from main import run_pipeline
from cbom import export_cbom
from scan_results import render_markdown
from scan_comparison import compare_scans


class PlanningContextTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        (root / 'app.py').write_text('from cryptography.hazmat.primitives.asymmetric import dh\nx = dh.generate_parameters(generator=2, key_size=2048)\n')
        self.result = run_pipeline(repo_path=str(root))
        self.finding = next(f for f in self.result['inventory']['findings'] if f['usage'] == 'key_exchange')
        self.scan_id = dashboard.record_scan_history(self.result, 'code')
        self.original = copy.deepcopy(self.result)

    def post(self, payload):
        handler = object.__new__(dashboard.DashboardRequestHandler)
        handler.path = '/api/reassess'
        data = json.dumps(payload).encode()
        handler.headers = {'Content-Length': str(len(data))}
        handler.rfile = io.BytesIO(data)
        responses = []
        handler.send_json = lambda status, body: responses.append((status, body))
        with patch('dashboard.run_pipeline', side_effect=AssertionError('must not scan')):
            handler.do_POST()
        return responses[0]

    def payload(self, **fields):
        return {'scan_id': self.scan_id, 'overrides': [{'finding_id': self.finding['id'], **fields}]}

    def test_defaults_are_explicit_assumptions(self):
        for f in self.result['inventory']['findings']:
            ctx = f.get('planning_context', {})
            self.assertEqual(set(ctx), {'data_lifetime_years', 'trust_lifetime_years', 'migration_years', 'exposure', 'criticality'})
            for key, entry in ctx.items():
                self.assertEqual(entry['provenance'], 'assumed')
                self.assertEqual(entry['value'], f[key])
                self.assertTrue(entry['rationale'])

    def test_retention_changes_mosca_without_mutating_source(self):
        low_status, low = self.post(self.payload(data_lifetime_years=1))
        high_status, high = self.post(self.payload(data_lifetime_years=30))
        self.assertEqual((low_status, high_status), (200, 200))
        def delta(scan):
            return next(a['threat_analysis']['mosca_delta'] for a in scan['risk_assessment']['assessments']
                        if a['finding_id'] == self.finding['id'] and a['threat_analysis']['model'] == 'hndl')
        self.assertEqual(delta(high) - delta(low), 29)
        self.assertEqual(dashboard.get_scan_by_id(self.scan_id), self.original)
        self.assertNotEqual(low['metadata']['scan_id'], high['metadata']['scan_id'])
        self.assertEqual(high['metadata']['parent_scan_id'], self.scan_id)
        self.assertEqual(high['metadata']['assessment_type'], 'planning_update')
        self.assertIn('reassessed_at', high['metadata'])
        for key in ('scan_started_at', 'scan_finished_at', 'ruleset_fingerprint'):
            self.assertEqual(high['metadata'][key], self.original['metadata'][key])
        self.assertEqual(high['modules'], self.original['modules'])

    def test_confirmed_zero_and_safe_exports(self):
        status, derived = self.post(self.payload(data_lifetime_years=0, migration_years=0))
        self.assertEqual(status, 200)
        f = next(f for f in derived['inventory']['findings'] if f['id'] == self.finding['id'])
        self.assertEqual(f['data_lifetime_years'], 0)
        self.assertEqual(f['migration_years'], 0)
        self.assertEqual(f['planning_context']['migration_years']['provenance'], 'user_confirmed')
        threat = next(a['threat_analysis'] for a in derived['risk_assessment']['assessments']
                      if a['finding_id'] == f['id'] and a['threat_analysis']['model'] == 'hndl')
        self.assertEqual(threat['migration_window'], 0)
        self.assertEqual(threat['data_shelf_life'], 0)
        self.assertIn('user_confirmed', json.dumps(derived))
        self.assertIn('user_confirmed', render_markdown(derived))
        self.assertIn('user_confirmed', json.dumps(export_cbom(derived)))
        comparison = compare_scans(self.original, derived)
        self.assertIn('Planning context', json.dumps(comparison))
        self.assertEqual(comparison['status'], 'inconclusive')
        self.assertFalse(comparison['remediation_verified'])

    def test_invalid_context_rejected(self):
        invalid = [-1, float('nan'), float('inf'), 10 ** 400, True, '30', None, 1001, {}, []]
        for value in invalid:
            with self.subTest(value=value):
                self.assertEqual(self.post(self.payload(data_lifetime_years=value))[0], 400)
        for override in ([], None, 'bad', {'finding_id': 'not-an-asset', 'migration_years': 1},
                         {'finding_id': self.finding['id'], 'algorithm': 'ML-KEM-768'},
                         {'finding_id': self.finding['id'], 'exposure': 'anything'},
                         {'finding_id': self.finding['id'], 'criticality': True}):
            self.assertEqual(self.post({'scan_id': self.scan_id, 'overrides': [override]})[0], 400)
        for payload in ({'scan_id': self.scan_id, 'overrides': {}},
                        {**self.payload(migration_years=1), 'rules': {}},
                        {**self.payload(migration_years=1), 'risk_assessment': {}},
                        {**self.payload(migration_years=1), 'inventory': {}},
                        {'scan_id': self.scan_id, 'overrides': self.payload(migration_years=1)['overrides'] * 2}):
            self.assertEqual(self.post(payload)[0], 400)

    def test_missing_and_stale_scan_ids(self):
        for sid in ('', 'stale', None):
            self.assertEqual(self.post({'scan_id': sid, 'overrides': []})[0], 404)

    def test_exact_rules_snapshot_survives_disk_change(self):
        with patch('risk_engine.RuleSet.load_from_file', side_effect=AssertionError('must not reread rules')):
            status, derived = self.post(self.payload(migration_years=1))
        self.assertEqual(status, 200)
        self.assertEqual(derived['metadata']['ruleset_fingerprint'], self.original['metadata']['ruleset_fingerprint'])
        stale = copy.deepcopy(self.original)
        stale['metadata']['ruleset_fingerprint'] = 'missing-exact-rules'
        stale_id = dashboard.record_scan_history(stale)
        self.assertEqual(self.post({'scan_id': stale_id, 'overrides': []})[0], 409)

    def test_unknown_evidence_stays_unknown(self):
        original = copy.deepcopy(self.original)
        original['metadata']['errors'].append({'module': 'tls_scanner', 'error': 'probe not performed'})
        original['modules']['tls_scanner'] = {'scan_status': 'partial', 'key_exchange': None,
            'probes': [{'id': 'old-probe', 'outcome': 'unknown', 'timestamp': '2026-01-01T00:00:00Z'}]}
        from scan_results import post_process_scan_result
        post_process_scan_result(original)
        scan_id = dashboard.record_scan_history(original)
        payload = self.payload(data_lifetime_years=1)
        payload['scan_id'] = scan_id
        status, derived = self.post(payload)
        self.assertEqual(status, 200)
        self.assertIsNone(derived['risk_assessment']['summary']['readiness_score'])
        self.assertEqual(derived['modules'], original['modules'])
        self.assertEqual(derived['metadata']['errors'], original['metadata']['errors'])

    def test_tls_nonobject_exchange_is_ignored(self):
        from adapters import convert_tls_results_to_findings
        self.assertEqual(convert_tls_results_to_findings({'target': {'host': 'example.invalid'}, 'key_exchange': ['bad']}), [])


if __name__ == '__main__':
    unittest.main()
