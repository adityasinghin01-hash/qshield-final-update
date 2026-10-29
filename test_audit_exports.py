"""Regressions for exact-scan exports and offline formal CBOM validation."""
import copy
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import cbom
import dashboard
from main import run_pipeline
from scan_results import render_markdown


class FormalValidationTests(unittest.TestCase):
    def setUp(self):
        self.bom = cbom.export_cbom(run_pipeline(repo_path='sample_vulnerable_app'))

    def test_default_schema_rejects_invalid_document(self):
        for change in ({'version': 'INVALID'}, {'components': [{'type': 'INVALID'}]}):
            with self.subTest(change=change):
                result, error = cbom.validate_cbom_schema({**self.bom, **change})
                self.assertIs(result, False)
                self.assertTrue(error)

    def test_generated_code_tls_and_iac_documents_formally_validate(self):
        reports = [run_pipeline(repo_path='sample_vulnerable_app'),
                   run_pipeline(repo_path='docs/examples/iac_sample', iac=True)]
        tls = {'scan_status': 'ok', 'target': {'host': 'fixture.example', 'port': 443},
               'connection': {'tls_version': 'TLSv1.3'},
               'certificate': {'public_key': {'algorithm': 'RSA', 'key_size_bits': 2048},
                               'subject': {}, 'signature': {'algorithm': 'sha256WithRSAEncryption'}}}
        with patch('main.scan_tls', return_value=tls):
            reports.append(run_pipeline(host='fixture.example'))
        for report in reports:
            with self.subTest(target=report['metadata']['targets']):
                valid, error = cbom.validate_cbom_schema(cbom.export_cbom(report))
                self.assertIs(valid, True, error)

    def test_missing_validator_is_not_formally_validated(self):
        with patch.dict('sys.modules', {'jsonschema': None}):
            valid, reason = cbom.validate_cbom_schema(self.bom)
        self.assertIsNone(valid)
        self.assertTrue(reason)

    def test_explicit_missing_schema_never_falls_back(self):
        with tempfile.TemporaryDirectory() as folder:
            valid, reason = cbom.validate_cbom_schema(self.bom, Path(folder)/'missing.json')
        self.assertIsNone(valid)
        self.assertTrue(reason)

    def test_unknown_schema_reference_is_never_retrieved(self):
        with tempfile.TemporaryDirectory() as folder:
            schema = Path(folder)/'schema.json'
            schema.write_text(json.dumps({'$schema': 'http://json-schema.org/draft-07/schema#',
                                         'properties': {'version': {'$ref': 'https://untrusted.invalid/schema'}}}))
            with patch('socket.create_connection', side_effect=AssertionError('schema network access')):
                valid, reason = cbom.validate_cbom_schema(self.bom, schema)
        self.assertIsNone(valid)
        self.assertTrue(reason)

    def test_unused_unknown_schema_reference_is_still_unavailable(self):
        with tempfile.TemporaryDirectory() as folder:
            schema = Path(folder)/'schema.json'
            schema.write_text(json.dumps({'$schema': 'http://json-schema.org/draft-07/schema#',
                                         'properties': {'not_present': {'$ref': 'https://untrusted.invalid/schema'}}}))
            with patch('socket.create_connection', side_effect=AssertionError('schema network access')):
                valid, reason = cbom.validate_cbom_schema(self.bom, schema)
        self.assertIsNone(valid)
        self.assertTrue(reason)

    def test_malformed_serial_number_is_invalid_not_exception(self):
        valid, error = cbom.validate_cbom_schema({**self.bom, 'serialNumber': None})
        self.assertIs(valid, False)
        self.assertTrue(error)

    def test_bundled_license_reference_is_validated_offline(self):
        document = copy.deepcopy(self.bom)
        document['metadata']['component']['licenses'] = [{'license': {'id': 'Apache-2.0'}}]
        with patch('socket.create_connection', side_effect=AssertionError('schema network access')):
            valid, error = cbom.validate_cbom_schema(document)
        self.assertIs(valid, True, error)
        document['metadata']['component']['licenses'][0]['license']['id'] = 'NOT-A-LICENSE'
        self.assertIs(cbom.validate_cbom_schema(document)[0], False)


class ExactScanExportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), dashboard.DashboardRequestHandler)
        cls.base = 'http://127.0.0.1:' + str(cls.server.server_port)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def setUp(self):
        with dashboard.SCAN_HISTORY_LOCK:
            dashboard.SCAN_HISTORY.clear()

    def get(self, path):
        try:
            response = urllib.request.urlopen(self.base+path, timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.status, response.read()

    def test_every_returned_demo_has_distinct_exportable_identity(self):
        _, first = self.get('/api/demo')
        _, second = self.get('/api/demo')
        a, b = json.loads(first), json.loads(second)
        self.assertTrue(a['metadata'].get('scan_id'))
        self.assertTrue(b['metadata'].get('scan_id'))
        self.assertNotEqual(a['metadata']['scan_id'], b['metadata']['scan_id'])
        status, exported = self.get('/api/export?format=json&id='+b['metadata']['scan_id'])
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(exported), b)

    def test_older_scan_exports_exact_target_and_shared_markdown(self):
        report = run_pipeline(repo_path='sample_vulnerable_app')
        scan_id = dashboard.record_scan_history(report, 'code')
        dashboard.record_scan_history(run_pipeline(repo_path='sample_remediated_app'), 'code')
        status, body = self.get('/api/export?format=cbom&id='+scan_id)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)['metadata']['component']['name'], 'sample_vulnerable_app')
        properties = {p['name']: p['value'] for p in json.loads(body)['metadata']['properties']}
        self.assertEqual(properties.get('qshield:scan_id'), scan_id)
        status, body = self.get('/api/export?format=markdown&id='+scan_id)
        self.assertEqual(status, 200)
        self.assertEqual(body.decode(), render_markdown(report))
        self.assertIn('**Confidence:**', body.decode())

    def test_markdown_contains_safe_evidence_and_iac_diagnostics(self):
        report = run_pipeline(repo_path='sample_vulnerable_app')
        text = render_markdown(report)
        self.assertIn('hashlib.md5(data)', text)
        self.assertIn('**Evidence:**', text)
        iac = render_markdown(run_pipeline(repo_path='docs/examples/iac_sample', iac=True))
        self.assertIn('Static IaC coverage', iac)
        self.assertIn('Scan diagnostics', iac)

    def test_recorded_scan_is_immutable_through_inputs_and_readers(self):
        report = run_pipeline(repo_path='sample_vulnerable_app')
        scan_id = dashboard.record_scan_history(report, 'code')
        report['metadata']['targets']['repo'] = 'wrong-input'
        retrieved = dashboard.get_scan_by_id(scan_id)
        retrieved['metadata']['targets']['repo'] = 'wrong-reader'
        status, exported = self.get('/api/export?format=json&id='+scan_id)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(exported)['metadata']['targets']['repo'], 'sample_vulnerable_app')

    def test_evicted_scan_cannot_export_latest(self):
        old = dashboard.record_scan_history(run_pipeline(repo_path='sample_vulnerable_app'))
        for _ in range(dashboard.MAX_HISTORY_ENTRIES):
            dashboard.record_scan_history({'metadata': {}, 'risk_assessment': {'summary': {}}})
        for fmt in ('json', 'markdown', 'cbom'):
            self.assertEqual(self.get('/api/export?format='+fmt+'&id='+old)[0], 404)


if __name__ == '__main__':
    unittest.main()
