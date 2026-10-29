"""Pipeline regressions for evidence boundaries, source identity and KDF policy."""
import json
import ast
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from main import run_pipeline
from adapters import convert_code_results_to_findings
from crypto_source import _literal


class AuditSource(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def scan(self, text, suffix='.py'):
        path = self.root / ('source' + suffix)
        path.write_text(text)
        return run_pipeline(repo_path=str(path))

    def active(self, report):
        return [f for f in report['inventory']['findings']
                if f['attributes']['match_type'] == 'CONFIRMED_CALL']

    def test_symlinks_and_nested_symlinks_are_excluded(self):
        outside = self.root / 'outside'
        outside.mkdir()
        marker = outside / 'marker.py'
        marker.write_text('hashlib.md5(b"OUTSIDE_MARKER")')
        repo = self.root / 'repo'
        repo.mkdir()
        (repo / 'good.py').write_text('hashlib.sha1(b"inside")')
        (repo / 'escape.py').symlink_to(marker)
        (repo / 'directory').symlink_to(outside, target_is_directory=True)
        (repo / 'nested').mkdir()
        (repo / 'nested' / 'escape.py').symlink_to(marker)
        report = run_pipeline(repo_path=str(repo))
        self.assertNotIn('OUTSIDE_MARKER', json.dumps(report))
        self.assertEqual(len(self.active(report)), 1)
        cov = report['modules']['code_scanner']['coverage']
        self.assertEqual(cov['scanned_paths'], ['good.py'])
        self.assertEqual(len(cov['exclusions']), 3)
        self.assertIsNone(report['risk_assessment']['summary']['readiness_score'])
        direct = run_pipeline(repo_path=str(repo / 'escape.py'))
        self.assertFalse(self.active(direct))
        self.assertNotIn('OUTSIDE_MARKER', json.dumps(direct))

    def test_regular_nested_file_is_scanned(self):
        (self.root / 'nested').mkdir()
        (self.root / 'nested' / 'ok.py').write_text('hashlib.md5(b"x")')
        report = run_pipeline(repo_path=str(self.root))
        self.assertEqual(len(self.active(report)), 1)
        self.assertEqual(report['modules']['code_scanner']['coverage']['scanned_paths'], ['nested/ok.py'])

    def test_leaf_and_ancestor_swaps_never_follow_links(self):
        outside = self.root / 'outside'
        outside.mkdir()
        (outside / 'item.py').write_text('hashlib.md5(b"RACE_MARKER")')
        repo = self.root / 'repo'
        repo.mkdir()
        nested = repo / 'nested'
        nested.mkdir()
        (nested / 'item.py').write_text('hashlib.sha1(b"inside")')
        real_open = os.open
        swapped = False

        def swap_directory(path, flags, *args, **kwargs):
            nonlocal swapped
            if str(path) == 'nested' and not swapped:
                swapped = True
                nested.rename(repo / 'original')
                nested.symlink_to(outside, target_is_directory=True)
            return real_open(path, flags, *args, **kwargs)

        with patch('code_scanner.os.open', side_effect=swap_directory):
            report = run_pipeline(repo_path=str(repo))
        self.assertTrue(swapped)
        self.assertNotIn('RACE_MARKER', json.dumps(report))
        self.assertFalse(self.active(report))
        self.assertTrue(report['modules']['code_scanner']['coverage']['exclusions'])
        nested.unlink()
        (repo / 'original').rename(nested)
        swapped = False

        def swap_leaf(path, flags, *args, **kwargs):
            nonlocal swapped
            if str(path) == 'item.py' and not swapped:
                swapped = True
                (nested / 'item.py').unlink()
                (nested / 'item.py').symlink_to(outside / 'item.py')
            return real_open(path, flags, *args, **kwargs)

        with patch('code_scanner.os.open', side_effect=swap_leaf):
            report = run_pipeline(repo_path=str(repo))
        self.assertTrue(swapped)
        self.assertNotIn('RACE_MARKER', json.dumps(report))
        self.assertFalse(self.active(report))

    def test_unsupported_source_counts_but_documentation_does_not(self):
        (self.root / 'ok.py').write_text('AESGCM(b"x" * 32)')
        (self.root / 'Other.java').write_text('class Other {}')
        (self.root / 'README.md').write_text('documentation')
        report = run_pipeline(repo_path=str(self.root))
        cov = report['modules']['code_scanner']['coverage']
        self.assertEqual((cov['supported_files'], cov['unsupported_files'], cov['scanned_files']), (1, 1, 1))
        self.assertEqual([e['path'] for e in cov['exclusions']], ['Other.java'])
        self.assertIsNone(report['risk_assessment']['summary']['readiness_score'])

    def test_reassigned_shadowed_and_conditional_aliases_are_unknown(self):
        cases = [
            'import hashlib as h\nh = user_value\nh.md5(b"x")',
            'from hashlib import md5 as digest\ndigest = user_value\ndigest(b"x")',
            'import hashlib as h\ndef f(h):\n    h.md5(b"x")',
            'if flag:\n    import hashlib as h\nh.md5(b"x")',
            'import hashlib as h\nh += user_value\nh.md5(b"x")',
            'import hashlib as h\ndef h(): pass\nh.md5(b"x")',
            'import hashlib as h\nh.md5 = user_value\nh.md5(b"x")',
            'import hashlib as h\nh["md5"] = user_value\nh.md5(b"x")',
            'class C:\n    import hashlib as h\n    def f(self):\n        h.md5(b"x")',
        ]
        for source in cases:
            with self.subTest(source=source):
                report = self.scan(source)
                self.assertFalse(self.active(report))
                self.assertTrue(report['modules']['code_scanner']['coverage']['unresolved'])

    def test_python_bound_call_alias_is_detected(self):
        report = self.scan('import hashlib\nf = hashlib.md5\nf(b"x")')
        self.assertTrue(any(f['algorithm'] == 'MD5' for f in self.active(report)))

    def test_nested_namespace_is_not_invented_and_parameter_scope_is_bounded(self):
        report = self.scan('user.hashlib.md5(b"x")')
        self.assertFalse(self.active(report))
        report = self.scan('cost = 600000\ndef derive(cost):\n    return hashlib.pbkdf2_hmac("sha256", p, s, cost)')
        self.assertIsNone(report['risk_assessment']['summary']['readiness_score'])
        self.assertNotIn('iterations', self.active(report)[0]['attributes']['parameters'])

    def test_js_block_import_alias_is_not_global_evidence(self):
        report = self.scan("if(flag) { const c = require('crypto'); } c.createHash('md5')", '.js')
        self.assertFalse(self.active(report))
        self.assertTrue(report['modules']['code_scanner']['coverage']['unresolved'])

    def test_js_computed_optional_and_dynamic_calls(self):
        for source in ["crypto['createHash']('md5')", "crypto?.createHash('md5')"]:
            with self.subTest(source=source):
                report = self.scan(source, '.js')
                self.assertTrue(any(f['algorithm'] == 'MD5' for f in self.active(report)))
        report = self.scan('crypto[method]("md5")', '.js')
        self.assertFalse(self.active(report))
        self.assertTrue(report['modules']['code_scanner']['coverage']['unresolved'])

    def test_js_reassigned_import_alias_is_unknown(self):
        for source in ["const c = require('crypto'); c = user; c.createHash('md5')",
                       "import c from 'crypto'; c=user; c.createHash('md5')",
                       "import c from 'crypto'; const f=c=>c.createHash('md5')",
                       "const c = require('crypto'); c.createHash=user; c.createHash('md5')"]:
            with self.subTest(source=source):
                report = self.scan(source, '.js')
                self.assertFalse(self.active(report))
                self.assertTrue(report['modules']['code_scanner']['coverage']['unresolved'])

    def test_js_import_evidence_does_not_capture_neighboring_secret_arguments(self):
        report = self.scan('import crypto from "crypto"\n'
                           'crypto.pbkdf2Sync("PASSWORD_MARKER", "SALT_MARKER", 600000, 32, "sha256")', '.js')
        self.assertNotIn('PASSWORD_MARKER', json.dumps(report))
        self.assertNotIn('SALT_MARKER', json.dumps(report))
        self.assertEqual(self.active(report)[0]['attributes']['parameters']['iterations'], 600000)

    def test_js_non_crypto_require_cannot_create_crypto_namespace(self):
        report = self.scan("const c=require('other', 'crypto'); c.createHash('md5')", '.js')
        self.assertFalse(self.active(report))

    def test_dynamic_getattr_and_cost_strings_are_not_parameter_evidence(self):
        report = self.scan('import hashlib\nf=getattr(hashlib, method)\nf(b"x")')
        self.assertTrue(report['modules']['code_scanner']['coverage']['unresolved'])
        report = self.scan('crypto.pbkdf2Sync("aes-128-gcm", "salt", 600000, 32, "sha256")', '.js')
        self.assertNotIn('key_bits', self.active(report)[0]['attributes']['parameters'])

    def test_imports_and_comments_do_not_create_active_risk(self):
        report = self.scan('import hashlib\n# hashlib.md5(b"x")')
        self.assertFalse(self.active(report))
        self.assertFalse(report['risk_assessment']['assessments'])
        self.assertIsNone(report['risk_assessment']['summary']['readiness_score'])

    def test_unresolved_source_is_counted_as_unknown_even_without_findings(self):
        report = self.scan('crypto[method]("md5")', '.js')
        summary = report['risk_assessment']['summary']
        self.assertEqual(summary['readiness_posture'], 'unknown')
        self.assertGreater(summary['unknown_count'], 0)
        self.assertTrue(summary['unknown_reasons'])

    def test_two_calls_on_one_line_retain_distinct_identity(self):
        report = self.scan('hashlib.md5(b"x"); hashlib.md5(b"y")')
        calls = self.active(report)
        self.assertEqual(len(calls), 2)
        self.assertNotEqual(calls[0]['attributes']['source_identity']['anchor'], calls[1]['attributes']['source_identity']['anchor'])

    def test_pbkdf2_weak_setting_is_conventional(self):
        report = self.scan("import hashlib\nhashlib.pbkdf2_hmac('sha256', b'PASSWORD_MARKER', b'SALT_MARKER', 1)")
        self.assertTrue(any(a['rule_id'] == 'WEAK_KDF_PARAMETERS' and a['track'] == 'conventional'
                            for a in report['risk_assessment']['assessments']))
        params = self.active(report)[0]['attributes']['parameters']
        self.assertEqual(params['iterations'], 1)
        self.assertEqual(params['digest'], 'sha256')
        self.assertNotIn('PASSWORD_MARKER', json.dumps(report))
        self.assertNotIn('SALT_MARKER', json.dumps(report))

    def test_pbkdf2_bounded_explicit_cost_and_unknown_cost(self):
        report = self.scan("import hashlib\ncost=600000\nhashlib.pbkdf2_hmac('sha256', password, salt, cost)")
        params = self.active(report)[0]['attributes']['parameters']
        self.assertEqual(params['iterations'], 600000)
        self.assertEqual(params['kdf_assessment']['status'], 'adequate')
        self.assertEqual(params['kdf_assessment']['assessment_scope'], 'explicit_cost_only')
        self.assertEqual(params['kdf_assessment']['salt_status'], 'unknown')
        self.assertTrue(params['kdf_assessment']['unknown_reasons'])
        self.assertIsNone(report['risk_assessment']['summary']['readiness_score'])
        for args in ["'sha256', password, salt", "'sha256', password, salt, caller_cost", "digest, password, salt, 600000"]:
            with self.subTest(args=args):
                report = self.scan('import hashlib\nhashlib.pbkdf2_hmac(' + args + ')')
                self.assertIsNone(report['risk_assessment']['summary']['readiness_score'])
                self.assertGreater(report['risk_assessment']['summary']['unknown_count'], 0)

    def test_cryptography_pbkdf2_costs(self):
        report = self.scan('from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC\n'
                           'from cryptography.hazmat.primitives import hashes\n'
                           'PBKDF2HMAC(algorithm=hashes.SHA512(), length=32, salt=salt, iterations=220000)')
        params = self.active(report)[0]['attributes']['parameters']
        self.assertEqual((params['iterations'], params['digest']), (220000, 'sha512'))
        self.assertEqual(params['kdf_assessment']['status'], 'adequate')

    def test_argon2_tradeoff_profiles_and_unknown_variant(self):
        for memory, passes, status in [(47104, 1, 'adequate'), (19456, 2, 'adequate'), (1024, 1, 'weak')]:
            with self.subTest(memory=memory):
                report = self.scan('from argon2 import PasswordHasher, Type\n'
                    f'PasswordHasher(memory_cost={memory}, time_cost={passes}, parallelism=1, type=Type.ID)')
                params = self.active(report)[0]['attributes']['parameters']
                self.assertEqual(params['kdf_assessment']['status'], status)
                self.assertEqual(params['memory_cost'], memory)
        report = self.scan('import argon2\nargon2.PasswordHasher(memory_cost=47104, time_cost=1, parallelism=1)')
        self.assertIsNone(report['risk_assessment']['summary']['readiness_score'])

    def test_bcrypt_explicit_rounds_and_caller_salt_unknown(self):
        for rounds, status in [(10, 'adequate'), (4, 'weak')]:
            with self.subTest(rounds=rounds):
                report = self.scan(f'import bcrypt\ns = bcrypt.gensalt(rounds={rounds})\nbcrypt.hashpw(password, s)')
                calls = self.active(report)
                self.assertEqual(len(calls), 2)
                self.assertTrue(all(f['attributes']['parameters']['rounds'] == rounds for f in calls))
                self.assertTrue(all(f['attributes']['parameters']['kdf_assessment']['status'] == status for f in calls))
        report = self.scan('import bcrypt\nbcrypt.hashpw(password, caller_salt)')
        self.assertIsNone(report['risk_assessment']['summary']['readiness_score'])

    def test_source_identity_survives_line_changes_without_argument_disclosure(self):
        a = self.scan('def derive(password):\n    return hashlib.pbkdf2_hmac("sha256", password, salt, 600000)')
        b = self.scan('\n\ndef derive(password):\n    return hashlib.pbkdf2_hmac("sha256", password, salt, 600000)')
        attrs = self.active(a)[0]['attributes']
        self.assertEqual(attrs['source_scope'], 'derive')
        self.assertEqual(attrs['source_call'], 'hashlib.pbkdf2_hmac')
        self.assertEqual(attrs['source_identity'], self.active(b)[0]['attributes']['source_identity'])
        self.assertEqual(a['modules']['code_scanner']['coverage']['settings'], {'ignore_comments': False, 'quantum_only': False})

    def test_named_arrow_scope_changes_source_identity(self):
        for body in ['() => { return crypto.createHash("md5"); }',
                     'value => crypto.createHash("md5")',
                     'async () => crypto.createHash("md5")']:
            with self.subTest(body=body):
                before = self.scan('const a = ' + body + ';', '.js')
                after = self.scan('const b = ' + body + ';', '.js')
                attrs = self.active(before)[0]['attributes']
                self.assertEqual(attrs['source_scope'], 'a')
                self.assertEqual(self.active(after)[0]['attributes']['source_scope'], 'b')
                self.assertNotEqual(attrs['source_identity']['anchor'], self.active(after)[0]['attributes']['source_identity']['anchor'])
                shifted = self.scan('\n\nconst a = ' + body + ';', '.js')
                self.assertEqual(attrs['source_identity'], self.active(shifted)[0]['attributes']['source_identity'])

    def test_nested_arrow_names_keep_ancestry_and_do_not_scope_neighbor_calls(self):
        source = ('const left = () => { const same = () => crypto.createHash("md5"); };'
                  'const right = () => { const same = () => { crypto.createHash("md5"); }; };'
                  'crypto.createHash("md5");')
        calls = self.active(self.scan(source, '.js'))
        self.assertEqual([f['attributes']['source_scope'] for f in calls], ['left.same', 'right.same', '<module>'])
        self.assertNotEqual(calls[0]['attributes']['source_identity']['anchor'], calls[1]['attributes']['source_identity']['anchor'])

    def test_ambiguous_arrow_scopes_are_explicitly_unresolved(self):
        for source in ['items.map(() => crypto.createHash("md5"));',
                       'const same = () => crypto.createHash("md5"); const same = () => crypto.createHash("md5");']:
            with self.subTest(source=source):
                report = self.scan(source, '.js')
                self.assertTrue(report['modules']['code_scanner']['coverage']['unresolved'])
                self.assertTrue(all(f['attributes']['source_scope'] == '<unresolved>' for f in self.active(report)))

    def test_semicolon_free_expression_arrow_boundary_is_conservative(self):
        report = self.scan('const a = () => crypto.createHash("md5")\ncrypto.createHash("md5");', '.js')
        self.assertTrue(report['modules']['code_scanner']['coverage']['unresolved'])
        self.assertTrue(all(f['attributes']['source_scope'] == '<unresolved>' for f in self.active(report)))

    def test_arrow_and_named_function_scopes_keep_nesting_order(self):
        report = self.scan('const outer = () => { function inner() { crypto.createHash("md5"); } };', '.js')
        self.assertEqual(self.active(report)[0]['attributes']['source_scope'], 'outer.inner')

    def test_tls_fingerprint_real_shape_and_missing(self):
        tls = {'scan_status': 'ok', 'target': {'host': 'audit.test'}, 'certificate': {
            'public_key': {'algorithm': 'RSA', 'key_size_bits': 2048}, 'fingerprint_sha256': 'ab' * 32}}
        with patch('main.scan_tls', return_value=tls):
            report = run_pipeline(host='audit.test')
        self.assertEqual(report['inventory']['findings'][0]['attributes']['fingerprint_sha256'], 'ab' * 32)
        del tls['certificate']['fingerprint_sha256']
        with patch('main.scan_tls', return_value=tls):
            report = run_pipeline(host='audit.test')
        self.assertIsNone(report['inventory']['findings'][0]['attributes']['fingerprint_sha256'])

    def test_literal_alias_chains_keep_the_scope_of_each_binding(self):
        source = ('import hashlib\ncost_base=1\ncost=cost_base\n'
                  'def derive():\n    cost_base=600000\n'
                  '    return hashlib.pbkdf2_hmac("sha256", password, salt, cost)')
        report = self.scan(source)
        self.assertEqual(self.active(report)[0]['attributes']['parameters']['iterations'], 1)
        self.assertIn('WEAK_KDF_PARAMETERS', [a['rule_id'] for a in report['risk_assessment']['assessments']])
        # The inverse must not invent weakness from a same-named local either.
        report = self.scan(source.replace('cost_base=1', 'cost_base=600000', 1).replace('    cost_base=600000', '    cost_base=1'))
        self.assertEqual(self.active(report)[0]['attributes']['parameters']['iterations'], 600000)

    def test_literal_expansion_stops_before_exceeding_the_total_budget(self):
        # This first expression is safe to evaluate on the old implementation:
        # its 16 MiB result demonstrates the missing cumulative bound. The
        # 64 GiB expression is exercised only after the first assertion passes.
        self.assertIsNone(_literal(ast.parse("b'x' * 4096 * 4096", mode='eval').body, {}))
        report = self.scan("hashlib.pbkdf2_hmac('sha256', p, s, b'x' * 4096 * 4096 * 4096)")
        self.assertNotIn('iterations', self.active(report)[0]['attributes']['parameters'])
        self.assertEqual(_literal(ast.parse("b'x' * 32", mode='eval').body, {}), b'x' * 32)

    def test_js_destructuring_and_shadowed_require_are_unresolved(self):
        cases = [
            "if(flag) { const {createHash: hash}=require('crypto'); } hash('md5');",
            "const {createHash: hash}=require('crypto'); function f({hash}) { hash('md5'); }",
            "const {createHash: hash}=require('crypto'); ({hash}=fake); hash('md5');",
            "function require(x) { return fake; } const {createHash: hash}=require('crypto'); hash('md5');",
            "function f(require) { const {createHash: hash}=require('crypto'); hash('md5'); }",
            "const require = fake; const c=require('crypto'); c.createHash('md5');",
            "const {createHash: hash}=require('crypto'); function f([hash]) { hash('md5'); }",
            "const {createHash: hash}=require('crypto'); function f(...hash) { hash('md5'); }",
            "const {createHash: hash}=require('crypto'); ([hash]=fake); hash('md5');",
        ]
        for source in cases:
            with self.subTest(source=source):
                report = self.scan(source, '.js')
                self.assertFalse(self.active(report))
                self.assertTrue(report['modules']['code_scanner']['coverage']['unresolved'])

    def test_pattern_captures_cannot_reuse_imported_aliases(self):
        cases = [
            "match user:\n    case {'h': h}:\n        h.md5(b'x')",
            "match user:\n    case [*h]:\n        h.md5(b'x')",
            "match user:\n    case {'x': x, **h}:\n        h.md5(b'x')",
        ]
        for source in cases:
            with self.subTest(source=source):
                report = self.scan('import hashlib as h\n' + source)
                self.assertFalse(self.active(report))
                self.assertTrue(report['modules']['code_scanner']['coverage']['unresolved'])

    def test_nested_classes_skip_enclosing_class_namespaces(self):
        report = self.scan("class Outer:\n    import hashlib as h\n    class Inner:\n        h.md5(b'x')")
        self.assertFalse(self.active(report))
        self.assertTrue(report['modules']['code_scanner']['coverage']['unresolved'])
        report = self.scan("def outer():\n    import hashlib as h\n    class Outer:\n        class Inner:\n            h.md5(b'x')")
        self.assertTrue(any(f['algorithm'] == 'MD5' for f in self.active(report)))

    def test_adapter_parameter_schema_rejects_arbitrary_strings(self):
        raw = {'findings': [{'detected_algorithm': 'PBKDF2-HMAC', 'likely_purpose': 'Password-Based Key Derivation',
            'file_path': 'example.py', 'line_number': 1, 'match_type': 'CONFIRMED_CALL',
            'parameters': {'digest': 'SALT_MARKER', 'iterations': 'PASSWORD_MARKER', 'rounds': 'PASSWORD_MARKER',
                'curve': 'CURVE_SECRET', 'mode': 'MODE_SECRET', 'variant': 'VARIANT_SECRET',
                'key_bits': True, 'memory_cost': 1.5}}]}
        findings = convert_code_results_to_findings(raw)
        self.assertNotIn('MARKER', json.dumps(findings[0].attributes))
        self.assertNotIn('_SECRET', json.dumps(findings[0].attributes))
        self.assertEqual(findings[0].attributes['parameters']['kdf_assessment']['status'], 'unknown')
        raw['findings'][0]['parameters'] = {'digest': 'sha512', 'iterations': 220000, 'mode': 'GCM', 'curve': 'P-384', 'variant': 'argon2id'}
        parameters = convert_code_results_to_findings(raw)[0].attributes['parameters']
        self.assertEqual(parameters['iterations'], 220000)
        self.assertEqual(parameters['mode'], 'GCM')
        raw['findings'][0]['detected_algorithm'] = 'AES'
        raw['findings'][0]['likely_purpose'] = 'Symmetric Encryption'
        raw['findings'][0]['parameters'] = {'key_bits': 256, 'mode': 'MODE_SECRET', 'curve': 'CURVE_SECRET'}
        finding = convert_code_results_to_findings(raw)[0]
        self.assertNotIn('_SECRET', json.dumps({'algorithm': finding.algorithm, 'attributes': finding.attributes}))


if __name__ == '__main__':
    unittest.main()
