"""Selected-root aliases are portable; descendant links remain untrusted."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from code_scanner import CodeScanner
from iac_scanner import scan_iac


class AuditPortability(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='qshield path with spaces ')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.actual = self.base / 'authorized repo'
        self.actual.mkdir()
        self.alias = self.base / 'selected ancestor'
        self.alias.symlink_to(self.base, target_is_directory=True)
        (self.actual / 'good.py').write_text('import hashlib\nhashlib.md5(b"inside")')
        (self.actual / 'Dockerfile').write_text('FROM node:22\nENV GIT_SSL_NO_VERIFY=true\n')

    def source(self, target):
        scanner = CodeScanner()
        findings = scanner.scan_path(target)
        return scanner, [f.to_dict() for f in findings]

    def test_source_explicit_directory_and_file_through_ancestor_alias(self):
        for target in (self.alias / self.actual.name, self.alias / self.actual.name / 'good.py'):
            with self.subTest(target=target):
                scanner, findings = self.source(target)
                self.assertEqual(scanner.coverage['scanned_paths'], ['good.py'])
                self.assertEqual(scanner.scanned_files_count, 1)
                self.assertEqual([f['detected_algorithm'] for f in findings if f['match_type'] == 'CONFIRMED_CALL'], ['MD5'])

    def test_iac_explicit_directory_and_file_through_ancestor_alias(self):
        for target in (self.alias / self.actual.name, self.alias / self.actual.name / 'Dockerfile'):
            with self.subTest(target=target):
                result = scan_iac(target)
                self.assertEqual(result['summary']['scanned_files'], 1)
                self.assertEqual([f['attributes']['rule_id'] for f in result['findings']],
                                 ['IAC_DOCKER_TLS_VERIFY_DISABLED'])
                self.assertEqual(result['coverage_status'], 'complete')

    def test_default_temporary_root_scans_both_regular_file_types(self):
        # Intentionally retain tempfile's default spelling (/var on macOS).
        root = Path(self.temp.name) / self.actual.name
        scanner, _ = self.source(root)
        self.assertEqual(scanner.scanned_files_count, 1)
        self.assertEqual(scan_iac(root)['summary']['scanned_files'], 1)

    def test_direct_and_nested_links_do_not_read_external_marker(self):
        outside = self.base / 'outside'
        outside.mkdir()
        (outside / 'marker.py').write_text('import hashlib\nhashlib.md5(b"OUTSIDE_MARKER")')
        (outside / 'Dockerfile').write_text('FROM node:22\nENV GIT_SSL_NO_VERIFY=true\n# OUTSIDE_MARKER')
        (self.actual / 'escape.py').symlink_to(outside / 'marker.py')
        (self.actual / 'Dockerfile.escape').symlink_to(outside / 'Dockerfile')
        (self.actual / 'nested link').symlink_to(outside, target_is_directory=True)
        for target in (self.actual, self.actual / 'escape.py', self.actual / 'Dockerfile.escape',
                       self.actual / 'nested link'):
            with self.subTest(target=target):
                scanner, findings = self.source(target)
                result = scan_iac(target)
                self.assertNotIn('OUTSIDE_MARKER', json.dumps(findings))
                self.assertNotIn('OUTSIDE_MARKER', json.dumps(result))
                if target == self.actual:
                    self.assertEqual(scanner.scanned_files_count, 1)
                    self.assertEqual(result['summary']['scanned_files'], 1)
                else:
                    self.assertFalse(findings)
                    self.assertFalse(result['findings'])
                    self.assertTrue(scanner.coverage['exclusions'])
                    self.assertEqual(result['coverage_status'], 'partial')

    def test_iac_ancestor_and_leaf_swap_do_not_read_outside_bytes(self):
        outside = self.base / 'outside'
        outside.mkdir()
        # Distinct configured behavior exposes a read even though IaC redacts comments.
        (outside / 'Dockerfile').write_text('FROM node:22\nENV GIT_SSL_NO_VERIFY=true\n# RACE_MARKER')
        nested = self.actual / 'nested'
        nested.mkdir()
        (nested / 'Dockerfile').write_text('FROM node:22\n')
        for kind in ('ancestor', 'leaf'):
            with self.subTest(kind=kind):
                real_open = os.open
                real_resolve = Path.resolve
                swapped = False
                def swap_ancestor():
                    nonlocal swapped
                    swapped = True
                    nested.rename(self.actual / 'original')
                    nested.symlink_to(outside, target_is_directory=True)
                def resolve_then_swap(path, *args, **kwargs):
                    resolved = real_resolve(path, *args, **kwargs)
                    # Exercise the old check/open gap and the new anchored open.
                    if kind == 'ancestor' and path == nested / 'Dockerfile' and not swapped:
                        swap_ancestor()
                    return resolved
                def swap(path, flags, *args, **kwargs):
                    nonlocal swapped
                    name = Path(path).name
                    if not swapped and name == ('nested' if kind == 'ancestor' else 'Dockerfile'):
                        # Only descendant opens, never the unrelated root Dockerfile.
                        if kind == 'leaf' and kwargs.get('dir_fd') is None:
                            candidate = Path(path)
                            if candidate.parent != nested:
                                return real_open(path, flags, *args, **kwargs)
                        elif kind == 'leaf' and not swapped:
                            # Root Dockerfile is omitted below for an unambiguous hook.
                            pass
                        swapped = True
                        if kind == 'ancestor':
                            swap_ancestor()
                        else:
                            (nested / 'Dockerfile').unlink()
                            (nested / 'Dockerfile').symlink_to(outside / 'Dockerfile')
                    return real_open(path, flags, *args, **kwargs)
                (self.actual / 'Dockerfile').unlink(missing_ok=True)
                with patch.object(Path, 'resolve', resolve_then_swap), patch('iac_scanner.os.open', side_effect=swap):
                    result = scan_iac(self.actual)
                if kind == 'ancestor' and nested.is_symlink():
                    nested.unlink()
                    (self.actual / 'original').rename(nested)
                self.assertTrue(swapped)
                self.assertFalse(result['findings'])
                self.assertEqual(result['coverage_status'], 'partial')
                self.assertNotIn('RACE_MARKER', json.dumps(result))

    def test_missing_nofollow_capability_reports_partial_without_reading(self):
        with patch.object(os, 'O_NOFOLLOW', 0, create=True):
            scanner, findings = self.source(self.actual)
            result = scan_iac(self.actual)
        self.assertFalse(findings)
        self.assertEqual(scanner.scanned_files_count, 0)
        self.assertIn('unsupported_platform', [e['reason'] for e in scanner.coverage['exclusions']])
        self.assertFalse(result['findings'])
        self.assertEqual(result['coverage_status'], 'partial')
        self.assertIn('unsupported_platform', [d['code'] for d in result['diagnostics']])


if __name__ == '__main__':
    unittest.main()
