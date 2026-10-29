"""The shipped dashboard must load from local static resources offline."""
import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import unittest
from urllib.parse import urlparse

from qshield_version import VERSION

ROOT = Path(__file__).resolve().parent
WEB = ROOT/'web'


class AssetReferences(HTMLParser):
    def __init__(self):
        super().__init__()
        self.urls = []

    def handle_starttag(self, tag, attributes):
        attrs = dict(attributes)
        if tag == 'script' and attrs.get('src'):
            self.urls.append(attrs['src'])
        if tag == 'link' and attrs.get('rel') in ('stylesheet', 'preload'):
            self.urls.append(attrs['href'])


class OfflineAssetTests(unittest.TestCase):
    def test_shell_dependencies_are_existing_local_resources(self):
        parser = AssetReferences()
        parser.feed((WEB/'index.html').read_text())
        self.assertTrue(parser.urls)
        for url in parser.urls:
            with self.subTest(url=url):
                self.assertTrue(url.startswith('/') and not url.startswith('//'))
                self.assertTrue((WEB/url.lstrip('/')).is_file())

    def test_css_has_no_external_imports_or_fonts(self):
        styles = [WEB/'command.css', *sorted((WEB/'assets').glob('*.css'))]
        for file in styles:
            text = file.read_text()
            self.assertFalse(re.search(r'(?:@import|url\()[^;\n]*(?:https?:|//)', text), file.name)
            for reference in re.findall(r'url\([\'\"]?([^\'\")]+)', text):
                url = urlparse(reference)
                self.assertFalse(url.scheme or url.netloc, reference)
                target = (WEB/url.path.lstrip('/')) if url.path.startswith('/') else file.parent/url.path
                self.assertTrue(target.resolve().is_relative_to(WEB.resolve()), reference)
                self.assertTrue(target.is_file(), reference)

    def test_built_manifest_matches_shipped_bytes(self):
        manifest = WEB/'assets'/'manifest.json'
        self.assertTrue(manifest.exists(), 'Build the shipped dashboard assets.')
        data = json.loads(manifest.read_text())
        self.assertEqual(data['version'], VERSION)
        self.assertEqual(json.loads((ROOT/'package.json').read_text())['version'], VERSION)
        self.assertTrue(data['files'])
        actual_files = {file.relative_to(manifest.parent).as_posix()
                        for file in manifest.parent.rglob('*') if file.is_file() and file != manifest}
        self.assertEqual(set(data['files']), actual_files)
        for relative, expected in data['files'].items():
            file = WEB/'assets'/relative
            self.assertTrue(file.resolve().is_relative_to((WEB/'assets').resolve()))
            self.assertEqual(hashlib.sha256(file.read_bytes()).hexdigest(), expected, relative)


if __name__ == '__main__':
    unittest.main()
