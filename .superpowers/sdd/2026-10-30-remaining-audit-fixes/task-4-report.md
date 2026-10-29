# Task 4 — release identity and offline browser assets (26–28)

Application release `1.4.1` is defined by `qshield_version.VERSION`, imported by the CLI/pipeline, dashboard health and CBOM tool identity. The dashboard badge reads scan metadata. Engine/ruleset/schema versions retain their separate meanings. CLI JSON and CBOM exports, served health/scan/CBOM responses and formal CycloneDX 1.6 validation are covered together.

Preserved and consolidated the prepared React 18 extraction and pinned Node build. Review against the prior inline JSX found only the intended version badge change, besides import extraction. Python serves compiled JS, Tailwind/custom CSS and packaged Latin font weights locally. WOFF/WOFF2 now use font MIME types with `nosniff`. Build isolation prevents stale generated files; rebuild checks compare names and SHA-256 bytes, with locale-independent manifest ordering. Copied React/React DOM MIT and three font OFL notices; graph regressions resolve every CSS font URL, check exact manifest membership/hashes and release parity. Node is a development requirement only. README/build/release policy docs distinguish prototype evidence, three repair chunks, POSIX safe-open limits, historical test claims and unverified remote CI.

## RED

- Earlier prepared local-asset regressions failed against the CDN/Babel shell; retained log `/private/tmp/qshield-offline-red.log`.
- `/private/tmp/qshield-review-arm-venv-20261030/bin/python -m unittest test_release_integration.TestMergedDashboard.test_health_scan_and_cbom_export_report_same_release test_release_integration.TestMergedDashboard.test_cli_json_and_cbom_release_parity test_release_integration.TestMergedDashboard.test_bundled_fonts_are_served_with_font_mime_and_exact_bytes` — three expected failures: health and CLI exported `2.0.0`; WOFF2 served as `text/plain`.

## GREEN

- Same three focused regressions: passed after central version/MIME changes.
- `npm run build:web && node tools/build-web.mjs --check` — built 32 local files and isolated rebuild matched committed asset bytes.
- `/private/tmp/qshield-review-arm-venv-20261030/bin/python -m unittest discover -s . -p 'test_*.py' > /private/tmp/qshield-remaining-default.log 2>&1` — 265 tests passed in 7.741s, default environment (no TMPDIR override).
- `/private/tmp/qshield-review-arm-venv-20261030/bin/python tools/validate_cbom_exports.py` — source, remediated, IaC and synthetic TLS exports formally valid offline.
- Parent repeated the actual browser check after restarting the current Python server at `127.0.0.1:8765`: all nonlocal requests blocked; no external requests, failed requests or page errors; fonts loaded. Clicking Scan Repository returned HTTP 200, 17 inventory findings (`scan_aaf3ec86fafa48db8f414a4b54de3837`), scan and health version `1.4.1`, rendered badge `v1.4.1`.
- `git diff --check` — clean.

No remote CI execution or production security certification is claimed. TLS target scans still need network access; static scan coverage and platform limitations remain explicit. Task 5 owns subsequent UI reflow/context work.
