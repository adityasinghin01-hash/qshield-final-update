# Audit fixes 1–14

Implemented on `fix/qshield-v1.4-audit`, based on `version-1.4` at `83d1a83`.

| Item | Result |
| --- | --- |
| 1 | Source files open through anchored directory descriptors and no-follow checks. Symlink entries are excluded, including nested and swapped links. |
| 2–3 | Supported PBKDF2, Argon2 and bcrypt calls retain bounded, non-secret explicit settings. Weak settings add conventional findings; missing settings and salt/runtime security remain unknown. |
| 4 | Python assigned aliases and JS computed/optional calls are handled conservatively. Shadowed, reassigned and unsupported dynamic bindings become unresolved evidence. |
| 5–6 | Source coverage includes attempted/scanned/supported/unsupported files, excluded entries, unresolved observations, capabilities and settings. |
| 7 | Dashboard and Markdown show distinct affected assets, unknown findings/evidence and critical findings with unknown evidence alongside the heuristic posture score. |
| 8 | Normalization preserves the scanner's certificate SHA-256 fingerprint. |
| 9 | Browser CBOM and Markdown exports use the displayed scan's exact ID; every demo has its own immutable history identity. Expired IDs return an inline error, without exporting the latest scan. |
| 10–11 | Formal validation directly loads the bundled schema, resolves its offline schema graph, and distinguishes valid (`True`), invalid (`False`) and unavailable (`None`). Unknown references never trigger network retrieval. |
| 12 | Development requirements include formal validation; CI installs all dependencies and runs representative generated CBOMs through a separate offline validation gate. |
| 13 | Browser and CLI Markdown use the same renderer, including redacted literal evidence, parameters, coverage, diagnostics and assessment details. |
| 14 | Comparison preserves relative file/function/call identity and duplicate counts. Lost files/probes/trust outcomes, unknown evidence, changed settings/rules/targets and demo inputs make the comparison inconclusive. |

The existing CBOM write-failure test also received a portable fixture: a regular
file used as an output parent. It verifies real failure on POSIX and Windows,
rather than assuming a Windows-looking path is unwritable everywhere.

## Verification

Local verification on 30 October 2026, native ARM Python 3.14:

- Full regression suite: **231 tests passed**.
- `python demo_migration.py`: passed, including local hybrid agreement and tamper rejection.
- `python tools/validate_cbom_exports.py`: source, remediated source, IaC and synthetic TLS exports all formally valid.
- Browser: exact demo/historical CBOM identity; shared Markdown evidence and coverage; expired export preserves the displayed report; coverage visible at desktop/mobile sizes; same-file observed improvement and incompatible/demo comparison warnings.
- Independent source/export/comparison reviews and final whole-branch review: no unresolved critical or important findings.

Run:

```sh
python -m pip install -r requirements-dev.txt
python -m unittest discover -s . -p 'test_*.py' -v
python tools/validate_cbom_exports.py
python demo_migration.py
```

On macOS use a canonical temporary directory for tests that inspect source paths:

```sh
TMPDIR=/private/tmp python -m unittest discover -s . -p 'test_*.py' -v
```

Remote GitHub Actions execution is separate from these local results. The
existing workflow branch filters remain unchanged.

## Boundaries

Source opening currently requires POSIX descriptor/no-follow support and fails
closed where unavailable. All source symlinks are excluded. JS/TS analysis remains
lexical; unsupported scope or dynamic constructs are reported unresolved.
Password-cost adequacy does not establish salt generation, uniqueness or runtime
security. A comparison can show fewer observed findings; it always reports
`remediation_verified: false` because absence alone does not prove a working fix.
TLS probe provenance gaps remain conservative comparison warnings; this change
does not add full-chain/revocation discovery or rewrite TLS probing.
