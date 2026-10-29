# Q-SHIELD audit fixes 1–14 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Repair the fourteen authorized scanner, assessment, export and comparison defects on `fix/qshield-v1.4-audit`.

**Architecture:** Preserve the existing Python/React local workbench. Extend source evidence with bounded static parameters, explicit file coverage and stable source identity. Keep assessment/report rendering shared, and bind every exported artifact to an immutable recorded scan.

**Tech Stack:** Python 3.11+, unittest, standard-library HTTP server, cryptography, PyYAML, python-hcl2, jsonschema, existing CDN React UI.

## Global Constraints

- Work in `/Users/aditya/dev/innotech-qshield-v1.4-review-20261030` on `fix/qshield-v1.4-audit`; never push main/version-1.4 or force-push.
- Scope is approved fixes 1–14. Preserve unknown evidence; no score certifies safety/compliance. Do not execute scanned repository code, disclose secret values, or fetch external JSON-schema references.
- Use `/private/tmp/qshield-review-arm-venv-20261030/bin/python` for verification, with `TMPDIR=/private/tmp` on this Mac. Baseline: 163/164 tests pass with canonical temp; the Windows-drive CBOM test is a known unrelated failure. Do not quietly weaken that test or claim the full suite passes.
- Add meaningful failing regression cases before production changes; record red and green commands/results. Commit only each task's files. Do not revert other work.
- Maintain existing fields/API compatibility where possible. New coverage/detail fields are additive. Any schema API returns `True`, `False`, or `None` as its first tuple element: None means not formally validated.
- Password-cost policy source, verified 2026-10-30: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html . PBKDF2 SHA256 minimum 600000, SHA512 220000, SHA1 1400000 (legacy); bcrypt rounds minimum 10. Argon2id accepted (KiB,passes) profiles: (47104,1),(19456,2),(12288,3),(9216,4),(7168,5), with valid positive parallelism; do not infer library defaults, runtime salts or caller values. Explain unsupported parameters as unknown rather than unsafe.
- No broad frontend redesign, TLS probing rewrite, deployment, or new migration feature. Schema validation CI/dependency changes are included because fix 12 requires them.

### Task 1: Source containment, parameters, coverage, posture and certificate identity (fixes 1–8)

**Files:** `code_scanner.py`, `crypto_source.py`, `adapters.py`, `scan_results.py`; a focused new KDF policy module if needed; new `test_audit_source.py`; relevant small docs.

**Interfaces:** `scan_code(path, ignore_comments=False, quantum_only=False)` remains. Add `coverage` with supported/attempted/scanned/excluded source counts, exclusions with reasons, unresolved diagnostics, and analysis capabilities; retain legacy `coverage_status`. Add safe `attributes.parameters` to normalized findings. Include non-secret `source_scope`, `source_call`, and stable source identity metadata for later comparison. Summary exposes coverage, unknown counts/reasons, unresolved critical count and distinct affected asset counts in addition to the heuristic score. Missing required KDF parameters prevent a perfect posture; known weak parameters create conventional findings.

- [x] Write regressions in `test_audit_source.py` that exercise `run_pipeline` on synthetic temporary files. Test: outside-file and directory symlinks never read marker; normal and contained files still scan; reassigned/uncertain aliases don't invent confident calls; `f=hashlib.md5; f(b'x')`, `crypto['createHash']('md5')`, `crypto?.createHash('md5')` are detected or explicitly unresolved; dynamic computed calls are unresolved; unsupported Java beside observed AES is counted and cannot yield repository-complete 100; imports/comments alone do not become active risk.
- [x] Add KDF cases: PBKDF2 iteration1 => conventional weak-setting finding; supported adequate explicit cost is recorded; missing/dynamic cost => unknown/N/A; bounded local variables are resolved without executing code; cryptography PBKDF2HMAC, Argon2 PasswordHasher and bcrypt gensalt/hashpw supported explicit settings captured; parameter-dependent salt/variant remains unknown; costs never leak password/salt bytes. Test two Argon2 tradeoff profiles and weak settings. Preserve existing legacy detection tests.
- [x] Test normalized TLS certificate fingerprint survives a synthetic real-shape scanner result. Test unassessed missing fingerprint stays missing.
- [x] Run `/private/tmp/qshield-review-arm-venv-20261030/bin/python -m unittest test_audit_source -v`, record failures before changes.
- [x] Implement safe source opening with containment and no-follow checks; classify unsupported source extensions without treating every README/image as an analysis error. Improve bounded import/call alias resolution and JS lexical callee recognition; emit unknown diagnostics for unsupported crypto-like syntax. Extract only relevant non-secret parameters; assess KDF settings through a shared helper. Forward evidence into normalized inventory and the report. Repair fingerprint field.
- [x] Run new tests plus `test_audit_regressions.AuditScannerRegression`, `test_integration`, `test_cli`, `test_risk_engine`. Record outcomes; any expected behavior change must retain stronger assertions, not remove checks.
- [x] Commit task files with `fix(scanner): enforce evidence boundaries and assess crypto parameters`.

### Task 2: Exact-scan export, formal validation and shared Markdown (fixes 9–13)

**Files:** `dashboard.py`, `web/index.html`, `cbom.py`, `requirements.txt` and/or `requirements-dev.txt`, `.github/workflows/qshield-ci.yml`, new `test_audit_exports.py`, a runnable schema validation check, bundled subsidiary schema files if needed.

**Interfaces:** Preserve `/api/export?format=...&id=<scan_id>`, default latest for existing API clients. Record each returned demo with an exportable ID. Browser CBOM and Markdown always supply the displayed ID; missing or evicted ID produces a visible error without falling back to latest or navigating away. JSON remains export of displayed data. `validate_cbom_schema(dict,schema_path=None) -> (Optional[bool],Optional[str])`; explicit `None` for dependency/schema unavailable, `False` for invalid, `True` only after real validation. Use an offline reference registry and reject unknown references.

- [x] Add server API regression: record two different reports, export the older exact ID and assert root target/data marker; load another demo and assert new exportable ID. Missing/evicted IDs are 404. Markdown from exact ID includes diagnostics, confidence, rule, IaC coverage and safe evidence; matches `render_markdown`.
- [x] Add schema regressions with invalid `version` and component type: default lookup rejects; valid generated code/TLS/IaC documents pass; missing jsonschema or absent/unreadable schema => None; unresolved external schema reference => None/explicit unavailable, never network retrieval or success.
- [x] Run `/private/tmp/qshield-review-arm-venv-20261030/bin/python -m unittest test_audit_exports -v` and record the failing baseline. Bind tests to local port with escalation only if sandbox requires it.
- [x] Fix default schema loading using direct JSON load, remove machine-specific paths, handle malformed schemas and dependency absence honestly. Validate bundled references offline. Add formal validation dependency to development/CI installation and a real CI step that generates representative code, TLS and IaC exports and fails on non-True validation. Preserve existing branch filters (broader branch-filter fixes are outside this task).
- [x] Route browser Markdown through shared server renderer using displayed ID. Fix CBOM handler; surface expired scan errors inline. Ensure every demo response has its own recorded identity without mutating old history entries.
- [x] Run export/schema tests and existing `test_cbom`, dashboard tests. Browser verify: real scan then load demo, export correct CBOM and Markdown; open old history and export correct target; simulate expired ID and verify an error with current report retained.
- [x] Commit task files with `fix(exports): bind artifacts to scan identity and validate schemas`.

### Task 3: Stable comparison and full integration (fix 14 plus visible completion of 6–7)

**Files:** `crypto_source.py`, `code_scanner.py`, `adapters.py` only if identity evidence needs completion; `dashboard.py` or focused comparison module; `scan_results.py`; `web/index.html`; new `test_audit_comparison.py`; README audit note.

**Interfaces:** Preserve comparison list fields. Stable source key includes normalized relative file, scope/function, canonical call/purpose and rule, with occurrence pairing for duplicates; excludes generated IDs and shifting line numbers. Exact snippets are evidence, not persisted secret-containing identifiers. Existing reports without richer identity retain conservative legacy matching and an identity-confidence warning. No improvement claim from lost coverage, changed source scope/files, incompatible settings/rules, or demo data.

- [x] Write regression: prepend blank lines and finding persists; move one MD5 use from function A to function B and it is newly/previously observed rather than same use; duplicate calls retain multiplicity; reordered findings preserve identity; weak→adequate KDF is absent/new evidence with parameters retained.
- [x] Write regression: removed/skipped/unsupported source file, narrower quantum_only filter, incomplete/unresolved evidence, changed targets/scenario/rules/modules, and differing demo status never yield status improved. Same-scope explicit full evidence may improve after actual removal of a weak operation. Missing metadata is conservatively inconclusive, with readable warnings.
- [x] Run new tests and confirm failure. Implement source evidence and robust compatibility checks. Keep 'absent from comparison' distinct from verified remediation. Make current coverage counts/reasons and unresolved critical/asset counts visible in UI and shared Markdown, near the existing score. Preserve existing layout.
- [x] Run focused source/export/comparison tests, full unittest discovery and real `demo_migration.py`. Record known baseline failure separately. Run browser desktop/mobile checks for new summary visibility, old report exports, comparison warnings and actual clean/weak KDF outputs.
- [x] Obtain an independent code review of security boundaries, uncertainty handling, schema network isolation and scan identity, resolve important findings, then rerun affected checks.
- [ ] Commit `fix(comparison): preserve evidence identity and reject coverage regressions`. Push only `fix/qshield-v1.4-audit` after verification; if repository write access is unavailable, retain local commits and report the exact blocker.
