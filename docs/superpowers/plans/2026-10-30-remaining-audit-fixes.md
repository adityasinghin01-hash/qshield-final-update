# Remaining Q-SHIELD audit fixes Implementation Plan

> **For agentic workers:** Use subagent-driven-development for scoped implementation/review, or execute dependent tasks inline. The user explicitly authorized completing the remaining numbered fixes in chunks.

**Goal:** Finish audit items 15–36 except mobile-specific item33 (removed by user30Oct2026) on the local branch `Aditya-Singh-AIML`, preserving all already committed 1–14 fixes.

**Architecture:** Keep the Python scanners/server and the existing React dashboard. Make source/IaC path handling portable without weakening descendant containment; retain individual TLS-probe provenance/outcomes; add explicit per-asset planning context and server-side reassessment of immutable scan snapshots. Build and vendor the existing frontend locally and improve the primary scan/results journey and accessibility.

**Tech Stack:** Python 3.11+, cryptography, PyYAML, python-hcl2, jsonschema, unittest; existing React 18 UI with local compiled assets and local fonts/CSS. A Node development build is acceptable; running the Python dashboard must not need Node or external network assets.

## Global Constraints

- Repository `/Users/aditya/dev/innotech-qshield-v1.4-review-20261030`, branch `Aditya-Singh-AIML` (spaces are not valid Git branch syntax). Base `827f804`; never force-push or modify main/version-1.4.
- Execution order is user chunk 21–25, then 15–20 (two internal tasks), then 26–36 (two internal tasks). Review and commit each task; do not discard existing source/export/comparison fixes.
- Baseline 231 tests pass with canonical TMPDIR=/private/tmp. Goal is default-environment local tests passing, plus CI-suitable portable tests. `requirements-dev.txt` already installs all dependencies; existing CBOM unwritable-parent fixture is already portable.
- Use `/private/tmp/qshield-review-arm-venv-20261030/bin/python`. New behavior needs meaningful failing tests first. Low-impact wording/CSS need direct browser/content verification, not implementation-mirroring tests.
- No scanned repository code executes. Preserve bounded source reads, no-follow descendant opens and secret redaction. Failures, omitted probes, unsupported settings and unknown evidence must not become safety claims.
- Do not add full arbitrary migration/autofix features, enterprise accounts, live incident feeds, or full revocation services. Item20 is precise coverage disclosure; full-chain/revocation discovery was explicitly a larger follow-up in the approved list.
- Primary references checked: https://docs.python.org/3.11/library/ssl.html ; https://csrc.nist.gov/projects/post-quantum-cryptography/faqs ; https://blog.mozilla.org/security/2026/10/20/protecting-firefox-users-following-the-compromise-of-emudhra-intermediate-certificates/ . Use conditional planning language; AES-128 is not currently broken by a practical quantum attack. Mozilla initial OneCRL distribution completed 17Oct2026; 20Oct was publication and additional releases.
- User authorized local commits. Origin push previously returned403 for authenticated accountadityasinghin01-hash. Preserve local work/bundle if access still unavailable; do not create a fork or change authentication without authorization.

### Task 1: CI, path portability and regression coverage (items 21–25)

**Files:** `.github/workflows/qshield-ci.yml`, `code_scanner.py`, `iac_scanner.py`, focused `test_audit_portability.py`, existing path-sensitive tests only if their own assumptions are invalid, optional shared safe-path helper.

**Interfaces:** Preserve source/IaC scanner APIs, dashboard workspace boundary and descendant-symlink exclusions. Define the explicit submitted root separately from descendant entries. Canonicalizing a selected root's parent (e.g. macOS /var→/private/var) is allowed; direct target symlinks and nested symlink escapes must still be excluded. Source no-follow opens remain descriptor-anchored.

- [ ] Reproduce default-environment tests and create failures for source+IaC reached through a symlinked ancestor pointing to the same authorized directory; supported regular source and config must scan. Retain direct/nested symlink and ancestor/leaf race cases that prove external marker bytes never appear. Add a path with spaces and a directory root/file root case.
- [ ] Implement root canonicalization without following descendant symlinks or weakening dashboard resolved containment. IaC file reading stays no-follow/bounded and never evaluates templates. Recognize and report unsupported platforms honestly.
- [ ] CI installs `requirements-dev.txt`, covers pushes/PR targets for main,integration,version-* and Aditya-Singh-AIML (or all branches if simpler), and offers manual workflow_dispatch. Compile actual Python modules/tests without an obsolete hardcoded14-file list; run unittest discovery and offline CBOM gate. Do not claim remote GitHubActions ran.
- [ ] Run new portability tests, all containment/source/IaC/CLI suites, then full discovery using default environment (no TMPDIR workaround). Record RED/GREEN and commit Task1 files only. Existing portable CBOM failure test must retain its real failure and intact-parent assertion.

### Task 2: TLS provenance, enumeration outcomes and certificate boundaries (items 15–16,20)

**Files:** `tls_scanner.py`, `adapters.py`, `scan_comparison.py`, `scan_results.py`, focused `test_audit_tls.py`, boundary docs. Parent integrates UI disclosure later.

**Interfaces:** Existing keys remain, with additive `probes`/`coverage`/`cipher_enumeration` records. Each independent handshake/probe has an ID, stage, timestamp, endpoint/peer address when observed, certificate fingerprint when observed, client implementation/version, status/outcome and attribution. The main Python handshake and verified/OpenSSL probes are never asserted to be one connection. Key-exchange evidence must retain its actual probe provenance and identity mismatch/unknown correlation.

- [ ] RED tests with controlled sockets/subprocess results: matching versus different leaf fingerprints across inspection/trust/group probes; unavailable CLI; timeout; explicit protocol rejection versus local unsupported error. Do not make test assumptions that two calls are the same peer.
- [ ] For optional TLS1.2 enumeration, preserve accepted compatibility list but add per-attempt outcome accepted/rejected/unknown, safe error category and attempted/candidate counts. Timeout/OSError/local context failure must be unknown, not rejected. Only definite remote negotiation refusal may be rejected. Partial enumeration propagates diagnostics/partial coverage. Bound total work and keep direct API compatibility where practical.
- [ ] Record actual certificate observations from each available handshake. OpenSSL output can yield the probe's leaf fingerprint; missing output leaves it unknown. Correlation is matched/mismatched/unknown, never inferred from hostname equality. Avoid exporting raw PEM/key material or arbitrary subprocess output.
- [ ] Clearly expose leaf-only inspection, separate system trust-store validation, full-chain inventory unassessed and revocation not checked. Shared Markdown includes these boundaries and provenance/outcome diagnostics. Comparison refuses improvements from narrower/lost/unknown probe coverage and uses recorded enumeration coverage rather than always blanket-rejecting every complete deep scan.
- [ ] Run controlled TLS/adapter/CLI/comparison regressions, full suite and schema gate. A single optional ordinary live endpoint scan may verify integration, but no external bulk/deep probing is required. Commit only task files and report interfaces for parent UI.

### Task 3: Planning assumptions, confirmed asset context and precise threat claims (items 17–19)

**Files:** `main.py`, `adapters.py`, `risk_engine.py`, `rules.json`, a focused planning-context helper, `dashboard.py`, `scan_results.py`, `demo_migration.py`, relevant tests/docs. Parent owns frontend edits and consumes returned API.

**Interfaces:** Every finding exposes its effective retention/trust lifetime, migration duration, exposure and criticality with provenance `assumed` or `user_confirmed` and rationale. Expose explicit per-asset overrides; validate numbers as finite nonnegative bounded years, reject booleans/nonobjects/unknown assets. An API re-evaluates a stored scan by ID using server-owned inventory and effective rules, stores a NEW immutable derived result and links parent scan. Never trust client-submitted replacement findings/score/rules, never silently use a different ruleset, and do not rerun network scans just to change planning context. Preserve source scan/evidence and its unknown status. Provide CLI context input if straightforward but API+UI is required.

- [ ] RED tests: identical crypto with confirmed30-year versus1-year retention changes relevant server-side Mosca assessment; defaults labeled assumed; explicit confirmed zero respected; invalid NaN/Infinity/negative/bool/unknown asset rejects400; old snapshot unchanged; missing/stale scanID404; differing rules refuse or use exact server-held rules; unknown evidence stays unknown after reassessment; context exported in JSON/Markdown/CBOM safe metadata.
- [ ] Implement shared context validation/application and immutable reassessment. Ensure inherited metadata is truthful: derived scan identifies planning update, original evidence timestamp/parent, updated assumptions, not newly measured TLS. Business context changes make comparisons scope-warning/inconclusive rather than verified remediation.
- [ ] Tighten risk/demo/Q&A wording: assumed horizons conditional, no prediction that adversaries will decrypt in a precise year; practical Grover caveats; AES-128 quantum margin is planning context and not proof currently broken; hybrid demo is local functional evidence not authenticated transport or compliance. Preserve public-key quantum migration relevance.
- [ ] Run focused context/API/rules/score/exports/comparison regressions, demo and fullsuite. Commit Task3 code; document exact context/reassess request/response contract for frontend integration.

### Task 4: Version/release consistency and offline asset delivery (items 26–28)

**Files:** central version module, `main.py`, `cbom.py`, dashboard version source/UI, release docs, `web/` assets/source/build files, pinned Node development manifest/lock/build script and attribution.

- [ ] Align explicit release version to1.4.1 (audit repair release fromversion-1.4) using one Python authority. Dashboard gets version from scan/health, not a separate hardcoded string. CBOM metadata/CLI must match. Retain engine/ruleset versions as distinct concepts.
- [ ] Replace outdated fixed35-test/production-ready assertions with commands and current verified scope. Explain three chunks, source/POSIX limits, frontend build/runtime requirements and evidence boundaries accurately.
- [ ] Compile current JSX and Tailwind utilities into local static assets; local React runtime, local fonts (or retain visual style through packaged equivalents), no CDN/Babel runtime dependency. Keep React18 to avoid unnecessary migration. Node only for deterministic pinned rebuild; Python serves built assets.
- [ ] Verify local asset graph and attribution, no external subresource requests, clean asset rebuild, schema/CLI/exportversion parity. Browser checks with external network blocked must render and run a local source scan. Commit Task4 files.

### Task 5: Primary desktop task UX, dialog accessibility and incident chronology (items 29–36; frontend integration for17–20)

**Files:** existing frontend source/styles (nowbuiltlocally), controlled browser verification script/artifacts, README/release notes.

**Design decision:** Preserve dark green/acid palette, existing typography/globe and meaningful chart interactions. The first desktop screen contains a compact scan entry and mode selector; long incident story moves to a secondary learning disclosure/view. Optional globe/horizon exploration follows actionable results. Report summary/evidence appear immediately after scan. Clearly label demo counters and carry scanidentity/type throughout.

- [ ] Integrate asset-planning controls from Task3 near evidence/inventory: perasset confirmed retention/trust/migration/exposure/criticality with defaults clearly assumed, submit server reassessment and show derived planning result/errors without replacing old scan on failure. Render TLS per-probe provenance/unknown coverage and leaf/chain/revocation boundaries fromTask2.
- [ ] Move scan entry into firstscreen, conditionally show relevant input fields, keep optional scanning settings secondary. After success focus/scroll to results summary respecting reducedmotion; make evidence the next action. Retain history/export/compare functions and avoid misleading visuals.
- [ ] Desktop readability: wrap long evidence paths, retain usable table/tab navigation, increase small body/control/caption text and visible focus states. User removed mobile fixes on30Oct2026: no mobile-specific layout, overflow, breakpoint or viewport-testing work (item33 excluded). Preserve pre-existing responsive CSS.
- [ ] Evidence inspector uses role=dialog, aria-modal, accessible title/close name, initialfocus, tab/shift-tab containment, Escape close, returnfocus to opener, scroll lock and background inertness. Verify keyboard behavior against actual rendered UI, not source-string assertions.
- [ ] Incident timeline distinguishes17Oct initial OneCRL distribution from20Oct public response/additional releases; source links remain accurate and optional, and UI works offline without auto-fetching them.
- [ ] Verify desktop/offline navigation, scan/failure/unknown/KDFcontext/reassess, exports/history/compare and dialog keyboard. Rebuild assets, run fullPython suite/schema/runtimechecks, obtain scoped and final independent review, resolve important findings, commit each finished chunk. Save final verification notes and refreshed portablebundle. Only retry origin push if current permission allows; if403 persists report exact limitation.
