# Remaining audit fixes — desktop scope

Implemented locally on `Aditya-Singh-AIML`, continuing the [original fixes 1–14](AUDIT_FIXES.md). Release identity is **1.4.1**, derived from `version-1.4`. Git branch names cannot contain spaces; this is the valid form of the requested “Aditya Singh AIML” name.

| Item | Result |
| --- | --- |
| 15 | Independent TLS inspection, trust, protocol, group and cipher probes retain identities, client versions, timestamps, observed peers/fingerprints and correlation. A separate group cannot establish the inspected connection's PQ protection. |
| 16 | Cipher/protocol attempts distinguish accepted, definite remote refusal and unknown local/transport/timeout outcomes. Deep enumeration records actual bounded candidate coverage; incomplete coverage cannot establish improvement. |
| 17 | Every inventory finding exposes effective planning context, assumed/user-confirmed provenance and rationale. Unknown lifetime values remain unknown. |
| 18 | `/api/reassess` validates confirmed context and assesses server-owned inventory using exact cached rules. It creates a new parent-linked report without changing original evidence or running another scan. Desktop controls update all findings in the selected asset group. |
| 19 | Horizons are conditional assumptions, Grover query scaling is qualified by practical limits, and the hybrid demo is described as a local functional check rather than authenticated transport or compliance evidence. |
| 20 | UI and Markdown distinguish leaf inspection, separate system trust validation, unassessed full-chain inventory and revocation not checked. |
| 21–22 | Development requirements include validation dependencies; CI covers development/release branches, offers manual execution, compiles actual tracked Python files and verifies committed browser assets. |
| 23 | Explicit roots reached through canonical parent aliases work on macOS. Descendant symlinks and swaps remain excluded through anchored no-follow traversal for source and IaC. |
| 24 | The existing output-failure test uses a regular-file parent and verifies failure without damaging that parent. |
| 25 | Regression coverage includes containment/portability, TLS outcomes/provenance, immutable context updates, export/version parity, offline assets and rendered desktop interactions. |
| 26 | `qshield_version.py` is the Python release authority. CLI scans, health, CBOM tool metadata and dashboard badge agree on 1.4.1; engine/rules versions remain separate concepts. |
| 27 | Current documentation uses executable checks and explicit evidence boundaries. Earlier test counts are historical records, not current readiness claims. |
| 28 | React 18, CSS and fonts are local committed assets with licenses and pinned rebuild dependencies. Python dashboard runtime needs no Node or CDN. |
| 29 | The scan form appears in the first desktop screen with mode-specific targets and secondary optional settings. |
| 30 | Incident learning and visual exploration remain available in secondary disclosures after actionable evidence. Navigation opens the relevant disclosure. |
| 31 | Demo report/counter groups are explicitly labeled illustrative. |
| 32 | Successful scans, history opens and planning updates focus/scroll results, respecting reduced motion. Initial demo loading does not move the viewport. |
| 33 | **Excluded at the user's request.** No mobile-specific fixes or final mobile acceptance tests were added. Existing responsive stylesheet rules remain unchanged. |
| 34 | Desktop evidence paths wrap; practical controls/captions have larger text and visible focus states. Optional chart controls measured at least 12px. |
| 35 | The named native evidence dialog has explicit initial focus, Tab/Shift+Tab containment, Escape, focus restoration, inert background and scroll lock. |
| 36 | Timeline separates initial OneCRL distribution on 17 October from Mozilla's 20 October publication/additional releases. |

## Verification

Verified locally on 30 October 2026 using native ARM Python 3.14 and Node 22. No claim is made that remote GitHub Actions or deployment checks ran.

- Final Python discovery at `d7b69b5`: **265 passed**, 7.080 seconds, exit 0; no warning/failure markers.
- `python tools/validate_cbom_exports.py`: source, remediated source, IaC and synthetic TLS all formally valid against bundled offline schemas.
- `node tools/build-web.mjs --check`: committed asset membership and bytes match the pinned source build.
- The complete `tools/verify-desktop.mjs` assertion function ran successfully against the local server: first-screen scan entry, settled dialog focus/keyboard cleanup, real three-finding asset reassessment with 30-year retention and migration zero, unknown-field omission, new parent-linked identity, failure preservation, scan success/failure, navigation and chart filtering.
- Independent browser checks at 1280×800: initial scroll 0, scan form top about 311px and submit bottom about 608px. At 1440×1000 the form remains in the first screen. No mobile viewport acceptance was performed after its scope was removed.
- External browser requests blocked: local assets/fonts loaded and a real source scan returned 17 inventory findings; version matched across badge, scan and health. Task 5 retains that local asset graph.
- Deferred-response regression at `faf9a8c`: held obsolete reassessment success and failure responses both left the newer real scan selected; request invalidation prevents stale result/error state after report changes.
- Individual desktop checks also exercised TLS unknown/mismatched probe disclosure, session history/comparison and JSON/Markdown/CBOM downloads. Expected HTTP400/409 cases preserve the displayed report.

Run the backend/build gates from the repository root:

```sh
python -m pip install -r requirements-dev.txt
python -m unittest discover -s . -p 'test_*.py' -v
python tools/validate_cbom_exports.py
npm ci
node tools/build-web.mjs --check
```

Start `python dashboard.py --port 8765 --no-browser`, then import the default function from `tools/verify-desktop.mjs` and call it with a connected Playwright page. The function uses local sample scans and controlled failure responses; it performs no external TLS scan. See [asset build instructions](FRONTEND_BUILD.md), [TLS boundaries](TLS_EVIDENCE.md) and [source boundaries](SOURCE_EVIDENCE.md).

History and exact-rule snapshots are bounded, process-local stores. A missing snapshot requires a new scan. Context updates are planning updates, and comparisons always report `remediation_verified: false`. Full-chain/revocation discovery and an authenticated migration transport remain outside this repair scope.
