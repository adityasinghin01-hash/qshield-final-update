# Task 5 — Desktop task flow, business context and evidence accessibility

Implemented the approved desktop scope; mobile-specific item 33 is excluded at the user's request. The entire prior `web/command.css` prefix (including every responsive rule) is preserved verbatim, verified against HEAD. No mobile viewport checks were performed.

The compact introductory text and mode-specific scan form precede results. Only relevant target fields appear; extra scan settings sit in a disclosure, and irrelevant deep/source settings are false in requests. Actual scan, history-open and confirmed-context success focus and scroll the results summary with reduced-motion support; initial demo does not move the viewport. Results carry report identity/type and a direct evidence link. Globe, interactive charts, attack-surface/horizon exploration and incident learning remain available below actionable evidence in optional disclosures. Navigation opens their ancestor disclosures. Original fonts/palette/globe and meaningful chart interactions remain. Demo counter groups are explicitly labeled. Evidence paths wrap; body/control/caption sizes and visible focus states are increased.

`PlanningContext` groups every inventory finding by exact asset and submits all finding IDs in the selected group. Five fields expose current values, mixed values, assumed/user-confirmed provenance and rationale. Edited or explicitly checked fields are confirmed; blank unknown years are omitted, and zero is displayed/submitted as zero. Full successful `/api/reassess` responses replace the report; failures preserve the old one. The derived report explains parent identity and original evidence timestamp.

`TLSProvenance` distinguishes inspection groups from the separate OpenSSL observation and correlates leaf fingerprints without merging negotiated parameters. It displays per-probe stage/outcome/client/fingerprint/correlation/ID/time/endpoint/error category, trust-probe attribution, candidate enumeration counts and leaf-only/separate-trust/full-chain-unassessed/revocation-not-checked boundaries. Legacy demo observations disclose absent per-probe provenance.

The evidence inspector is a native modal dialog in a body portal with an accessible title/named close, initial focus, explicit Tab/Shift+Tab boundary handling, Escape, opener focus restoration, inert application background and body scroll lock. Closed-details descendants are excluded from focus candidates. The incident timeline distinguishes 17 October initial OneCRL distribution completed 22:59 UTC from 20 October publication/additional releases; existing optional primary source links remain, with no automatic external fetches.

## Rendered desktop verification

Actual Playwright browser interactions at local dashboard `127.0.0.1:8765`, **1440×1000**:

- Initial demo scrollY 0; scan heading top 311.2px and submit bottom 604.0px in the first UI pass, versus prior form top 2091px. Root independently checked final layout at 1280×800: form top 311px, submit bottom 608px and initial scroll 0.
- Dialog starts on named close; Shift+Tab wraps to footer close and Tab wraps back; attempts to focus app controls are blocked. Escape closes and restores opener; inert and scroll lock are cleared. Native-only forward wrapping exposed a body-focus gap, which was fixed with explicit boundary handling and rechecked. Independent root review also caught initial focus settling on the scroll container: React autoFocus did not emit the attribute used by the query. The dialog now explicitly focuses its named close control after showModal and inert setup. Root rechecked settled initial focus after reload: BUTTON / “Close evidence inspector”, root inert true and body overflow hidden; Shift+Tab → footer “Close Inspector”; Tab → named close; Escape restored opener and cleared root inert.
- Actual sample repository scan focuses `results-summary`. Reduced-motion mode exercised. Invalid repository scan keeps the previous report and displays the error.
- Real reassessment submitted three IDs for the shared demo endpoint with retention 30 and migration 0, omitted untouched unknown/mixed trust, returned HTTP200 with new ID and parent identity, kept trust assumed, and displayed 0. Controlled HTTP409 preserved the report. Password-storage evidence displays unknown lifetime inputs as blank/Unknown/Assumed rather than 0.
- Controlled TLS UI fixture: inspection group unknown; separate hybrid group with mismatched leaf; trust true with unknown leaf correlation; one detailed per-probe row; partial local-candidate enumeration 4 candidates/3 attempted/1 accepted/1 rejected/2 unknown. No main-connection PQ-active claim appeared.
- History contained 12 runs; open focused results; comparison returned inconclusive with scope/unknown/demo warnings. Actual JSON, Markdown (36,785 bytes) and CycloneDX CBOM (62,881 bytes) downloads parsed.
- Horizon navigation opened the closed exploration disclosure, severity-chart click applied its filter, and incident navigation exposed 17 October 22:59 UTC wording. Optional exploration had 65 visible buttons with minimum computed font size **12px** after readability updates.
- Screenshot captured by browser tool as `qshield-task5-desktop.png` in its artifact output. The repeatable core assertion function is `tools/verify-desktop.mjs`; it exercises rendered behavior against the local backend, not source strings. It supplements the individual executed interactions recorded above.

## Checks and boundaries

- `npm run build:web` and `node tools/build-web.mjs --check`: passed, including final demo-counter label change.
- Approved full default-environment Python suite: **265 passed**, 9.812s, exit 0. `/private/tmp/qshield-remaining-default.log` contains the complete output.
- `python tools/validate_cbom_exports.py` using native task venv: source, remediated, IaC and synthetic TLS exports formally valid offline.
- `git diff --check`: clean. Self-review covered request omissions, all asset IDs, failure state, null/zero semantics, modal cleanup/hidden focus candidates, navigation disclosures and unchanged responsive CSS.

No external TLS scan or bulk network request was made. Primary incident facts were supplied by the previously checked reference notes. No full-chain or revocation service is implemented. Root owns final independent acceptance, refreshed portable bundle and any origin-push limitation. These are scoped local checks, not remote CI or deployment verification.

## Review fix round 1 — obsolete reassessment response

Independent review found that a pending context response could call the old form's `onUpdated` after a newer scan/history report unmounted it. Reproduced against base `d7b69b5` using a Playwright route that fetched the real `/api/reassess` result, held its response, completed a new local repository scan, then released the old result. **RED:** newer `scan_8b673480dc7c459981593300c85e1bbe` was replaced by delayed `scan_f4563de599a64c4694350752ecf0b5db` (`newerPreserved=false`, `obsoleteInstalled=true`).

`PlanningContext` now owns an AbortController in a request ref. Unmount first invalidates the ref and aborts its pending fetch. Result application, catch/error state and finally/busy state require the same still-current request; duplicate pending submissions are ignored. This prevents stale completion even if delivery races cancellation.

Added exported `verifyReassessmentLifetime(page)` to `tools/verify-desktop.mjs`. The function performs real local scans and controls only response timing/status. Ran it through `browser_run_code_unsafe` using the function source read from that file (removing the module export for the browser tool). **GREEN:** delayed success preserved newer `scan_1e10b3c282ed4bf3a60cc76c52023446`; delayed HTTP409 preserved newer `scan_0963f488b1c742f8b7073308a798e127` and produced no obsolete error in its UI. Both responses were released only after the newer report identity appeared.

Also executed the complete existing `verifyDesktop(page)` assertion function through the browser tool: initial scroll 0; form top 311.2px, submit bottom 608.5px at 1440×1000; dialog checks passed; 3-ID confirmation/new report/zero/error preservation passed; actual scan success/failure checks passed; navigation passed; 56 rendered optional buttons had minimum 12px computed size for that scan. No fixture routes remain installed.

`npm run build:web`, `node tools/build-web.mjs --check`, `node --check tools/verify-desktop.mjs` and `git diff --check` passed. No Python or backend changes; the 265-test suite was not repeated for this UI request-lifetime fix. Parent release documentation remains outside this commit.
