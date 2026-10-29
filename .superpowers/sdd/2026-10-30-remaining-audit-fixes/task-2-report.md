# Task 2 — TLS provenance and certificate boundaries

Implemented remaining items 15–16 and 20. Independent inspection, trust, OpenSSL,
protocol and cipher handshakes retain safe provenance and observed leaf identity.
Main-connection group/PQ status remains unknown; successful OpenSSL group evidence
is assessed on its own scoped asset. Unknown/mismatched correlation propagates
partial coverage. Cipher enumeration retains accepted/rejected/unknown attempts,
candidate counts and bounded work. Comparison validates actual complete coverage
and refuses narrower/lost/unknown outcomes while permitting equal complete deep
coverage, including conclusively rejected candidates with an empty accepted list.

Boundary and precise additive response-field contract: `docs/TLS_EVIDENCE.md`.
Existing compatibility keys and default direct probe/list APIs remain. Shared
Markdown reports leaf-only inspection, separate system trust, full-chain inventory
unassessed, revocation not checked, and probe outcome/correlation diagnostics.
TLSv1/TLSv1.1 expected deprecation warnings are scoped only to the intentional
legacy-version assignments; no global suppression was added.

TDD: initial 9 tests exposed missing interfaces plus real false-rejection and
warning failures. Review added 5 tests exposing 8 failures in partial status,
failed CLI evidence, safe errors, malformed input, and comparison coverage; all
14 focused TLS tests passed after fixes. Added the complete empty-accepted-list
comparison assertion; included in the subsequent full-suite run.

Verification: full default-environment suite **251 passed**, 7.111s, exit 0 in
`/private/tmp/qshield-remaining-default.log`, using the specified native venv and
escalated loopback access. Formal CBOM gate: source/remediated/IaC/synthetic TLS,
all four valid, exit 0. Focused mixed suite initially encountered two sandbox
loopback-bind setup errors; the full escalated run covers those cases. A redundant
focused escalation stalled and was interrupted; no result claimed for that run.

Self-review corrected failed CLI group promotion, stale group attribution, safe
main error categories, missing/unknown independent probe comparisons and real
attempt validation. No external live/deep endpoint scans were run. Full-chain
inventory/revocation remain explicitly out of scope. Parent UI/offline build
changes are excluded from this commit.
