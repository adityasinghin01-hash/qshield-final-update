# Source evidence and password-cost policy

`scan_code(path, ignore_comments=False, quantum_only=False)` keeps its existing
arguments and fields. These fields are additive; they are not a repository safety
or compliance certificate.

`coverage` records `supported_files`, `unsupported_files`, `attempted_files`,
`scanned_files`, `excluded_files`, sorted root-relative `scanned_paths`,
`exclusions` (`path`, `reason`), `unresolved` diagnostics, `settings` and
`capabilities`. Supported/attempted counts describe regular files classified for
the supported analyzers. Exclusions count entries, including directories whose
contents were deliberately not traversed; they are not a count of every file in
an excluded subtree. Ordinary documentation and images are not unsupported source
errors. Known unsupported source languages, excluded entries, parse failures and
unresolved syntax make legacy `coverage_status` partial. A quantum-only filter
also leaves overall evidence partial.

Source opening uses POSIX directory descriptors, `O_DIRECTORY`, `O_NOFOLLOW`,
regular-file checks and a 10 MiB bounded read. Every ancestor is opened relative
to its already opened parent. All symlinks are excluded, even when their targets
are inside the selected repository. Unsupported platforms fail closed rather
than falling back to following paths. Source code is parsed, never executed.

Normalized findings preserve safe `attributes.parameters` and their shared
`kdf_assessment` (`status`, `reasons`, `unknown_reasons`, `policy_source`). Only
explicit, bounded non-secret settings are extracted. KDF snippets omit all
password/salt arguments. Missing or dynamic digest/cost/salt-derived settings,
unsupported variants, and unobserved library defaults remain unknown. Explicit
weak settings add `WEAK_KDF_PARAMETERS` on the conventional track. An adequate
cost alone does not establish correct salt generation, password handling or
runtime behavior.

The policy follows the [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html),
reviewed 2026-10-30: PBKDF2 SHA-256 600,000; SHA-512 220,000; legacy SHA-1
1,400,000 iterations; bcrypt minimum 10 rounds. Argon2id accepts the memory KiB /
passes tradeoffs (47,104 / 1), (19,456 / 2), (12,288 / 3), (9,216 / 4),
(7,168 / 5), with explicit positive parallelism and valid per-lane memory.
No salt or variant defaults are inferred. Scrypt is observed but its cost policy
is not implemented and therefore remains unknown.

`source_scope` is the Python class/function path, or a best-effort JS lexical
function/class path; `source_call` is the canonical callee without arguments.
`source_identity` version 1 contains `relative_path`, `scope`, `call`,
`match_type`, `occurrence`, and `anchor` (SHA-256 of the sorted-key JSON of the
other fields, including version). Occurrence is one-based within each
scope/callee/match-type group. Line-only movement preserves the identity. Two
calls on one line remain separate. Reordering repeated identical calls,
renaming files/scopes or changing syntax can change identity; consumers must
treat ambiguous matching conservatively. Identity is not a hash of secret
arguments or a proof of behavioral equivalence.

The report summary exposes `unknown_finding_count`, aggregate `unknown_count`
and `unknown_reasons` (finding reasons, unresolved diagnostics, excluded entries),
`unresolved_critical_count` (unknown findings explicitly marked critical),
`affected_asset_counts` (distinct observed assets with non-info assessments,
split by track, and unknown observed assets), and detailed source coverage.
Multiple assessment rules on one source file count as one affected asset.
Excluded subtrees have unknown severity; zero known unresolved critical findings
does not establish absence of critical problems there. Incomplete evidence makes
the posture score N/A. Import/comment inventory never becomes active risk.

Alias resolution deliberately favors unknown over guessed identity. Python
handles single unconditional scoped imports and call aliases, rejects competing
writes/namespace mutation and bounds literal resolution. JS/TS recognizes dotted,
literal-computed and optional callees, but it is a lexical analyzer rather than
a full JS/TS parser; shadowed, reassigned, conditional or dynamic evidence is
not assumed to establish a crypto namespace. Reflection, runtime settings,
interprocedural flow and arbitrary library defaults are not resolved.

TLS certificate normalization preserves the scanner's `fingerprint_sha256`
field (and its legacy nested representation when provided). Missing fingerprints
remain missing.
