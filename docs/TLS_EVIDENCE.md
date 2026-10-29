# TLS evidence and coverage boundaries

The scanner inspects the main handshake's leaf certificate only. System trust-store
and hostname validation uses a separate Python handshake. Full-chain inventory is
**unassessed**; revocation is **not checked**. Trust success applies to the trust
probe, not automatically to the inspected certificate.

Each independent handshake has a `probes` entry: unique `id`, `stage`, UTC
`timestamp`, requested `endpoint`, nullable observed `peer_address` and
`certificate_fingerprint_sha256`, `client` implementation/version, `status`,
`outcome`, safe `error_category`, `attribution`, and `correlation_to_inspection`.
Protocol attempts add `protocol`; cipher attempts add `cipher_name`. Failed
handshakes often cannot expose a fingerprint; it stays null. No raw PEM, key
material or arbitrary subprocess output is retained.

Correlation is `matched`, `mismatched` or `unknown` using observed leaf SHA-256
fingerprints only. Matching hostname, address or leaf never establishes the same
connection or negotiated parameters. Inspection is the reference and has no
independent correlation.

`key_exchange.group` and `post_quantum_or_hybrid_group` describe inspection and
remain null when Python cannot observe its group. OpenSSL's separate observation
uses `group_probe_id`, `probe_group`, `probe_post_quantum_or_hybrid_group`,
`correlation_to_inspection`, and `openssl_probe`. Successful group evidence is
assessed on an asset ending `#key-exchange-probe`, never as the main connection's
PQ protection. Failed CLI output cannot promote a group. Legacy supplied
telemetry remains compatible; its provenance cannot be reconstructed.

`certificate_validation.trusted` applies to its `probe_id`, with leaf correlation
reported separately. `coverage` contains `certificate_inspection: leaf_only`,
`system_trust: separate_handshake`, `full_chain_inventory: unassessed`, and
`revocation: not_checked`.

`supported_protocols` preserves true/false/null compatibility. Only explicit peer
negotiation refusal establishes false. Timeout, transport/local-context failures,
and ambiguous TLS errors remain unknown. Unknown outcomes and accepted probes
with unknown/mismatched correlation propagate partial scan status and diagnostics.

Deep `cipher_enumeration` contains `accepted`, per-attempt `attempts`,
`candidate_names`, `candidate_count`, `attempted_count`, `accepted_count`,
`rejected_count`, `unknown_count`, `status`, `scope`, `settings`, and optional safe
`error_category`. `supported_tls12_ciphers` remains the accepted list, adding each
entry's `probe_id`. Direct `enumerate_tls12_ciphers(...)` defaults to the list;
`detailed=True` returns the record. Protocol probes similarly retain the default
mapping and accept `detailed=True`.

Enumeration limits work to 64 attempts and a 30-second connection budget; local
context creation/cleanup add overhead. Each connection receives the smaller of
its timeout and remaining budget. Candidates belong to the current local TLS 1.2
client, not every possible suite. Every recorded candidate must have a conclusive
outcome for `complete`; unknowns or exhausted budgets produce partial coverage.

Comparison checks actual attempts, candidate identity, settings, scope, and probe
coverage. Missing/narrower/unknown coverage cannot establish improvement. Equal
complete local-candidate coverage can compare, including empty accepted lists
when every candidate was conclusively rejected. Comparison remains observed
change, not verified remediation. Shared Markdown includes boundaries and probe
diagnostics. Tests use controlled sockets/subprocesses; no external bulk scan or
full-chain/revocation service is implemented or implied.
