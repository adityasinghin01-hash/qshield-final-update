# 🏆 Q-SHIELD Release Checklist, Architecture Defense & Judge Q&A

This document provides the official Project Lead release checklist, end-to-end architecture explanation, and technical defense guide for hackathon judges and security auditors.

For the 1.4.1 audit repair release, use `qshield_version.py` as the application version authority. Run `python -m unittest discover -s . -p "test_*.py"`, `python tools/validate_cbom_exports.py` and `node tools/build-web.mjs --check` after installing the development dependencies. Python serves the committed React 18 assets without Node or CDN requests; Node 22 is needed only to rebuild them with `npm ci` and `npm run build:web`. See [asset build and attribution](FRONTEND_BUILD.md) and [current evidence boundaries](../README.md#audit-repair-scope). Remote CI and branch protection need separate evidence.

---

## 📋 Release Readiness Checklist

These original checklist entries predate the current audit and do not establish current release status. Use the current audit report and fresh local/CI evidence for release decisions.

| Category | Item | Verification Command / Check | Lead Status |
| :--- | :--- | :--- | :--- |
| **Git Safety** | Current branch verification | `git branch` $\rightarrow$ must be on `member/lead` or `integration` | ✅ **VERIFIED** |
| **Git Safety** | Direct push prohibition | No direct commits to `main`; all releases flow via PR from `integration` | ✅ **VERIFIED** |
| **Code Integrity** | Python Bytecode Compilation | `python -m py_compile ...` across all 14 project modules | ✅ **PASSED (14/14 files)** |
| **Test Quality Gate**| Automated Test Suite Pass | `python -m unittest discover -s . -p "test_*.py" -v` | ✅ **PASSED (35/35 tests)** |
| **Discovery** | TLS Network Handshake | `python main.py --host google.com` | ✅ **VERIFIED** |
| **Discovery** | Static Source Code AST Scan | `python main.py --repo sample_vulnerable_app` | ✅ **VERIFIED** |
| **Fault Tolerance** | Graceful Network Recovery | `python main.py --host invalid-offline-target.test` continues cleanly | ✅ **VERIFIED** |
| **Track Separation**| Defensible Track Separation | Track A (Quantum) isolated from Track B (Conventional) | ✅ **VERIFIED** |
| **Recommendations**| Cryptographic Alignment | Key Exchange $\rightarrow$ ML-KEM; Signatures $\rightarrow$ ML-DSA; Passwords $\rightarrow$ Argon2id | ✅ **VERIFIED** |
| **Migration Proof**| Controlled Migration Demo | `python demo_migration.py` exercises local functional behavior; it does not prove risk elimination | ✅ **VERIFIED** |
| **Interactive UI** | Lightweight React Dashboard | `python main.py --dashboard` starts cleanly on `http://localhost:8080` | ✅ **VERIFIED** |
| **CI / CD Gate** | GitHub Actions Workflow | `.github/workflows/qshield-ci.yml` syntax check & test matrix (Py 3.11, 3.12) | ✅ **VERIFIED** |
| **Governance** | CODEOWNERS & Branch Policy | `.github/CODEOWNERS` and `docs/BRANCH_POLICY.md` aligned | ✅ **VERIFIED** |

---

## 🏛️ Architecture Explanation (The 4 Layers of Q-SHIELD)

```
[Layer 1: Multi-Modal Discovery]
  ├─ tls_scanner.py (Member 1)      -> Per-probe TLS observations, cipher suite, leaf certificate, scoped group evidence
  └─ code_scanner.py (Member 1)     -> Static AST & regex scanner for Python, JS/TS crypto calls & secrets

[Layer 2: Orchestration & Normalization]
  ├─ adapters.py (Member 4 & 5)     -> Normalizes heterogeneous telemetry into canonical `Finding` schema
  └─ main.py (Member 1 & 5)         -> Pipeline orchestrator, explicit targets, timeout bounds, CLI flags

[Layer 3: Defensible Assessment Engine]
  └─ risk_engine.py (Member 3)      -> Dual-Track risk quantification:
                                       • Track A (Quantum): Shor's/Grover's algorithms, Mosca's Theorem (X+Y > Z)
                                       • Track B (Conventional): Classical hygiene flaws (MD5, 3DES, ECB, unsalted SHA-256)
                                       • Priority scoring (0-100) & Evidence-weighted confidence (0.5-3.5)

[Layer 4: Presentation & Visualization]
  ├─ Terminal Formatter (main.py)   -> ANSI-colored executive badges and migration action cards
  ├─ JSON / Markdown Exports        -> Standardized portable artifacts (demo_report.json)
  └─ React 18 Dashboard (web/)      -> Zero-node browser SPA with real-time Post-Quantum Readiness Meter
```

### Key Architectural Differentiators
1. **Multi-Modal Synthesis**: Unifies network TLS telemetry with source code AST discoveries into a single unified risk score.
2. **Defensible Dual-Track Separation**: Avoids the fatal trap of proposing quantum algorithms for classical implementation flaws.
3. **Mathematical Threat Modeling**: Uses Mosca's planning inequality ($X + Y > Z$) with explicit assumptions and distinguishes idealized Grover query complexity from practical attack feasibility.
4. **Zero-Overhead Web Delivery**: The interactive React 18 dashboard requires **zero npm/node runtime dependencies**, running entirely from the Python standard library `http.server`.

---

## 🧑‍⚖️ Technical Judge Q&A Defense Guide

### Q1: What is Mosca's Theorem, and why does Harvest-Now-Decrypt-Later (HNDL) make quantum migration urgent today?
> **Answer**:
> Mosca's planning inequality compares the confidentiality lifetime ($X$) plus migration time ($Y$) with an assumed quantum capability horizon ($Z$). **If $X + Y > Z$, the selected scenario indicates a timing gap requiring migration planning.** It is not proof of compromise.
> - **$X$ (Shelf-Life / Confidentiality Lifetime)**: How many years the data must remain confidential (e.g., healthcare records: 30 years; state secrets: 25-50 years).
> - **$Y$ (Migration Time)**: Assumed duration to inventory, re-architect, replace dependencies and deploy the selected migration. An asset owner can confirm this value, including zero.
> - **$Z$ (CRQC Horizon)**: An assumed Cryptanalytically Relevant Quantum Computer horizon for scenario planning. The bundled 10/15/25-year scenarios are not forecasts or predicted attack dates.
> 
> Under Harvest-Now-Decrypt-Later (HNDL), captured ciphertext may be decrypted later if a sufficiently capable quantum adversary emerges while the data remains sensitive. $X + Y > Z$ signals planning urgency under the chosen assumptions. Public-key key establishment still needs a PQC migration plan; urgency depends on retention, exposure, criticality and migration time. Defaults are marked assumed; confirmed business context changes planning, not the original TLS/static evidence.

---

### Q2: How does Shor's algorithm differ from Grover's algorithm in its impact on cryptography?
> **Answer**:
> - **Shor's Algorithm (Threat to Widely Used Public-Key Schemes)**:
>   - Solves integer factorization and discrete logarithms in **polynomial time** ($O((\log N)^3)$).
>   - On a sufficiently capable fault-tolerant quantum computer, threatens RSA, ECDSA, Ed25519, Diffie-Hellman and ECDH. Increasing classical key sizes does not provide a PQC migration strategy. Current deployments should inventory and plan migration to suitable standardized PQC algorithms.
> - **Grover's Algorithm (Idealized Quadratic Query Speedup)**:
>   - Searches unsorted databases of size $N$ in $O(\sqrt{N})$ operations.
>   - For an idealized AES-128 key-search oracle, query scaling is roughly $2^{64}$. Serial depth, fault tolerance, hardware costs and limited parallelization constrain practical benefit; this is not a current practical break.
>   - AES-256 increases the idealized search margin to roughly $2^{128}$ queries. NIST currently permits AES-128, AES-192 and AES-256; quantum margin alone does not establish secure deployment or mandate universal key doubling. See the [NIST PQC migration FAQ](https://csrc.nist.gov/projects/post-quantum-cryptography/faqs).

---

### Q3: What are NIST's standardized Post-Quantum Cryptography (PQC) algorithms released in August 2024?
> **Answer**:
> Q-SHIELD maps its recommendations directly to NIST's finalized post-quantum standards:
> 1. **NIST FIPS 203: ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)**:
>    - Formerly known as *CRYSTALS-Kyber*.
>    - Used for general encryption and key establishment (replacing ECDH and RSA key transport). Parameter sets: ML-KEM-512, ML-KEM-768, ML-KEM-1024.
> 2. **NIST FIPS 204: ML-DSA (Module-Lattice-Based Digital Signature Algorithm)**:
>    - Formerly known as *CRYSTALS-Dilithium*.
>    - Used for general-purpose digital signatures (replacing RSA and ECDSA). Parameter sets: ML-DSA-44, ML-DSA-65, ML-DSA-87.
> 3. **NIST FIPS 205: SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)**:
>    - Formerly known as *SPHINCS+*.
>    - Backup signature scheme relying purely on the security of hash functions rather than lattice mathematics.

---

### Q4: Why does Q-SHIELD strictly separate Track A (Quantum) from Track B (Conventional)? Why can't PQC solve classical flaws?
> **Answer**:
> Cryptographic defensibility demands strict problem-domain alignment:
> - If an application stores passwords using unsalted SHA-256 or MD5, migrating that hash to a post-quantum algorithm like ML-DSA or ML-KEM is nonsense—ML-DSA is a digital signature scheme, and ML-KEM is a key encapsulation mechanism. Even replacing it with SHA-512 fails because general cryptographic hashes lack a **work factor** and **memory-hardness**. The correct remediation is a classical password-hashing function: **Argon2id (RFC 9106)** or **bcrypt**.
> - Similarly, ECB mode preserves structural patterns in images and blocks because it lacks an initialization vector and diffusion; migrating to PQC does not fix ECB mode. The fix is classical **Authenticated Encryption with Associated Data (AEAD)**, such as **AES-256-GCM**.
> - Q-SHIELD enforces this boundary rigorously: **PQC solves quantum attacks; classical hygiene solves classical implementation flaws.**

---

### Q5: How does Q-SHIELD distinguish static evidence from live runtime verification?
> **Answer**:
> - **Static Evidence**: Extracted by our AST and regex code scanner. It identifies the presence of an API call or syntax construct in the codebase (e.g., `ec.generate_private_key()`), but cannot guarantee whether that code branch executes in production. Static findings receive a confidence score based on syntax specificity.
> - **Live Runtime Verification**: Verified by dynamic execution. In network discovery, `tls_scanner.py` records the negotiated cipher and any observed group with per-probe provenance. Separate probes may reach different peers; an unavailable group remains unknown. In our controlled migration demo (`demo_migration.py`), we execute local encryption/decryption roundtrips, tag rejection and password checks. The hybrid demo exercises local two-party agreement and ciphertext tamper rejection; it does not verify authenticated transport, timing behavior, production security or compliance.

---

### Q6: How does Q-SHIELD enforce safe scanning defaults and prevent secret disclosure?
> **Answer**:
> 1. **Explicit Target Mandate**: Running `python main.py` without `--host` or `--repo` refuses to scan random network ranges or unintended directories; it prints help and exits safely.
> 2. **Network Timeouts & Resource Bounds**: TLS socket connections default to a bounded 6.0-second timeout. Code scanner skips files exceeding 10MB to prevent memory exhaustion.
> 3. **Secret Redaction**: When static AST scanning identifies hardcoded PEM private keys (`-----BEGIN PRIVATE KEY-----`), `adapters.py` masks the private key payload with `[REDACTED PRIVATE KEY MATERIAL]`, ensuring credentials are never exposed in terminal output or saved JSON reports.
