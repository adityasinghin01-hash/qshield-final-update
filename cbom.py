#!/usr/bin/env python3
"""
cbom.py - CycloneDX 1.6 Cryptographic Bill of Materials (CBOM) Serializer for Q-SHIELD.

Converts normalized Q-SHIELD scan results and cryptographic inventory findings into
production-quality, strictly schema-conformant CycloneDX 1.6 JSON CBOM documents.

Conforms to:
  - CycloneDX 1.6 JSON Schema (http://cyclonedx.org/schema/bom-1.6.schema.json)
  - Asset types: algorithm, certificate, protocol, related-crypto-material
  - Vulnerability ratings, CWEs, and component associations via affects refs
  - Strict confidentiality: Zero private keys, secrets, credentials, or raw source snippets
  - Deterministic serialization: Stable ordering across runs
  - Zero external runtime dependencies: Uses only Python standard library
"""

from __future__ import annotations

import datetime
import json
import re
import sys
import uuid
from pathlib import Path
from urllib.parse import urljoin
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union

# Local redaction and identities
try:
    from crypto_evidence import mlkem_group, redact_evidence
except ImportError:
    from .crypto_evidence import mlkem_group, redact_evidence

CYCLONEDX_VERSION = "1.6"
QSHIELD_TOOL_NAME = "Q-SHIELD"
QSHIELD_TOOL_VERSION = "2.0.0"

# Schema-valid enum constants
VALID_PRIMITIVES: Set[str] = {
    "drbg", "mac", "block-cipher", "stream-cipher", "signature", "hash",
    "pke", "xof", "kdf", "key-agree", "kem", "ae", "combiner", "other", "unknown"
}

VALID_MODES: Set[str] = {
    "cbc", "ecb", "ccm", "gcm", "cfb", "ofb", "ctr", "other", "unknown"
}

VALID_PADDINGS: Set[str] = {
    "pkcs5", "pkcs7", "pkcs1v15", "oaep", "raw", "other", "unknown"
}

VALID_CRYPTO_FUNCTIONS: Set[str] = {
    "generate", "keygen", "encrypt", "decrypt", "digest", "tag",
    "keyderive", "sign", "verify", "encapsulate", "decapsulate", "other", "unknown"
}

VALID_SEVERITIES: Set[str] = {
    "critical", "high", "medium", "low", "info", "none", "unknown"
}

VALID_CRYPTO_MATERIAL_TYPES: Set[str] = {
    "private-key", "public-key", "secret-key", "key", "ciphertext", "signature",
    "digest", "initialization-vector", "nonce", "seed", "salt", "shared-secret",
    "tag", "additional-data", "password", "credential", "token", "other", "unknown"
}

VALID_KEY_STATES: Set[str] = {
    "pre-activation", "active", "suspended", "deactivated", "compromised", "destroyed"
}


# ============================================================================
# ALGORITHM & METADATA INFERENCE HELPERS (FACTS-ONLY, NO FABRICATION)
# ============================================================================

def _normalize_mode(algo_name: str, attrs: Dict[str, Any]) -> Optional[str]:
    """Detect block cipher mode if explicitly present in algorithm name or attributes."""
    combined = f"{algo_name} {attrs.get('cipher_suite_name', '')} {attrs.get('raw_algorithm', '')}".lower()
    if "gcm" in combined:
        return "gcm"
    if "ccm" in combined:
        return "ccm"
    if "cbc" in combined:
        return "cbc"
    if "ecb" in combined:
        return "ecb"
    if "ctr" in combined:
        return "ctr"
    if "cfb" in combined:
        return "cfb"
    if "ofb" in combined:
        return "ofb"
    return None


def _detect_curve(algo_name: str, attrs: Dict[str, Any]) -> Optional[str]:
    """Detect elliptic curve name if observed in algorithm name or attributes."""
    combined = f"{algo_name} {attrs.get('curve', '')} {attrs.get('group', '')}".lower()
    if "secp256r1" in combined or "p-256" in combined or "prime256v1" in combined:
        return "secp256r1"
    if "secp384r1" in combined or "p-384" in combined:
        return "secp384r1"
    if "secp521r1" in combined or "p-521" in combined:
        return "secp521r1"
    if "secp256k1" in combined:
        return "secp256k1"
    if "x25519" in combined:
        return "Curve25519"
    if "ed25519" in combined:
        return "Ed25519"
    if "ed448" in combined or "x448" in combined:
        return "Ed448"
    return None


def _infer_primitive_and_functions(
    algo_name: str,
    usage: Optional[str],
    attrs: Dict[str, Any],
) -> Tuple[str, List[str]]:
    """
    Infers the standard CycloneDX 1.6 algorithm primitive and functions
    based on observed usage and algorithm family without fabricating facts.
    """
    usage_str = (usage or "").lower()
    algo_lower = algo_name.lower()
    is_hybrid = bool(attrs.get("is_pqc_hybrid"))
    mac_or_aead = str(attrs.get("mac_or_aead", "")).upper()

    # 1. Post-Quantum KEM or Hybrid Key Exchange
    if is_hybrid or "ml-kem" in algo_lower or "mlkem" in algo_lower or "kyber" in algo_lower:
        if is_hybrid:
            return "combiner", ["encapsulate", "decapsulate", "keyderive"]
        return "kem", ["encapsulate", "decapsulate"]

    # 2. Key Agreement (ECDH, DH, X25519)
    if usage_str == "key_exchange" or any(k in algo_lower for k in ("ecdh", "diffie-hellman", "x25519")):
        return "key-agree", ["keyderive"]

    # 3. Digital Signatures (RSA signatures, ECDSA, Ed25519, ML-DSA)
    if usage_str == "signature" or any(s in algo_lower for s in ("ecdsa", "ed25519", "ed448", "ml-dsa", "slh-dsa", "sphincs")):
        return "signature", ["sign", "verify"]

    # 4. Authenticated Encryption vs Block Cipher vs Stream Cipher
    if usage_str == "symmetric_encryption" or any(c in algo_lower for c in ("aes", "3des", "des", "rc4", "chacha20")):
        if "gcm" in algo_lower or "ccm" in algo_lower or mac_or_aead == "AEAD":
            return "ae", ["encrypt", "decrypt"]
        if "rc4" in algo_lower or "chacha20" in algo_lower:
            return "stream-cipher", ["encrypt", "decrypt"]
        return "block-cipher", ["encrypt", "decrypt"]

    # 5. Password Hashing / KDF
    if usage_str == "password_storage" or any(p in algo_lower for p in ("argon2", "pbkdf2", "bcrypt", "scrypt")):
        return "kdf", ["keyderive"]

    # 6. Cryptographic Hash / Digest
    if usage_str == "hash" or any(h in algo_lower for h in ("sha-", "sha256", "sha384", "sha512", "sha1", "sha-1", "md5", "blake")):
        return "hash", ["digest"]

    # 7. Asymmetric PKE (Raw RSA key encapsulation / encryption)
    if "rsa" in algo_lower:
        if usage_str == "signature":
            return "signature", ["sign", "verify"]
        return "pke", ["encrypt", "decrypt"]

    return "unknown", ["unknown"]


def _get_parameter_set_identifier(algo_name: str, key_bits: Optional[int], attrs: Dict[str, Any]) -> Optional[str]:
    """Returns a clean parameter set identifier string (e.g. '2048', '256', 'ML-KEM-768')."""
    group = attrs.get("group")
    if group:
        return str(group)
    if key_bits is not None and key_bits > 0:
        return str(key_bits)
    # Check if number in algorithm name
    match = re.search(r"\b(512|768|1024|2048|3072|4096|128|192|256|384)\b", algo_name)
    if match:
        return match.group(1)
    return None


def _get_quantum_security_level(algo_name: str, attrs: Dict[str, Any]) -> Optional[int]:
    """
    Maps NIST Post-Quantum security category (1 to 5) when formally established by NIST.
    Returns None if classical, vulnerable, or not a standardized PQC parameter set.
    """
    name_upper = algo_name.upper()
    group_upper = str(attrs.get("group", "")).upper()
    combined = f"{name_upper} {group_upper}"

    if "ML-KEM-512" in combined or "MLKEM512" in combined or "ML-DSA-44" in combined:
        return 1
    if "ML-KEM-768" in combined or "MLKEM768" in combined or "ML-DSA-65" in combined:
        return 3
    if "ML-KEM-1024" in combined or "MLKEM1024" in combined or "ML-DSA-87" in combined:
        return 5
    return None


def _parse_cwe_id(cwe_val: Any) -> Optional[int]:
    """Safely extracts integer CWE ID from 'CWE-327', 327, etc."""
    if not cwe_val:
        return None
    if isinstance(cwe_val, int):
        return cwe_val
    if isinstance(cwe_val, str):
        match = re.search(r"\d+", cwe_val)
        if match:
            try:
                return int(match.group(0))
            except ValueError:
                return None
    return None


def _sanitize_bom_ref(raw_ref: str) -> str:
    """Creates a clean, valid CycloneDX bom-ref string conforming to refType."""
    sanitized = re.sub(r"[^a-zA-Z0-9_\-\.:]", "_", str(raw_ref).strip())
    # bom-ref should not start with 'urn:cdx:' to avoid BOM-Link ambiguity
    if sanitized.startswith("urn:cdx:"):
        sanitized = "ref-" + sanitized[8:]
    return sanitized or f"ref-{uuid.uuid4().hex[:8]}"


# ============================================================================
# COMPONENT GENERATORS
# ============================================================================

def _build_certificate_component(
    finding_id: str,
    asset: str,
    algo_name: str,
    attrs: Dict[str, Any],
) -> Dict[str, Any]:
    """Builds a CycloneDX 1.6 component for an X.509 Certificate."""
    bom_ref = _sanitize_bom_ref(f"cert::{finding_id}")
    subject_info = attrs.get("subject", {})
    issuer_info = attrs.get("issuer", {})
    validity = attrs.get("validity", {})

    subj_name = subject_info.get("rfc4514") or subject_info.get("common_name") or asset
    issuer_name = issuer_info.get("rfc4514") or issuer_info.get("common_name")

    cert_props: Dict[str, Any] = {
        "certificateFormat": "X.509",
    }
    if subj_name:
        cert_props["subjectName"] = str(subj_name)
    if issuer_name:
        cert_props["issuerName"] = str(issuer_name)
    if validity.get("not_before"):
        cert_props["notValidBefore"] = str(validity["not_before"])
    if validity.get("not_after"):
        cert_props["notValidAfter"] = str(validity["not_after"])

    properties: List[Dict[str, str]] = [
        {"name": "qshield:finding_id", "value": finding_id},
        {"name": "qshield:asset", "value": asset},
        {"name": "qshield:evidence_source", "value": "certificate"},
        {"name": "qshield:signature_algorithm", "value": str(attrs.get("signature_algorithm") or "unknown")},
    ]
    if attrs.get("serial_number"):
        properties.append({"name": "qshield:serial_number", "value": str(attrs["serial_number"])})
    if attrs.get("confidence"):
        properties.append({"name": "qshield:confidence", "value": str(attrs["confidence"])})

    properties.sort(key=lambda p: p["name"])

    return {
        "type": "cryptographic-asset",
        "name": f"X.509 Certificate ({subj_name})",
        "bom-ref": bom_ref,
        "cryptoProperties": {
            "assetType": "certificate",
            "certificateProperties": cert_props,
        },
        "properties": properties,
    }


def _build_protocol_component(
    finding_id: str,
    asset: str,
    algo_name: str,
    attrs: Dict[str, Any],
) -> Dict[str, Any]:
    """Builds a CycloneDX 1.6 component for a Cryptographic Protocol (TLS)."""
    bom_ref = _sanitize_bom_ref(f"proto::{finding_id}")
    proto_str = str(attrs.get("protocol") or algo_name).replace("Deprecated-", "")

    # Extract version: e.g. TLSv1.2 -> "1.2"
    version_match = re.search(r"(\d+(?:\.\d+)?)", proto_str)
    version = version_match.group(1) if version_match else proto_str

    proto_props: Dict[str, Any] = {
        "type": "tls",
        "version": version,
    }

    properties: List[Dict[str, str]] = [
        {"name": "qshield:finding_id", "value": finding_id},
        {"name": "qshield:asset", "value": asset},
        {"name": "qshield:evidence_source", "value": attrs.get("evidence_source") or "network"},
        {"name": "qshield:raw_protocol", "value": proto_str},
    ]
    if attrs.get("match_type"):
        properties.append({"name": "qshield:match_type", "value": str(attrs["match_type"])})
    if attrs.get("confidence"):
        properties.append({"name": "qshield:confidence", "value": str(attrs["confidence"])})

    properties.sort(key=lambda p: p["name"])

    return {
        "type": "cryptographic-asset",
        "name": f"TLS Protocol v{version}",
        "bom-ref": bom_ref,
        "cryptoProperties": {
            "assetType": "protocol",
            "protocolProperties": proto_props,
        },
        "properties": properties,
    }


def _build_secret_material_component(
    finding_id: str,
    asset: str,
    algo_name: str,
    key_bits: Optional[int],
    attrs: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Builds a CycloneDX 1.6 component for compromised or hardcoded private key/credential material.
    STRICT PRIVACY: Never outputs secret values, bytes, or raw private key snippets.
    """
    bom_ref = _sanitize_bom_ref(f"material::{finding_id}")

    material_props: Dict[str, Any] = {
        "type": "private-key",
        "state": "compromised",
    }
    if key_bits and key_bits > 0:
        material_props["size"] = int(key_bits)

    format_candidate = "PEM" if "pem" in f"{algo_name} {attrs.get('raw_algorithm', '')}".lower() else None
    if format_candidate:
        material_props["format"] = format_candidate

    properties: List[Dict[str, str]] = [
        {"name": "qshield:finding_id", "value": finding_id},
        {"name": "qshield:asset", "value": asset},
        {"name": "qshield:evidence_source", "value": "static"},
        {"name": "qshield:secret_state", "value": "hardcoded_compromised"},
        {"name": "qshield:redaction_notice", "value": "Secret bytes redacted in compliance with security policy"},
    ]
    if attrs.get("confidence"):
        properties.append({"name": "qshield:confidence", "value": str(attrs["confidence"])})

    properties.sort(key=lambda p: p["name"])

    return {
        "type": "cryptographic-asset",
        "name": f"Exposed Asymmetric Key Material ({algo_name})",
        "bom-ref": bom_ref,
        "cryptoProperties": {
            "assetType": "related-crypto-material",
            "relatedCryptoMaterialProperties": material_props,
        },
        "properties": properties,
    }


def _build_algorithm_component(
    finding_id: str,
    asset: str,
    algo_name: str,
    usage: Optional[str],
    key_bits: Optional[int],
    attrs: Dict[str, Any],
) -> Dict[str, Any]:
    """Builds a CycloneDX 1.6 component for a Cryptographic Algorithm."""
    bom_ref = _sanitize_bom_ref(f"algo::{finding_id}")

    primitive, functions = _infer_primitive_and_functions(algo_name, usage, attrs)
    param_set = _get_parameter_set_identifier(algo_name, key_bits, attrs)
    curve = _detect_curve(algo_name, attrs)
    mode = _normalize_mode(algo_name, attrs)
    nist_level = _get_quantum_security_level(algo_name, attrs)

    algo_props: Dict[str, Any] = {
        "primitive": primitive,
    }
    if param_set:
        algo_props["parameterSetIdentifier"] = param_set
    if curve:
        algo_props["curve"] = curve
    if mode and mode in VALID_MODES:
        algo_props["mode"] = mode
    if key_bits and key_bits > 0:
        algo_props["classicalSecurityLevel"] = int(key_bits)
    if nist_level is not None:
        algo_props["nistQuantumSecurityLevel"] = int(nist_level)
    if functions:
        valid_funcs = [f for f in functions if f in VALID_CRYPTO_FUNCTIONS]
        if valid_funcs:
            algo_props["cryptoFunctions"] = valid_funcs

    properties: List[Dict[str, str]] = [
        {"name": "qshield:finding_id", "value": finding_id},
        {"name": "qshield:asset", "value": asset},
        {"name": "qshield:evidence_source", "value": attrs.get("evidence_source") or "static"},
    ]
    if usage:
        properties.append({"name": "qshield:declared_usage", "value": str(usage)})
    if attrs.get("match_type"):
        properties.append({"name": "qshield:match_type", "value": str(attrs["match_type"])})
    if attrs.get("confidence"):
        properties.append({"name": "qshield:confidence", "value": str(attrs["confidence"])})
    if attrs.get("is_pqc_hybrid"):
        properties.append({"name": "qshield:pqc_hybrid", "value": "true"})

    properties.sort(key=lambda p: p["name"])

    return {
        "type": "cryptographic-asset",
        "name": algo_name,
        "bom-ref": bom_ref,
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": algo_props,
        },
        "properties": properties,
    }


# ============================================================================
# PRIMARY SERIALIZER
# ============================================================================

def export_cbom(
    scan_result: Dict[str, Any],
    serial_number: Optional[str] = None,
    timestamp: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Serializes a normalized Q-SHIELD scan result dictionary into an official
    CycloneDX 1.6 Cryptographic Bill of Materials (CBOM) document.

    Guarantees:
      - Schema conformance with CycloneDX 1.6.
      - Total redaction of private keys and secret values.
      - Deterministic ordering of components, properties, and vulnerabilities.
      - Facts-first representation with honest handling of incomplete/unknown telemetry.
    """
    if not isinstance(scan_result, dict):
        raise ValueError(f"Expected scan_result to be a dict, got {type(scan_result).__name__}")

    # Defensive recursive redaction
    clean_scan = redact_evidence(scan_result)

    metadata_in = clean_scan.get("metadata", {})
    targets_in = metadata_in.get("targets", {})
    inventory_findings = clean_scan.get("inventory", {}).get("findings", [])
    assessments_in = clean_scan.get("risk_assessment", {}).get("assessments", [])

    # 1. Determine root target identity
    target_name = (
        targets_in.get("host")
        or (Path(targets_in.get("repo")).name if targets_in.get("repo") else None)
        or "Q-SHIELD-Target"
    )
    root_ref = _sanitize_bom_ref(f"target::{target_name}")

    # 2. Assign valid BOM metadata
    bom_serial = serial_number or f"urn:uuid:{uuid.uuid4()}"
    if not re.match(r"^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", bom_serial):
        bom_serial = f"urn:uuid:{uuid.uuid4()}"

    bom_timestamp = timestamp or metadata_in.get("scan_finished_at") or datetime.datetime.now(datetime.timezone.utc).isoformat()
    # Ensure ISO-8601 with Z or offset
    if isinstance(bom_timestamp, str) and bom_timestamp.endswith("+00:00"):
        bom_timestamp = bom_timestamp.replace("+00:00", "Z")

    metadata_props: List[Dict[str, str]] = [
        {"name": "qshield:orchestrator", "value": metadata_in.get("orchestrator", QSHIELD_TOOL_NAME)},
        {"name": "qshield:version", "value": metadata_in.get("version", QSHIELD_TOOL_VERSION)},
        {"name": "qshield:scenario", "value": str(metadata_in.get("scenario", "central"))},
    ]
    for key in ('scan_id', 'scan_finished_at', 'is_demo'):
        if key in metadata_in:
            metadata_props.append({"name": "qshield:"+key, "value": str(metadata_in[key])})
    rules_version = clean_scan.get('risk_assessment', {}).get('metadata', {}).get('ruleset_version')
    if rules_version:
        metadata_props.append({"name": "qshield:ruleset_version", "value": str(rules_version)})
    if metadata_in.get("crqc_horizon_years") is not None:
        metadata_props.append({"name": "qshield:crqc_horizon_years", "value": str(metadata_in["crqc_horizon_years"])})
    if targets_in.get("host"):
        metadata_props.append({"name": "qshield:target_host", "value": str(targets_in["host"])})
    if targets_in.get("repo"):
        metadata_props.append({"name": "qshield:target_repo", "value": str(targets_in["repo"])})

    for key in ('parent_scan_id', 'assessment_type', 'evidence_scan_id', 'evidence_observed_at', 'reassessed_at', 'ruleset_fingerprint'):
        if key in metadata_in:
            metadata_props.append({"name": "qshield:"+key, "value": str(metadata_in[key])})
    # Business context is application metadata, never an observed algorithm capability.
    context = [{"finding_id": item.get("id"), "planning_context": item["planning_context"]}
               for item in inventory_findings if isinstance(item.get("planning_context"), dict)]
    if context:
        metadata_props.append({"name": "qshield:planning_context", "value": json.dumps(context, sort_keys=True)})
    metadata_props.sort(key=lambda p: p["name"])

    # 3. Build Components & Track Finding-to-Component Mapping
    components: List[Dict[str, Any]] = []
    finding_to_bom_ref: Dict[str, str] = {}
    seen_refs: Set[str] = set()

    for item in inventory_findings:
        fid = str(item.get("id", f"finding-{len(components)+1}"))
        asset = str(item.get("asset", "unknown"))
        algo_name = str(item.get("algorithm", "unknown"))
        usage = item.get("usage")
        key_bits = item.get("key_bits")
        attrs = item.get("attributes", {})

        match_type = str(attrs.get("match_type", "")).upper()
        evidence_type = str(attrs.get("evidence_type", "")).lower()

        # Classify asset type
        if evidence_type == "x509_certificate" or match_type == "X509_CERTIFICATE":
            comp = _build_certificate_component(fid, asset, algo_name, attrs)
        elif evidence_type == "tls_protocol" or match_type == "PROTOCOL_SUPPORT_CHECK":
            comp = _build_protocol_component(fid, asset, algo_name, attrs)
        elif match_type == "EXPOSED_SECRET" or "SECRET" in match_type:
            comp = _build_secret_material_component(fid, asset, algo_name, key_bits, attrs)
        else:
            comp = _build_algorithm_component(fid, asset, algo_name, usage, key_bits, attrs)

        # Enforce unique bom-ref
        base_ref = comp["bom-ref"]
        dedup_ref = base_ref
        counter = 1
        while dedup_ref in seen_refs:
            dedup_ref = f"{base_ref}-{counter}"
            counter += 1
        comp["bom-ref"] = dedup_ref
        seen_refs.add(dedup_ref)

        finding_to_bom_ref[fid] = dedup_ref
        components.append(comp)

    # Sort components deterministically by bom-ref
    components.sort(key=lambda c: c["bom-ref"])

    # 4. Build Vulnerabilities (Mapping Q-SHIELD Assessments)
    vulnerabilities: List[Dict[str, Any]] = []
    seen_vuln_refs: Set[str] = set()

    for a in assessments_in:
        raw_aid = str(a.get("assessment_id") or a.get("rule_id") or f"vuln-{len(vulnerabilities)+1}")
        vuln_ref = _sanitize_bom_ref(f"vuln::{raw_aid}")
        dedup_vref = vuln_ref
        v_counter = 1
        while dedup_vref in seen_vuln_refs:
            dedup_vref = f"{vuln_ref}-{v_counter}"
            v_counter += 1
        seen_vuln_refs.add(dedup_vref)

        rule_id = str(a.get("rule_id", "QSHIELD-CRYPTO-FINDING"))
        title = str(a.get("title", rule_id))
        rationale = str(a.get("rationale") or "")
        threat_analysis = a.get("threat_analysis", {})
        details = str(threat_analysis.get("details") or rationale)
        recommendation_obj = a.get("recommendation", {})
        action_text = str(recommendation_obj.get("action") or "Review cryptographic asset.")

        # Severity mapping
        raw_sev = str(a.get("severity", "unknown")).lower()
        sev = raw_sev if raw_sev in VALID_SEVERITIES else "unknown"

        # Rating score (Priority 0-100 normalized to standard float)
        priority_score = float(a.get("priority", 0.0))
        conf_rationale = str(a.get("confidence_rationale") or a.get("confidence", "heuristic"))

        rating: Dict[str, Any] = {
            "source": {"name": "Q-SHIELD"},
            "score": priority_score,
            "severity": sev,
            "method": "other",
            "justification": conf_rationale,
        }

        vuln_entry: Dict[str, Any] = {
            "bom-ref": dedup_vref,
            "id": rule_id,
            "source": {"name": "Q-SHIELD Risk Engine"},
            "description": title,
            "detail": details,
            "recommendation": action_text,
            "ratings": [rating],
        }

        # CWE mapping
        finding_id = a.get("finding_id")
        matching_finding = next((f for f in inventory_findings if f.get("id") == finding_id), None)
        cwe_raw = matching_finding.get("attributes", {}).get("cwe_id") if matching_finding else None
        cwe_int = _parse_cwe_id(cwe_raw)
        if cwe_int is not None:
            vuln_entry["cwes"] = [cwe_int]

        # Link to affected component via affects ref
        affects_ref = finding_to_bom_ref.get(finding_id)
        if affects_ref:
            vuln_entry["affects"] = [{"ref": affects_ref}]

        # Metadata properties
        vuln_props: List[Dict[str, str]] = [
            {"name": "qshield:track", "value": str(a.get("track", "unknown"))},
            {"name": "qshield:rule_id", "value": rule_id},
        ]
        if a.get("assessment_id"):
            vuln_props.append({"name": "qshield:assessment_id", "value": str(a["assessment_id"])})
        if a.get("quantum_relevance"):
            vuln_props.append({"name": "qshield:quantum_relevance", "value": str(a["quantum_relevance"])})

        vuln_props.sort(key=lambda p: p["name"])
        vuln_entry["properties"] = vuln_props

        vulnerabilities.append(vuln_entry)

    # Sort vulnerabilities deterministically by id and bom-ref
    vulnerabilities.sort(key=lambda v: (v["id"], v["bom-ref"]))

    # 5. Build Dependency Graph
    dependencies: List[Dict[str, Any]] = []
    all_comp_refs = [c["bom-ref"] for c in components]
    if all_comp_refs:
        dependencies.append({
            "ref": root_ref,
            "dependsOn": sorted(all_comp_refs),
        })

    # 6. Assemble Root CycloneDX 1.6 Document
    cbom_doc: Dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_VERSION,
        "serialNumber": bom_serial,
        "version": 1,
        "metadata": {
            "timestamp": bom_timestamp,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": QSHIELD_TOOL_NAME,
                        "version": QSHIELD_TOOL_VERSION,
                    }
                ]
            },
            "component": {
                "type": "application",
                "name": target_name,
                "bom-ref": root_ref,
            },
            "properties": metadata_props,
        },
        "components": components,
    }

    if dependencies:
        cbom_doc["dependencies"] = dependencies
    if vulnerabilities:
        cbom_doc["vulnerabilities"] = vulnerabilities

    return cbom_doc


def write_cbom_file(
    scan_result: Dict[str, Any],
    output_path: Union[str, Path],
    serial_number: Optional[str] = None,
    timestamp: Optional[str] = None,
    indent: int = 2,
) -> str:
    """
    Serializes and writes the CBOM JSON document to output_path.
    Creates parent directories if necessary.
    Returns the serialized JSON string.
    """
    cbom_dict = export_cbom(scan_result, serial_number=serial_number, timestamp=timestamp)
    content = json.dumps(cbom_dict, indent=indent) + "\n"

    target_path = Path(output_path)
    target_path.parent.mkdir(parents=True, exist_ok=True)
    target_path.write_text(content, encoding="utf-8")
    return content


def validate_cbom_schema(
    cbom_dict: Dict[str, Any],
    schema_path: Optional[Union[str, Path]] = None,
) -> Tuple[Optional[bool], Optional[str]]:
    """
    Validate against CycloneDX 1.6 using bundled, offline schema resources.

    Return (True, None) only after formal validation, (False, reason) for an
    invalid document, or (None, reason) when validation could not be performed.
    Explicit schema paths never silently fall back to another schema.
    """
    # 1. Built-in fast structural checks
    if not isinstance(cbom_dict, dict):
        return False, "CBOM root must be a JSON object"
    if cbom_dict.get("bomFormat") != "CycloneDX":
        return False, f"Expected bomFormat 'CycloneDX', got {cbom_dict.get('bomFormat')!r}"
    if cbom_dict.get("specVersion") != "1.6":
        return False, f"Expected specVersion '1.6', got {cbom_dict.get('specVersion')!r}"
    serial = cbom_dict.get("serialNumber")
    if not isinstance(serial, str) or not re.fullmatch(r"urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", serial):
        return False, f"Invalid RFC 4122 serialNumber: {cbom_dict.get('serialNumber')!r}"

    try:
        from jsonschema import Draft7Validator, SchemaError, ValidationError
        from referencing import Registry, Resource
        from referencing.exceptions import CannotDetermineSpecification, NoSuchResource, Unresolvable
    except ImportError:
        return None, "Not formally validated: install requirements-dev.txt (jsonschema)."

    docs = Path(__file__).resolve().parent / "docs"
    selected = Path(schema_path) if schema_path is not None else docs / "bom-1.6.schema.json"
    try:
        schema = json.loads(selected.read_text(encoding="utf-8"))
        Draft7Validator.check_schema(schema)

        def deny_retrieval(uri):
            raise NoSuchResource(ref=uri)

        registry = Registry(retrieve=deny_retrieval)
        schema_resources = []
        # Register only the bundled allowlist. Unknown references never trigger
        # filesystem or network retrieval, including references in custom schemas.
        for path in (docs / "spdx.schema.json", docs / "jsf-0.82.schema.json"):
            contents = json.loads(path.read_text(encoding="utf-8"))
            resource = Resource.from_contents(contents)
            registry = registry.with_resource(contents['$id'], resource)
            registry = registry.with_resource(contents['$id'].replace('http:', 'https:', 1), resource)
            schema_resources.append((contents, contents['$id']))
        resource = Resource.from_contents(schema)
        schema_uri = schema.get('$id', selected.resolve().as_uri())
        registry = registry.with_resource(schema_uri, resource).crawl()
        schema_resources.append((schema, schema_uri))

        def check_references(node, base):
            if not isinstance(node, dict):
                return
            base = urljoin(base, node.get('$id', ''))
            if '$ref' in node:
                registry.resolver(base_uri=base).lookup(node['$ref'])
            # Only Draft 7 schema locations are traversed. Annotation values
            # (default, examples, enum, const) are arbitrary instance data.
            for key in ('definitions', 'properties', 'patternProperties', 'dependencies'):
                for child in node.get(key, {}).values():
                    if isinstance(child, (dict, bool)):
                        check_references(child, base)
            for key in ('additionalProperties', 'additionalItems', 'contains',
                        'propertyNames', 'not', 'if', 'then', 'else'):
                if key in node:
                    check_references(node[key], base)
            items = node.get('items', [])
            for child in items if isinstance(items, list) else [items]:
                check_references(child, base)
            for key in ('allOf', 'anyOf', 'oneOf'):
                for child in node.get(key, []):
                    check_references(child, base)

        # Check the whole resource set, including unused definitions/optional
        # branches. Formal success requires a self-contained schema graph.
        for contents, base in schema_resources:
            check_references(contents, base)
        validator = Draft7Validator(schema, registry=registry,
                                    format_checker=Draft7Validator.FORMAT_CHECKER)
        validator.validate(cbom_dict)
    except ValidationError as err:
        return False, f"Schema validation error at {list(err.path)}: {err.message}"
    except (OSError, ValueError, SchemaError, CannotDetermineSpecification, Unresolvable) as err:
        return None, f"Not formally validated: schema or offline reference unavailable ({type(err).__name__})."
    return True, None
