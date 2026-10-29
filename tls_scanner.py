#!/usr/bin/env python3
"""
tls_scanner.py - TLS and certificate scanner (Member 1, independent module)

Connects to host:port, performs a TLS handshake and reports:
  * negotiated TLS version, cipher suite (name, bits, key exchange, auth)
  * certificate details (subject, issuer, validity, SANs, fingerprint ...)
  * certificate public-key algorithm (+ key size / curve)
  * certificate signature algorithm (+ hash)
  * key-exchange details (ephemeral or static, forward secrecy, and -- when
    the local `openssl` CLI is available -- the actual group, e.g. X25519,
    secp256r1 or a post-quantum hybrid such as X25519MLKEM768)
  * which protocol versions the server accepts (TLS 1.0 - 1.3)
  * optionally (--deep) every TLS 1.2 cipher suite the server accepts

This module REPORTS FACTS ONLY. It does not assign risk. Risk and quantum
assessment belong to risk_engine.py (Member 3).

Usage (CLI):
    python tls_scanner.py example.com
    python tls_scanner.py example.com 8443 --json out.json --deep

Usage (library, as called from main.py):
    from tls_scanner import scan_tls
    result = scan_tls("example.com", 443)      # never raises; returns a dict
    if result["scan_status"] != "ok": ...      # "ok" | "partial" | "failed"

Dependencies: Python 3.8+, `cryptography` (pip install cryptography).
Optional:     `openssl` binary on PATH (for exact key-exchange group).
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
import uuid
import warnings
from typing import Any

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import (
        dh,
        dsa,
        ec,
        ed448,
        ed25519,
        rsa,
    )
    from cryptography.x509.oid import ExtensionOID, NameOID
    _HAVE_CRYPTO = True
except ImportError:  # pragma: no cover
    _HAVE_CRYPTO = False

SCHEMA_VERSION = "1.0"
MODULE_NAME = "tls_scanner"

# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------

_PROTOCOLS = [
    ("TLSv1.0", "TLSv1"),
    ("TLSv1.1", "TLSv1_1"),
    ("TLSv1.2", "TLSv1_2"),
    ("TLSv1.3", "TLSv1_3"),
]


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def normalize_target(raw: str, default_port: int = 443):
    """Turn whatever the user typed into (host, port).

    Accepts: 'example.com', 'https://www.example.com/some/path?x=1',
             'example.com:8443', 'user@host:443', '[::1]:8443', ' Example.COM '
    Raises ValueError if no hostname can be found.
    """
    from urllib.parse import urlsplit
    s = (raw or "").strip()
    if not s:
        raise ValueError("No domain entered")
    if "://" not in s:
        s = "//" + s                      # let urlsplit treat it as netloc
    parts = urlsplit(s)
    host = parts.hostname                 # strips scheme, path, creds, brackets; lowercases
    if not host:
        raise ValueError(f"Could not find a hostname in {raw!r}")
    try:
        port = parts.port
    except ValueError:
        raise ValueError(f"Invalid port in {raw!r}")
    try:                                  # internationalised domain names
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        pass
    return host, port or default_port


def _make_context(verify: bool, version: str | None = None,
                  ciphers: str | None = None) -> ssl.SSLContext:
    """Client context. Unverified contexts are used for *inspection* so that
    self-signed / expired / mismatched certs can still be analysed."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if verify:
        ctx.load_default_certs()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
    else:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if version:
        tv = getattr(ssl.TLSVersion, version)  # may raise AttributeError
        # Allow legacy protocols to be *offered* so we can detect them.
        try:
            ctx.set_ciphers("ALL:@SECLEVEL=0")
        except ssl.SSLError:
            pass
        # Offering obsolete versions is intentional inspection, not our client
        # policy. Silence only Python's expected warning at these assignments.
        with warnings.catch_warnings():
            warnings.filterwarnings('ignore', message=r'ssl\.TLSVersion\.TLSv1(_1)? is deprecated',
                                    category=DeprecationWarning)
            ctx.minimum_version = tv
            ctx.maximum_version = tv
    if ciphers:
        ctx.set_ciphers(ciphers)
    return ctx


def _connect(host: str, port: int, ctx: ssl.SSLContext, timeout: float):
    raw = socket.create_connection((host, port), timeout=timeout)
    try:
        return ctx.wrap_socket(raw, server_hostname=host)
    except Exception:
        raw.close()
        raise


def _probe_record(host, port, stage, implementation='Python ssl', version=None):
    return dict(id=uuid.uuid4().hex, stage=stage, timestamp=_now().isoformat(),
                endpoint={'host': host, 'port': port}, peer_address=None,
                certificate_fingerprint_sha256=None,
                client={'implementation': implementation,
                        'version': version or (sys.version.split()[0] + ' / ' + ssl.OPENSSL_VERSION)
                        if implementation == 'Python ssl' else version},
                status='unknown', outcome='unknown', error_category=None,
                attribution='independent_handshake', correlation_to_inspection='unknown')


def _observe_socket(record, sock):
    record['peer_address'] = sock.getpeername()[0]
    der = sock.getpeercert(binary_form=True)
    if der:
        record['certificate_fingerprint_sha256'] = hashlib.sha256(der).hexdigest()
    record.update(status='completed', outcome='accepted')
    return der


def _failure_category(error, local=False):
    """Only explicit peer negotiation alerts establish a remote refusal."""
    if isinstance(error, (TimeoutError, subprocess.TimeoutExpired)):
        return 'timeout'
    if local or isinstance(error, (AttributeError, ValueError)):
        return 'local_unsupported'
    if isinstance(error, ssl.SSLError):
        reason = (str(getattr(error, 'reason', '') or '') + ' ' + str(error)).upper()
        if any(token in reason for token in ('NO_PROTOCOLS_AVAILABLE', 'NO PROTOCOLS AVAILABLE',
                                             'NO_CIPHERS_AVAILABLE', 'NO CIPHERS AVAILABLE',
                                             'UNSUPPORTED_PROTOCOL', 'NO_SUITABLE_SIGNATURE_ALGORITHM')):
            return 'local_unsupported'
        if any(token in reason for token in ('TLSV1_ALERT_PROTOCOL_VERSION',
                                             'SSLV3_ALERT_HANDSHAKE_FAILURE',
                                             'TLSV1_ALERT_INSUFFICIENT_SECURITY')):
            return 'remote_negotiation_refused'
        return 'tls_error'
    return 'transport_error'


def _record_failure(record, error, local=False):
    category = _failure_category(error, local)
    record.update(status='completed' if category == 'remote_negotiation_refused' else 'unknown',
                  outcome='rejected' if category == 'remote_negotiation_refused' else 'unknown',
                  error_category=category)


def _correlate(record, inspection):
    left, right = (record.get('certificate_fingerprint_sha256'),
                   inspection.get('certificate_fingerprint_sha256'))
    record['correlation_to_inspection'] = ('matched' if left == right else 'mismatched') if left and right else 'unknown'


# --------------------------------------------------------------------------
# Certificate parsing
# --------------------------------------------------------------------------

def _name_to_dict(name: x509.Name) -> dict[str, Any]:
    out: dict[str, Any] = {"rfc4514": name.rfc4514_string()}
    for label, oid in (("common_name", NameOID.COMMON_NAME),
                       ("organization", NameOID.ORGANIZATION_NAME),
                       ("organizational_unit", NameOID.ORGANIZATIONAL_UNIT_NAME),
                       ("country", NameOID.COUNTRY_NAME)):
        attrs = name.get_attributes_for_oid(oid)
        out[label] = attrs[0].value if attrs else None
    return out


def _describe_public_key(pub) -> dict[str, Any]:
    """Public-key algorithm of the certificate, with size/curve."""
    if isinstance(pub, rsa.RSAPublicKey):
        return {"algorithm": "RSA", "key_size_bits": pub.key_size,
                "public_exponent": pub.public_numbers().e, "curve": None}
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return {"algorithm": "ECDSA (EC)", "key_size_bits": pub.curve.key_size,
                "curve": pub.curve.name}
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return {"algorithm": "Ed25519", "key_size_bits": 256, "curve": "ed25519"}
    if isinstance(pub, ed448.Ed448PublicKey):
        return {"algorithm": "Ed448", "key_size_bits": 456, "curve": "ed448"}
    if isinstance(pub, dsa.DSAPublicKey):
        return {"algorithm": "DSA", "key_size_bits": pub.key_size, "curve": None}
    if isinstance(pub, dh.DHPublicKey):
        return {"algorithm": "DH", "key_size_bits": pub.key_size, "curve": None}
    return {"algorithm": type(pub).__name__, "key_size_bits": None, "curve": None}


def _describe_signature(cert: x509.Certificate) -> dict[str, Any]:
    oid = cert.signature_algorithm_oid
    hash_name = None
    try:
        h = cert.signature_hash_algorithm
        hash_name = h.name if h else None   # None for Ed25519/Ed448
    except Exception:
        pass
    name = getattr(oid, "_name", None) or oid.dotted_string
    # Family: RSA / ECDSA / Ed25519 / ...
    family = None
    low = name.lower()
    if "rsa" in low and "pss" in low:
        family = "RSA-PSS"
    elif "rsa" in low:
        family = "RSA (PKCS#1 v1.5)"
    elif "ecdsa" in low:
        family = "ECDSA"
    elif "ed25519" in low:
        family = "Ed25519"
    elif "ed448" in low:
        family = "Ed448"
    elif "dsa" in low:
        family = "DSA"
    return {"algorithm": name, "oid": oid.dotted_string,
            "family": family, "hash": hash_name}


def _extensions(cert: x509.Certificate) -> dict[str, Any]:
    ext: dict[str, Any] = {"subject_alt_names": [], "is_ca": None,
                           "key_usage": [], "extended_key_usage": [],
                           "ocsp_must_staple": False}
    try:
        san = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        ext["subject_alt_names"] = (
            [f"DNS:{n}" for n in san.get_values_for_type(x509.DNSName)] +
            [f"IP:{n}" for n in san.get_values_for_type(x509.IPAddress)])
    except x509.ExtensionNotFound:
        pass
    try:
        ext["is_ca"] = cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS).value.ca
    except x509.ExtensionNotFound:
        pass
    try:
        ku = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        for attr in ("digital_signature", "content_commitment", "key_encipherment",
                     "data_encipherment", "key_agreement", "key_cert_sign",
                     "crl_sign"):
            if getattr(ku, attr):
                ext["key_usage"].append(attr)
    except x509.ExtensionNotFound:
        pass
    try:
        eku = cert.extensions.get_extension_for_oid(
            ExtensionOID.EXTENDED_KEY_USAGE).value
        ext["extended_key_usage"] = [getattr(o, "_name", o.dotted_string) for o in eku]
    except x509.ExtensionNotFound:
        pass
    return ext


def parse_certificate(der: bytes) -> dict[str, Any]:
    """DER bytes -> structured certificate dict."""
    cert = x509.load_der_x509_certificate(der)
    try:
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
    except AttributeError:  # older cryptography
        not_before = cert.not_valid_before.replace(tzinfo=dt.UTC)
        not_after = cert.not_valid_after.replace(tzinfo=dt.UTC)
    now = _now()
    days_left = (not_after - now).days
    pub = cert.public_key()
    return {
        "subject": _name_to_dict(cert.subject),
        "issuer": _name_to_dict(cert.issuer),
        "self_signed": cert.subject == cert.issuer,
        "serial_number": format(cert.serial_number, "x"),
        "x509_version": cert.version.name,
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "days_until_expiry": days_left,
        "expired": now > not_after,
        "not_yet_valid": now < not_before,
        "public_key": _describe_public_key(pub),
        "signature": _describe_signature(cert),
        "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "fingerprint_sha1": hashlib.sha1(der).hexdigest(),
        "extensions": _extensions(cert),
    }


# --------------------------------------------------------------------------
# Cipher / key-exchange details
# --------------------------------------------------------------------------

_KEA_MAP = {  # OpenSSL 'kea' field -> readable
    "kx-ecdhe": "ECDHE", "kx-dhe": "DHE", "kx-rsa": "RSA (static key transport)",
    "kx-ecdh": "ECDH (static)", "kx-dh": "DH (static)", "kx-psk": "PSK",
    "kx-any": "any (TLS 1.3 ephemeral)", "kx-srp": "SRP", "kx-gost": "GOST",
}


def _cipher_details(sock: ssl.SSLSocket, ctx: ssl.SSLContext) -> dict[str, Any]:
    name, proto, bits = sock.cipher()
    info = {"name": name, "protocol": proto, "secret_bits": bits,
            "key_exchange": None, "authentication": None,
            "encryption": None, "mac_or_aead": None, "aead": None}
    for c in ctx.get_ciphers():
        if c.get("name") == name:
            info["key_exchange"] = _KEA_MAP.get(c.get("kea"), c.get("kea"))
            info["authentication"] = (c.get("auth") or "").replace("auth-", "") or None
            info["encryption"] = c.get("symmetric")
            info["mac_or_aead"] = c.get("digest") or ("AEAD" if c.get("aead") else None)
            info["aead"] = c.get("aead")
            break
    # Fallback / TLS 1.3 handling from the name
    if info["key_exchange"] is None:
        if name.startswith("TLS_"):
            info["key_exchange"] = "any (TLS 1.3 ephemeral)"
        elif name.startswith("ECDHE"):
            info["key_exchange"] = "ECDHE"
        elif name.startswith(("ECDHE", "DHE", "any")):
            info["key_exchange"] = "DHE"
        else:
            info["key_exchange"] = "RSA (static key transport)"
    return info


def _openssl_probe(host: str, port: int, timeout: float,
                   version_flag: str | None = None) -> dict[str, Any]:
    """Best-effort: ask the local `openssl s_client` which key-exchange group
    was actually used. Gives e.g. 'X25519', 'secp256r1', 'X25519MLKEM768'."""
    res = _probe_record(host, port, 'key_exchange', 'OpenSSL CLI')
    exe = shutil.which("openssl")
    res['available'] = bool(exe)
    if not exe:
        res['error_category'] = 'client_unavailable'
        return res
    address = f"[{host}]:{port}" if ':' in host else f"{host}:{port}"
    cmd = [exe, "s_client", "-connect", address, "-showcerts"]
    if not re.fullmatch(r"[\d.]+", host) and ":" not in host:
        cmd += ["-servername", host]
    if version_flag:
        cmd.append(version_flag)
    try:
        version = subprocess.run([exe, 'version'], check=False, capture_output=True, timeout=min(timeout, 2))
        text = version.stdout.decode('utf-8', 'replace').strip()
        if re.fullmatch(r'(?:OpenSSL|LibreSSL) [A-Za-z0-9. +()_-]{1,100}', text):
            res['client']['version'] = text
        p = subprocess.run(cmd, check=False, input=b"", capture_output=True, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError) as error:
        _record_failure(res, error)
        return res
    out = (p.stdout + p.stderr).decode("utf-8", "replace")
    # s_client prints leaf first. Retain only its fingerprint, never PEM/output.
    pem = re.search(r'-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----', out)
    if pem:
        try:
            der = ssl.PEM_cert_to_DER_cert(pem.group(0))
            res['certificate_fingerprint_sha256'] = hashlib.sha256(der).hexdigest()
        except (ValueError, ssl.SSLError):
            pass
    peer = re.search(r'Connecting to ([0-9a-fA-F:.]+)', out)
    if peer:
        import ipaddress
        try:
            res['peer_address'] = str(ipaddress.ip_address(peer.group(1)))
        except ValueError:
            pass
    patterns = {
        'server_temp_key': r'Server Temp Key:\s*([A-Za-z0-9_.+-]{1,80})',
        'server_temp_key_detail': r'Server Temp Key:[^,\n]+,\s*([0-9]{1,6} bits)',
        'negotiated_group': r'Negotiated TLS1\.3 group:\s*([A-Za-z0-9_.+-]{1,80})',
        'peer_signature_type': r'Peer signature type:\s*([A-Za-z0-9_.+-]{1,80})',
        'peer_signing_digest': r'Peer signing digest:\s*([A-Za-z0-9_.+-]{1,80})',
    }
    for key, pattern in patterns.items():
        match = re.search(pattern, out)
        if match:
            res[key] = match.group(1)
    if p.returncode == 0 and (res.get('negotiated_group') or res.get('server_temp_key')):
        res.update(status='completed', outcome='accepted')
    else:
        res['error_category'] = 'group_unreported' if p.returncode == 0 else 'client_failed'
    return res


_PQ_MARKERS = ("MLKEM",)  # Compatibility only; identification below uses exact groups.


def _key_exchange_section(cipher: dict[str, Any], probe: dict[str, Any]) -> dict[str, Any]:
    kx = cipher.get("key_exchange") or ""
    is_13 = cipher.get("protocol") == "TLSv1.3"
    ephemeral = is_13 or kx.startswith(("ECDHE", "DHE", "any"))
    group = ((probe.get("negotiated_group") or probe.get("server_temp_key"))
             if probe.get('outcome') == 'accepted' else None)
    detail = probe.get("server_temp_key_detail")
    pq = None
    if group:
        from crypto_evidence import mlkem_group
        if mlkem_group(group):
            pq = True
        elif group.lower() in ('x25519', 'x448', 'secp256r1', 'secp384r1', 'secp521r1') or re.fullmatch(r'ffdhe\d+', group.lower()):
            pq = False
        else:
            pq = None
    return {
        "method": "ECDHE/DHE (ephemeral, group negotiated)" if is_13 else kx,
        "ephemeral": ephemeral,
        "forward_secrecy": ephemeral,
        "group": group,
        "group_detail": detail,
        "post_quantum_or_hybrid_group": pq,   # None = could not determine
        "group_source": ("openssl s_client" if group else None),
        "note": (None if group else
                 "Exact key-exchange group not determined (openssl CLI missing "
                 "or did not report it). Method is inferred from the cipher suite."),
    }


# --------------------------------------------------------------------------
# Protocol / cipher enumeration
# --------------------------------------------------------------------------

def probe_protocol_versions(host: str, port: int, timeout: float, *, detailed=False):
    """Compatibility bool/None mapping; detailed=True also retains each handshake."""
    supported, probes = {}, []
    for label, attr in _PROTOCOLS:
        record = _probe_record(host, port, 'protocol')
        record['protocol'] = label
        probes.append(record)
        try:
            ctx = _make_context(verify=False, version=attr)
        except (AttributeError, ValueError, ssl.SSLError) as error:
            _record_failure(record, error, local=True)
            supported[label] = None
            continue
        try:
            with _connect(host, port, ctx, timeout) as sock:
                _observe_socket(record, sock)
                actual = sock.version()
                # Python calls TLS 1.0 "TLSv1".
                if actual != label and not (label == 'TLSv1.0' and actual == 'TLSv1'):
                    record.update(outcome='unknown', status='unknown', error_category='unexpected_protocol')
        except (OSError, ValueError) as error:
            _record_failure(record, error)
        supported[label] = {'accepted': True, 'rejected': False}.get(record['outcome'])
    return {'supported': supported, 'probes': probes} if detailed else supported


def enumerate_tls12_ciphers(host: str, port: int, timeout: float, *, detailed=False,
                            max_attempts=64, total_timeout=30.0):
    """Bounded local-candidate TLS 1.2 inspection, not all possible suites.

    The default remains the accepted list. detailed=True includes unknowns,
    explicit peer refusals, candidate coverage and independent observations.
    """
    result = dict(status='partial', accepted=[], attempts=[], candidate_names=[],
                  candidate_count=0, attempted_count=0, unknown_count=0,
                  accepted_count=0, rejected_count=0, error_category=None,
                  scope='local_client_tls12_candidates',
                  settings={'max_attempts': min(max(0, max_attempts), 64),
                            'total_timeout_seconds': min(max(0.0, total_timeout), 30.0)})
    deadline = time.monotonic() + result['settings']['total_timeout_seconds']
    try:
        base = _make_context(verify=False, version='TLSv1_2')
        candidates = {c['name']: c for c in base.get_ciphers()
                      if c.get('protocol') in ('TLSv1.2', 'TLSv1.0', 'SSLv3')}
    except (AttributeError, ValueError, ssl.SSLError) as error:
        result['error_category'] = _failure_category(error, local=True)
        return result if detailed else result['accepted']
    result['candidate_names'] = sorted(candidates)
    result['candidate_count'] = len(candidates)
    for name in result['candidate_names']:
        remaining = deadline - time.monotonic()
        if len(result['attempts']) >= result['settings']['max_attempts'] or remaining <= 0:
            result['error_category'] = 'budget_exhausted'
            break
        record = _probe_record(host, port, 'cipher_enumeration')
        record['cipher_name'] = name
        result['attempts'].append(record)
        try:
            ctx = _make_context(verify=False, version='TLSv1_2', ciphers=f'{name}:@SECLEVEL=0')
        except (AttributeError, ValueError, ssl.SSLError) as error:
            _record_failure(record, error, local=True)
            continue
        try:
            with _connect(host, port, ctx, min(timeout, remaining)) as sock:
                _observe_socket(record, sock)
                if sock.version() != 'TLSv1.2' or sock.cipher()[0] != name:
                    record.update(status='unknown', outcome='unknown', error_category='unexpected_negotiation')
                else:
                    c = candidates[name]
                    result['accepted'].append({'name': name,
                        'key_exchange': _KEA_MAP.get(c.get('kea'), c.get('kea')),
                        'authentication': (c.get('auth') or '').replace('auth-', ''),
                        'bits': c.get('strength_bits'), 'probe_id': record['id']})
        except (OSError, ValueError) as error:
            _record_failure(record, error)
    result['attempted_count'] = len(result['attempts'])
    for outcome in ('accepted', 'rejected', 'unknown'):
        result[outcome + '_count'] = sum(p['outcome'] == outcome for p in result['attempts'])
    if result['attempted_count'] == result['candidate_count'] and not result['unknown_count'] and candidates:
        result['status'] = 'complete'
    return result if detailed else result['accepted']


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------

def scan_tls(host: str, port: int | None = None, timeout: float = 8.0,
             deep: bool = False, use_openssl: bool = True) -> dict[str, Any]:
    """Scan one TLS endpoint. `host` may be a bare domain or a full URL
    ('https://example.com/x', 'example.com:8443'). If `port` is given it wins.
    NEVER raises: failures are reported in the result
    (`scan_status` = ok | partial | failed, plus an `errors` list)."""
    raw_input = host
    try:
        host, parsed_port = normalize_target(host)
        port = port or parsed_port
    except ValueError as e:
        return {"module": MODULE_NAME, "schema_version": SCHEMA_VERSION,
                "target": {"input": raw_input, "host": None, "port": port},
                "scanned_at": _now().isoformat(), "scan_status": "failed",
                "errors": [{"stage": "input", "error": str(e)}],
                "connection": None, "cipher_suite": None, "key_exchange": None,
                "certificate": None, "certificate_validation": None,
                "supported_protocols": None, "supported_tls12_ciphers": None}
    result: dict[str, Any] = {
        "module": MODULE_NAME,
        "schema_version": SCHEMA_VERSION,
        "target": {"input": raw_input, "host": host, "port": port},
        "scanned_at": _now().isoformat(),
        "scan_status": "failed",
        "errors": [],
        "connection": None,
        "cipher_suite": None,
        "key_exchange": None,
        "certificate": None,
        "certificate_validation": None,
        "supported_protocols": None,
        "supported_tls12_ciphers": None,
        "probes": [], "cipher_enumeration": None,
        "coverage": {"certificate_inspection": "leaf_only", "system_trust": "separate_handshake",
                     "full_chain_inventory": "unassessed", "revocation": "not_checked"},
    }
    if not _HAVE_CRYPTO:
        result["errors"].append({"stage": "init", "error":
            "The 'cryptography' package is required: pip install cryptography"})
        return result

    inspection = _probe_record(host, port, 'inspection')
    result['probes'].append(inspection)
    # 1) Main handshake (unverified, so we can still inspect bad certs)
    try:
        ctx = _make_context(verify=False)
        with _connect(host, port, ctx, timeout) as s:
            result["connection"] = {
                "tls_version": s.version(),
                "alpn_protocol": s.selected_alpn_protocol(),
                "ip_address": s.getpeername()[0],
            }
            result["cipher_suite"] = _cipher_details(s, ctx)
            der = _observe_socket(inspection, s)
    except (OSError, ValueError) as error:
        _record_failure(inspection, error)
        result["errors"].append({"stage": "inspection", "error": inspection['error_category']})
        return result

    result["scan_status"] = "ok"

    # 2) Certificate
    try:
        result["certificate"] = parse_certificate(der)
    except Exception as e:
        result["scan_status"] = "partial"
        result["errors"].append({"stage": "certificate", "error": "leaf_certificate_parse_failed"})

    # 3) System trust validation uses an independent handshake.
    trust = _probe_record(host, port, 'system_trust')
    result['probes'].append(trust)
    try:
        vctx = _make_context(verify=True)
        with _connect(host, port, vctx, timeout) as sock:
            _observe_socket(trust, sock)
            result["certificate_validation"] = {"trusted": True, "error": None}
    except ssl.SSLCertVerificationError as e:
        trust.update(status="completed", outcome="rejected", error_category="certificate_verification_failed")
        result["certificate_validation"] = {"trusted": False, "error": "System trust or hostname verification failed"}
    except (OSError, ValueError) as e:
        _record_failure(trust, e)
        result["certificate_validation"] = {"trusted": None, "error": "System trust validation inconclusive"}

    # 4) Key-exchange details
    _correlate(trust, inspection)
    result['certificate_validation'].update(probe_id=trust['id'], correlation_to_inspection=trust['correlation_to_inspection'])
    probe = _probe_record(host, port, 'key_exchange', 'OpenSSL CLI')
    probe.update(available=False, error_category='not_requested')
    if use_openssl:
        probe = _openssl_probe(host, port, timeout)
    result["key_exchange"] = _key_exchange_section(result["cipher_suite"], probe)
    _correlate(probe, inspection)
    result['probes'].append(probe)
    kx = result['key_exchange']
    kx.update(group_probe_id=probe['id'], probe_group=kx['group'],
              probe_post_quantum_or_hybrid_group=kx['post_quantum_or_hybrid_group'],
              correlation_to_inspection=probe['correlation_to_inspection'])
    # Even the same leaf can negotiate another group on another connection.
    kx.update(group=None, group_detail=None, post_quantum_or_hybrid_group=None,
              group_source=None, inspection_probe_id=inspection['id'],
              note='Exact group belongs to a separate OpenSSL handshake; the inspection group is unassessed.')
    kx['openssl_probe'] = probe
    if use_openssl and not probe.get("available"):
        result["errors"].append({"stage": "key_exchange", "error":
            "openssl CLI not found; exact key-exchange group and PQ status remain unknown"})

    # 5) Supported protocol versions
    try:
        protocol_result = probe_protocol_versions(host, port, timeout, detailed=True)
        result['supported_protocols'] = protocol_result['supported']
        for entry in protocol_result['probes']:
            _correlate(entry, inspection)
        result['probes'].extend(protocol_result['probes'])
        inconclusive = [name for name, accepted in result['supported_protocols'].items() if accepted is None]
        if inconclusive:
            result['scan_status'] = 'partial'
            result['errors'].append({'stage': 'protocol_probe', 'error': 'Inconclusive protocol tests: '+', '.join(inconclusive)})
    except Exception as e:  # defensive
        result["scan_status"] = "partial"
        result["errors"].append({"stage": "protocol_probe", "error": "protocol_probe_failed"})

    # 6) Optional TLS 1.2 cipher enumeration
    if deep:
        try:
            enumeration = enumerate_tls12_ciphers(host, port, timeout, detailed=True)
            result['cipher_enumeration'] = enumeration
            result['supported_tls12_ciphers'] = enumeration['accepted']
            for entry in enumeration['attempts']:
                _correlate(entry, inspection)
            result['probes'].extend(enumeration['attempts'])
            if enumeration['status'] != 'complete':
                result['scan_status'] = 'partial'
                result['errors'].append({'stage':'cipher_enum', 'error':'TLS 1.2 candidate enumeration incomplete; unknown outcomes are not rejections.'})
        except Exception as e:
            result["scan_status"] = "partial"
            result["errors"].append({"stage": "cipher_enum", "error": "cipher_enumeration_failed"})

    for entry in result['probes'][1:]:
        if entry['outcome'] == 'unknown' or (entry['outcome'] == 'accepted' and
                entry['correlation_to_inspection'] != 'matched'):
            result['scan_status'] = 'partial'
            result['errors'].append({'stage': entry['stage'], 'probe_id': entry['id'],
                                     'error': entry['error_category'] or
                                     'identity_correlation_' + entry['correlation_to_inspection']})

    return result


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _print_summary(r: dict[str, Any]) -> None:
    t = r["target"]
    print(f"\n== TLS scan: {t['host'] or t.get('input')}:{t['port']}  [{r['scan_status']}] ==")
    for e in r["errors"]:
        print(f"  ! {e['stage']}: {e['error']}")
    if r["connection"]:
        c, k = r["cipher_suite"], r["key_exchange"]
        print(f"  Version      : {r['connection']['tls_version']}")
        print(f"  Cipher suite : {c['name']} ({c['secret_bits']} bit)")
        print(f"  Key exchange : {k['method']}  group={k['group']}  "
              f"forward_secrecy={k['forward_secrecy']}  pq/hybrid={k['post_quantum_or_hybrid_group']}")
    cert = r["certificate"]
    if cert:
        pk, sg = cert["public_key"], cert["signature"]
        print(f"  Cert subject : {cert['subject']['common_name']}  (issuer: {cert['issuer']['common_name']})")
        print(f"  Public key   : {pk['algorithm']} {pk['key_size_bits']} bit  curve={pk['curve']}")
        print(f"  Signature    : {sg['algorithm']}  (hash={sg['hash']})")
        print(f"  Validity     : {cert['not_before'][:10]} -> {cert['not_after'][:10]}  "
              f"({cert['days_until_expiry']} days left)")
    v = r["certificate_validation"]
    if v:
        print(f"  Trusted chain: {v['trusted']}  {v['error'] or ''}")
    if r["supported_protocols"]:
        print("  Protocols    : " + ", ".join(
            f"{k}={'yes' if v_ else 'no' if v_ is False else '?'}"
            for k, v_ in r["supported_protocols"].items()))


def _ensure_dependencies() -> None:
    """If `cryptography` is missing, install it automatically and restart."""
    if _HAVE_CRYPTO:
        return
    import os
    print("First run: installing the 'cryptography' package (one time only)...")
    cmds = [[sys.executable, "-m", "pip", "install", "cryptography"],
            [sys.executable, "-m", "pip", "install", "--break-system-packages", "cryptography"]]
    for cmd in cmds:
        if subprocess.run(cmd, check=False).returncode == 0:
            os.execv(sys.executable, [sys.executable] + sys.argv)   # restart
    print("Could not install it automatically. Please run:  pip install cryptography")
    sys.exit(3)


def _scan_and_report(domain, port, args) -> int:
    r = scan_tls(domain, port, args.timeout, args.deep, not args.no_openssl)
    if args.json == "-":
        print(json.dumps(r, indent=2))
        return 0 if r["scan_status"] != "failed" else 1
    _print_summary(r)
    if not args.no_save and r["target"]["host"]:
        out = args.json or re.sub(r"[^A-Za-z0-9._-]", "_",
                                  f"{r['target']['host']}_tls.json")
        with open(out, "w", encoding="utf-8") as f:
            json.dump(r, f, indent=2)
        print(f"\n  Full JSON saved to: {out}")
    return 0 if r["scan_status"] != "failed" else 1


def main(argv: list[str] | None = None) -> int:
    _ensure_dependencies()
    ap = argparse.ArgumentParser(
        description="TLS and certificate scanner. Give it a domain or URL.")
    ap.add_argument("domain", nargs="?",
                    help="e.g. google.com, https://github.com/x, example.com:8443 "
                         "(prompted if omitted)")
    ap.add_argument("port", nargs="?", type=int, help="optional; default 443")
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--deep", action="store_true",
                    help="also enumerate every accepted TLS 1.2 cipher suite (slow)")
    ap.add_argument("--no-openssl", action="store_true",
                    help="do not call the openssl CLI for key-exchange group")
    ap.add_argument("--json", metavar="FILE",
                    help="JSON output file ('-' = print JSON to screen). "
                         "Default: auto-saved as <domain>_tls.json")
    ap.add_argument("--no-save", action="store_true", help="do not write a JSON file")
    args = ap.parse_args(argv)

    if args.domain:                      # one-shot mode
        return _scan_and_report(args.domain, args.port, args)

    # Interactive mode: just type domains, one after another.
    print("TLS & certificate scanner  -  type a domain and press Enter "
          "(blank line or 'q' to quit)")
    while True:
        try:
            domain = input("\nDomain> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if domain.lower() in ("", "q", "quit", "exit"):
            return 0
        _scan_and_report(domain, None, args)


if __name__ == "__main__":
    sys.exit(main())
