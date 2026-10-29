"""CI gate: generated code, IaC, and synthetic TLS CBOMs must formally validate."""
from dataclasses import asdict
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from adapters import convert_tls_results_to_findings
from cbom import export_cbom, validate_cbom_schema
from main import run_pipeline
from risk_engine import RiskEngine, RuleSet


def main():
    reports = [
        ('source', run_pipeline(repo_path=str(ROOT/'sample_vulnerable_app'))),
        ('remediated', run_pipeline(repo_path=str(ROOT/'sample_remediated_app'))),
        ('iac', run_pipeline(repo_path=str(ROOT/'docs/examples/iac_sample'), iac=True)),
    ]
    findings = convert_tls_results_to_findings({
        'scan_status': 'ok', 'target': {'host': 'fixture.example', 'port': 443},
        'connection': {'tls_version': 'TLSv1.3'},
        'cipher_suite': {'name': 'TLS_AES_256_GCM_SHA384', 'encryption': 'aes-256-gcm', 'secret_bits': 256},
        'certificate': {'subject': {'common_name': 'fixture.example'},
                        'public_key': {'algorithm': 'RSA', 'key_size_bits': 2048},
                        'signature': {'algorithm': 'sha256WithRSAEncryption'}},
    })
    reports.append(('synthetic TLS', {
        'metadata': {'targets': {'host': 'fixture.example'}, 'scenario': 'central'},
        'inventory': {'findings': [asdict(f) for f in findings]},
        'risk_assessment': RiskEngine(RuleSet.load_from_file(ROOT/'rules.json')).assess(findings).to_dict(),
    }))
    failed = False
    for label, report in reports:
        valid, reason = validate_cbom_schema(export_cbom(report))
        print(f'{label}: ' + ('formally valid' if valid is True else str(reason)))
        failed |= valid is not True
    return int(failed)


if __name__ == '__main__':
    raise SystemExit(main())
