"""Validated business assumptions and bounded, process-local exact rule snapshots.

Planning context never substitutes for TLS/source evidence. Missing snapshots refuse
reassessment; no disk reload or scanner is part of this path.
"""
import copy
import hashlib
import json
import math
import threading
from collections import OrderedDict
from dataclasses import asdict
from datetime import datetime, timezone

from risk_engine import RiskEngine

YEAR_FIELDS = ('data_lifetime_years', 'trust_lifetime_years', 'migration_years')
CONTEXT_FIELDS = YEAR_FIELDS + ('exposure', 'criticality')
EXPOSURES = ('internet', 'partner', 'internal', 'isolated')
CRITICALITIES = ('low', 'medium', 'high', 'critical')
MAX_YEARS = 1000
MAX_RULE_SNAPSHOTS = 50
_RULE_SNAPSHOTS = OrderedDict()
_RULE_LOCK = threading.Lock()


class RulesSnapshotUnavailable(ValueError):
    """Exact effective rules for this stored evidence are no longer available."""


def remember_rules(rules):
    fingerprint = hashlib.sha256(json.dumps(asdict(rules), sort_keys=True, default=str).encode()).hexdigest()
    with _RULE_LOCK:
        _RULE_SNAPSHOTS[fingerprint] = copy.deepcopy(rules)
        _RULE_SNAPSHOTS.move_to_end(fingerprint)
        while len(_RULE_SNAPSHOTS) > MAX_RULE_SNAPSHOTS:
            _RULE_SNAPSHOTS.popitem(last=False)
    return fingerprint


def findings_with_context(findings, planning):
    """Serialize effective values, identifying adapter/policy estimates as assumed."""
    serialized = []
    for finding in findings:
        item = asdict(finding)
        if item['migration_years'] is None:
            item['migration_years'] = planning.migration_years_default
        item['planning_context'] = {}
        for field in CONTEXT_FIELDS:
            value = item[field]
            rationale = ('Not provided; lifetime remains unknown for planning.' if value is None else
                         'Adapter or policy planning default; asset owner has not confirmed this value.')
            item['planning_context'][field] = dict(value=value, provenance='assumed', rationale=rationale)
        serialized.append(item)
    return serialized


def validate_overrides(overrides, findings):
    if not isinstance(overrides, list):
        raise ValueError('overrides must be an array of per-finding objects.')
    known = {f['id'] for f in findings}
    seen = set()
    for override in overrides:
        if not isinstance(override, dict) or set(override) - {'finding_id', *CONTEXT_FIELDS}:
            raise ValueError('Override must be an object with only finding_id and supported planning fields.')
        fid = override.get('finding_id')
        if not isinstance(fid, str) or fid not in known:
            raise ValueError('Unknown finding_id in planning override.')
        if fid in seen:
            raise ValueError('Duplicate finding_id in planning overrides.')
        seen.add(fid)
        if len(override) == 1:
            raise ValueError('Each override must confirm at least one planning field.')
        for field, value in override.items():
            if field in YEAR_FIELDS:
                if (type(value) not in (int, float) or not 0 <= value <= MAX_YEARS
                        or not math.isfinite(value)):
                    raise ValueError(field + ' must be a finite number from 0 to 1000 years.')
            elif field == 'exposure' and value not in EXPOSURES:
                raise ValueError('exposure must be internet, partner, internal or isolated.')
            elif field == 'criticality' and value not in CRITICALITIES:
                raise ValueError('criticality must be low, medium, high or critical.')
    return overrides


def reassess_planning(source, overrides):
    """Return a new result, using stored findings and the exact original RuleSet."""
    findings = source.get('inventory', {}).get('findings', [])
    validate_overrides(overrides, findings)
    fingerprint = source.get('metadata', {}).get('ruleset_fingerprint')
    with _RULE_LOCK:
        rules = copy.deepcopy(_RULE_SNAPSHOTS.get(fingerprint))
    if rules is None:
        raise RulesSnapshotUnavailable('Exact server-held rules for this scan are unavailable; run a new scan.')
    derived = copy.deepcopy(source)
    by_id = {f['id']: f for f in derived['inventory']['findings']}
    if any(not isinstance(f.get('planning_context'), dict) or
           set(f['planning_context']) != set(CONTEXT_FIELDS) for f in by_id.values()):
        raise RulesSnapshotUnavailable('Stored scan lacks effective planning context; run a new scan.')
    for override in overrides:
        item = by_id[override['finding_id']]
        for field, value in override.items():
            if field == 'finding_id':
                continue
            item[field] = value
            item['planning_context'][field] = dict(value=value, provenance='user_confirmed',
                rationale='Asset owner confirmed this business planning value; cryptographic evidence is unchanged.')
    meta = derived['metadata']
    parent_id = source['metadata'].get('scan_id')
    meta.pop('scan_id', None)
    meta.update(parent_scan_id=parent_id, assessment_type='planning_update',
                evidence_scan_id=meta.get('evidence_scan_id') or parent_id,
                evidence_observed_at=meta.get('evidence_observed_at') or meta.get('scan_finished_at'),
                reassessed_at=datetime.now(timezone.utc).isoformat())
    engine = RiskEngine(rules, scenario=meta.get('scenario'))
    derived['risk_assessment'] = engine.assess(derived['inventory']['findings']).to_dict()
    from scan_results import post_process_scan_result
    return post_process_scan_result(derived)
