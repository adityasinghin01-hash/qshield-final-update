"""Compare observed evidence without treating narrower scans as remediation."""
import re

SEVERITIES = ('critical', 'high', 'medium', 'low', 'info')


def _validate_report(report):
    if not isinstance(report, dict) or not report:
        raise ValueError('Comparison scans must be nonempty objects.')
    for field in ('metadata', 'risk_assessment', 'inventory', 'modules'):
        if not isinstance(report.get(field, {}), dict):
            raise ValueError(field + ' must be an object.')
    meta = report.get('metadata', {})
    if not isinstance(meta.get('targets', {}), dict) or not isinstance(meta.get('errors', []), list):
        raise ValueError('Invalid metadata targets or diagnostics.')
    risk = report.get('risk_assessment', {})
    summary = risk.get('summary', {})
    if not isinstance(summary, dict):
        raise ValueError('summary must be an object.')
    if not isinstance(summary.get('coverage', {}), dict):
        raise ValueError('Summary coverage must be an object.')
    for module, scan in report.get('modules', {}).items():
        if scan is None:
            continue
        if not isinstance(scan, dict):
            raise ValueError('Scanner modules must be objects or null.')
        for field in ('coverage', 'summary'):
            if field in scan and not isinstance(scan[field], dict):
                raise ValueError('Scanner ' + field + ' must be an object.')
        if module == 'iac_scanner':
            observations = scan.get('observations', [])
            if not isinstance(observations, list) or any(not isinstance(x, dict) for x in observations):
                raise ValueError('Infrastructure observations must be objects.')
    for field in ('severity', 'track'):
        values = summary.get(field, {})
        if not isinstance(values, dict) or any(type(n) is not int or n < 0 for n in values.values()):
            raise ValueError(field + ' counts must be nonnegative integers.')
    for field in ('total_assessments', 'unknown_count', 'unknown_finding_count'):
        if field in summary and (type(summary[field]) is not int or summary[field] < 0):
            raise ValueError(field + ' must be a nonnegative integer.')
    for values in (risk.get('assessments', []), report.get('inventory', {}).get('findings', [])):
        if not isinstance(values, list) or any(not isinstance(x, dict) for x in values):
            raise ValueError('Assessments and findings must be arrays of objects.')
        for item in values:
            for field in ('id', 'finding_id', 'assessment_id', 'asset', 'algorithm', 'rule_id', 'title'):
                if field in item and not isinstance(item[field], str):
                    raise ValueError(field + ' must be a string.')
            attrs = item.get('attributes', {})
            if not isinstance(attrs, dict):
                raise ValueError('Finding attributes must be an object.')
            identity = attrs.get('source_identity')
            if identity is not None:
                if not isinstance(identity, dict):
                    raise ValueError('Source identity must be an object.')
                for field in ('relative_path', 'scope', 'call', 'match_type'):
                    if field in identity and not isinstance(identity[field], str):
                        raise ValueError('Source identity fields must be strings.')


def _group_findings(report):
    groups, legacy = {}, False
    repo = str(report.get('metadata', {}).get('targets', {}).get('repo') or '').replace('\\', '/').rstrip('/')
    inventory = {f.get('id'): f for f in report.get('inventory', {}).get('findings', [])}
    for assessment in report.get('risk_assessment', {}).get('assessments', []):
        observation = inventory.get(assessment.get('finding_id'), {})
        attrs = observation.get('attributes', {})
        identity = attrs.get('source_identity') or {}
        asset = str(assessment.get('asset') or '').replace('\\', '/')
        rule = str(assessment.get('rule_id') or assessment.get('title') or '')
        algorithm = str(assessment.get('algorithm') or '')
        if identity.get('version') == 1 and all(identity.get(k) for k in ('relative_path', 'scope', 'call')):
            # Pair multiplicity, not generated IDs, line numbers or ordinal order.
            key = ('source', identity['relative_path'], identity['scope'], identity['call'],
                   identity.get('match_type', ''), rule, algorithm)
        elif str(assessment.get('finding_id', '')).startswith('code-') or attrs.get('source_scope'):
            legacy = True
            asset = re.sub(r':\d+$', '', asset)
            if repo and asset.startswith(repo + '/'):
                asset = asset[len(repo) + 1:]
            key = ('legacy-source', asset, rule, algorithm)
        elif attrs.get('file_path') and attrs.get('field'):
            key = ('iac', str(attrs['file_path']), str(attrs['field']), rule, algorithm)
        else:
            key = ('observation', asset or str(assessment.get('assessment_id') or 'unknown'), rule, algorithm)
        groups.setdefault(key, []).append(assessment)
    return groups, legacy


def _compatibility_warnings(before, after):
    warnings = []
    a, b = before.get('metadata', {}), after.get('metadata', {})
    for key, label in (('targets', 'Scan targets'), ('scenario', 'Planning scenarios'),
                       ('crqc_horizon_years', 'Planning horizons'),
                       ('ruleset_fingerprint', 'Effective rules'), ('scan_options', 'Scan options')):
        if key not in a or key not in b:
            warnings.append(label + ' lack comparable provenance.')
        elif a[key] != b[key]:
            warnings.append(label + ' differ; observed deltas are not a same-scope result.')
    if a.get('is_demo') or b.get('is_demo'):
        warnings.append('Comparison includes illustrative demo data.')
    for report in (before, after):
        if report.get('metadata', {}).get('errors'):
            warnings.append('At least one scan has diagnostics or failed stages.')
        summary = report.get('risk_assessment', {}).get('summary', {})
        if 'unknown_count' not in summary:
            warnings.append('Unknown-evidence counts are unavailable.')
        elif summary['unknown_count'] or summary.get('coverage', {}).get('status') in ('partial', 'unknown'):
            warnings.append('At least one scan contains incomplete or unresolved evidence.')
    modules_a, modules_b = before.get('modules', {}), after.get('modules', {})
    active_a = {k for k, v in modules_a.items() if v is not None}
    active_b = {k for k, v in modules_b.items() if v is not None}
    if not active_a or active_a != active_b:
        warnings.append('Scanner module coverage differs or is unavailable.')
    for module in active_a | active_b:
        left, right = modules_a.get(module), modules_b.get(module)
        if not isinstance(left, dict) or not isinstance(right, dict):
            continue
        if module == 'code_scanner':
            cov_a, cov_b = left.get('coverage', {}), right.get('coverage', {})
            for field in ('scanned_paths', 'settings', 'capabilities'):
                if field not in cov_a or field not in cov_b or cov_a[field] != cov_b[field]:
                    warnings.append('Source ' + field.replace('_', ' ') + ' differ or are unavailable.')
            for scan, coverage in ((left, cov_a), (right, cov_b)):
                if (scan.get('coverage_status') != 'complete' or coverage.get('exclusions')
                        or coverage.get('unresolved') or coverage.get('attempted_files') != coverage.get('scanned_files')):
                    warnings.append('Source inspection is incomplete or excludes evidence.')
        elif module == 'iac_scanner':
            if left.get('coverage_status') != 'complete' or right.get('coverage_status') != 'complete':
                warnings.append('Infrastructure inspection is incomplete.')
            if (left.get('catalog_reviewed_at') != right.get('catalog_reviewed_at')
                    or left.get('summary', {}).get('scanned_files') != right.get('summary', {}).get('scanned_files')):
                warnings.append('Infrastructure catalog or inspected file counts differ.')
            paths_a = {str(o.get('file')) for o in left.get('observations', [])}
            paths_b = {str(o.get('file')) for o in right.get('observations', [])}
            if paths_a != paths_b:
                warnings.append('Infrastructure observation files differ.')
        elif module == 'tls_scanner':
            if left.get('scan_status') != 'ok' or right.get('scan_status') != 'ok':
                warnings.append('TLS inspection is incomplete.')
            for field in ('connection', 'cipher_suite', 'certificate', 'certificate_validation',
                          'key_exchange', 'supported_protocols', 'supported_tls12_ciphers'):
                if bool(left.get(field)) != bool(right.get(field)):
                    warnings.append('TLS ' + field.replace('_', ' ') + ' evidence is missing from one scan.')
            for field in ('connection', 'certificate', 'key_exchange'):
                a_fields = set(left.get(field) or {})
                b_fields = set(right.get(field) or {})
                if a_fields != b_fields:
                    warnings.append('TLS ' + field.replace('_', ' ') + ' evidence fields differ.')
    return list(dict.fromkeys(warnings))


def compare_scans(baseline_scan, current_scan):
    """Return evidence deltas; a disappearance alone never verifies remediation."""
    _validate_report(baseline_scan)
    _validate_report(current_scan)
    before, legacy_before = _group_findings(baseline_scan)
    after, legacy_after = _group_findings(current_scan)
    absent, added, persistent = [], [], []
    for key in sorted(set(before) | set(after)):
        left, right = before.get(key, []), after.get(key, [])
        paired = min(len(left), len(right))
        persistent.extend(right[:paired])
        absent.extend(left[paired:])
        added.extend(right[paired:])

    def counts(report):
        items = report.get('risk_assessment', {}).get('assessments', [])
        return dict(id=report.get('metadata', {}).get('scan_id'),
                    timestamp=report.get('metadata', {}).get('scan_finished_at'),
                    targets=report.get('metadata', {}).get('targets', {}),
                    total_assessments=len(items),
                    severity={s: sum(x.get('severity') == s for x in items) for s in SEVERITIES},
                    track={t: sum(x.get('track') == t for x in items) for t in ('quantum', 'conventional')})

    a, b = counts(baseline_scan), counts(current_scan)
    delta = {s: b['severity'][s] - a['severity'][s] for s in SEVERITIES}
    warnings = _compatibility_warnings(baseline_scan, current_scan)
    if legacy_before or legacy_after:
        warnings.append('Legacy source identities lack function/call provenance; matching is approximate.')
    removed_risks = [x for x in absent if x.get('severity') in SEVERITIES[:-1]]
    added_risks = [x for x in added if x.get('severity') in SEVERITIES[:-1]]
    if warnings:
        status = 'inconclusive'
        note = 'Evidence or scope is not fully comparable. Absent findings do not establish remediation.'
    elif added_risks and removed_risks:
        status = 'changed'
        note = 'Some risks are absent and others are newly observed; inspect both sets.'
    elif added_risks or any(delta[s] > 0 for s in SEVERITIES[:-1]):
        status = 'degraded'
        note = 'New or higher-severity risks are observed in the comparable scope.'
    elif removed_risks or any(delta[s] < 0 for s in SEVERITIES[:-1]):
        status = 'improved'
        note = 'Fewer risks are observed in the same inspected scope. Absence does not verify remediation or runtime behavior.'
    elif absent or added:
        status = 'changed'
        note = 'Informational observations changed; this is not verified risk reduction.'
    else:
        status = 'unchanged'
        note = 'The same assessed observations remain in the comparable inspected scope.'
    return dict(warnings=warnings, status=status, status_note=note,
                scope_compatible=not warnings, remediation_verified=False,
                identity_confidence='approximate' if legacy_before or legacy_after else 'scoped',
                baseline=a, comparison=b,
                deltas=dict(total_assessments=b['total_assessments']-a['total_assessments'],
                            severity=delta, track={t: b['track'][t]-a['track'][t] for t in a['track']}),
                resolved_findings=absent, new_findings=added, persistent_findings=persistent)
