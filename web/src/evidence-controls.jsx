import React, {useEffect, useMemo, useRef, useState} from 'react';
import {createPortal} from 'react-dom';

// A portal keeps the native top-layer dialog outside the explicitly inert app.
export function EvidenceDialog({children, onClose}) {
  const dialogRef = useRef(null);
  useEffect(() => {
    const dialog = dialogRef.current;
    const opener = document.activeElement;
    const root = document.getElementById('root');
    const previousInert = root.inert;
    const previousOverflow = document.body.style.overflow;
    dialog.showModal();
    root.inert = true;
    document.body.style.overflow = 'hidden';
    dialog.querySelector('[aria-label="Close evidence inspector"]')?.focus({preventScroll:true});
    return () => {
      root.inert = previousInert;
      document.body.style.overflow = previousOverflow;
      dialog.close();
      if (opener?.isConnected) opener.focus({preventScroll:true});
    };
  }, []);
  const containTab = event => {
    if (event.key !== 'Tab') return;
    const dialog = dialogRef.current;
    const candidates = [...dialog.querySelectorAll('button, a[href], input, select, textarea, summary, [tabindex]')].filter(element => {
      if (element.disabled || element.tabIndex < 0 || !element.getClientRects().length) return false;
      for (let details=element.closest('details'); details; details=details.parentElement?.closest('details')) {
        if (!details.open && !details.querySelector(':scope > summary')?.contains(element)) return false;
      }
      return true;
    });
    const first=candidates[0], last=candidates[candidates.length-1];
    if (!first) { event.preventDefault(); dialog.focus(); return; }
    if (event.shiftKey && (document.activeElement===first || !dialog.contains(document.activeElement))) {event.preventDefault();last.focus();}
    else if (!event.shiftKey && (document.activeElement===last || !dialog.contains(document.activeElement))) {event.preventDefault();first.focus();}
  };
  return createPortal(<dialog onKeyDown={containTab} ref={dialogRef} className="evidence-dialog" aria-modal="true" aria-labelledby="evidence-dialog-title" onCancel={e=>{e.preventDefault();onClose();}}>{children}</dialog>, document.body);
}

const FIELDS = [
  ['data_lifetime_years','Data retention (years)'],
  ['trust_lifetime_years','Trust lifetime (years)'],
  ['migration_years','Migration time (years)'],
  ['exposure','Exposure',['internet','partner','internal','isolated']],
  ['criticality','Criticality',['low','medium','high','critical']],
];
const displayValue = value => value == null ? 'Unknown' : String(value);

export function PlanningContext({data, onUpdated}) {
  const groups = useMemo(() => {
    const grouped = new Map();
    for (const finding of data.inventory?.findings || []) {
      if (!finding.id || !finding.planning_context) continue;
      const asset = finding.asset || 'Unspecified asset';
      if (!grouped.has(asset)) grouped.set(asset, []);
      grouped.get(asset).push(finding);
    }
    return Array.from(grouped.entries());
  }, [data]);
  const [asset, setAsset] = useState(groups[0]?.[0] || '');
  const [edited, setEdited] = useState({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const findings = groups.find(([name])=>name===asset)?.[1] || [];
  if (!groups.length) return null;
  const describe = key => {
    const entries = findings.map(f=>f.planning_context[key]);
    const values = [...new Set(entries.map(entry=>displayValue(entry?.value)))];
    const provenance = [...new Set(entries.map(entry=>entry?.provenance || 'assumed'))];
    return {value: values.length===1 && values[0]!=='Unknown' ? String(entries[0].value) : '', label:values.join(' / '), mixed:values.length>1, provenance:provenance.map(p=>p==='user_confirmed'?'User confirmed':'Assumed').join(' / '), entries};
  };
  const confirm = async event => {
    event.preventDefault();
    setError('');
    const fields = {};
    for (const [key,,choices] of FIELDS) {
      if (!(key in edited) || edited[key]==='') continue;
      fields[key] = choices ? edited[key] : Number(edited[key]);
    }
    if (!Object.keys(fields).length) { setError('Choose at least one known value to confirm. Blank values remain unchanged.'); return; }
    setBusy(true);
    try {
      const response = await fetch('/api/reassess', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({scan_id:data.metadata.scan_id,overrides:findings.map(f=>({finding_id:f.id,...fields}))})});
      const result = await response.json();
      if (!response.ok || result.error) throw Error(result.error || 'Planning update failed.');
      onUpdated(result);
    } catch (failure) { setError(failure.message || 'Unable to update planning context.'); }
    finally { setBusy(false); }
  };
  return <section className="release-panel planning-context" aria-labelledby="planning-heading">
    <div className="intel-panel-head"><h3 id="planning-heading">Confirm asset planning context</h3><span>ASSUMPTIONS / OWNER INPUT</span></div>
    <p className="intel-description">Defaults are assumptions, including certificate-based estimates. Confirm only values you know. This recalculates conditional planning from stored evidence; it does not rescan or verify a fix.</p>
    {data.metadata?.assessment_type==='planning_update' && <p className="planning-update" role="status">Planning update {data.metadata.scan_id} · parent {data.metadata.parent_scan_id}. Updated {data.metadata.reassessed_at}. Original evidence: {data.metadata.evidence_observed_at || data.metadata.scan_finished_at}.</p>}
    <form onSubmit={confirm}>
      <label className="planning-asset">Asset<select aria-label="Planning asset" value={asset} disabled={busy} onChange={e=>{setAsset(e.target.value);setEdited({});setError('');}}>{groups.map(([name,items])=><option key={name} value={name}>{name} ({items.length} findings)</option>)}</select></label>
      <p className="intel-caption">Applies to all {findings.length} inventory findings for this asset. Mixed values stay unchanged unless you enter and confirm a shared value.</p>
      <div className="planning-fields">{FIELDS.map(([key,label,choices])=>{
        const current = describe(key), value = key in edited ? edited[key] : current.value;
        return <div key={key} className="planning-field"><label htmlFor={'context-'+key}>{label}</label>{choices?<select id={'context-'+key} disabled={busy} value={value} onChange={e=>setEdited({...edited,[key]:e.target.value})}><option value="">{current.mixed?'Mixed / leave unchanged':'Unknown / leave unchanged'}</option>{choices.map(choice=><option key={choice} value={choice}>{choice}</option>)}</select>:<input id={'context-'+key} disabled={busy} type="number" min="0" max="1000" step="any" placeholder={current.mixed?'Mixed / unchanged':'Unknown / unchanged'} value={value} onChange={e=>setEdited({...edited,[key]:e.target.value})}/>}
          <p className="context-current">{current.mixed?'Mixed values: ':''}{current.label} · <strong>{current.provenance}</strong></p>
          <label className="context-confirm"><input type="checkbox" disabled={busy||value===''} checked={key in edited && edited[key]!==''} onChange={e=>{const next={...edited};if(e.target.checked)next[key]=value;else delete next[key];setEdited(next);}}/>Confirm this value</label>
          <details><summary>Why this value?</summary>{[...new Set(current.entries.map(entry=>entry?.rationale || 'Context provenance unavailable.'))].map(rationale=><p key={rationale}>{rationale}</p>)}</details>
        </div>;
      })}</div>
      {error&&<p role="alert" className="release-error">{error}<small>The current report remains unchanged.</small></p>}
      <button className="context-submit" type="submit" disabled={busy}>{busy?'Updating planning…':'Confirm context & reassess'}</button>
    </form>
  </section>;
}

export function TLSProvenance({tls}) {
  const keyExchange = tls.key_exchange || {}, validation = tls.certificate_validation || {}, enumeration = tls.cipher_enumeration;
  return <section className="release-panel tls-provenance" aria-labelledby="tls-provenance-heading">
    <h3 id="tls-provenance-heading">TLS observation boundaries</h3>
    <p>Certificate inspection: <b>leaf only</b>. System trust and hostname validation: <b>separate handshake</b>. Full-chain inventory: <b>unassessed</b>. Revocation: <b>not checked</b>.</p>
    <p>Inspection key-exchange group: <b>{keyExchange.group ?? 'Unknown / not observed'}</b>. Independent OpenSSL probe group: <b>{keyExchange.probe_group ?? 'Unknown / not observed'}</b> · probe {keyExchange.group_probe_id || 'unavailable'} · leaf correlation: <b>{keyExchange.correlation_to_inspection || 'unknown'}</b>. A separate group observation does not establish the inspected connection’s negotiated parameters or PQ protection.</p>
    <p>System trust probe: <b>{validation.trusted === true?'Trusted by probe':validation.trusted === false?'Probe trust validation failed':'Unknown / not checked'}</b> · probe {validation.probe_id || 'unavailable'} · leaf correlation: <b>{validation.correlation_to_inspection || 'unknown'}</b>. Trust success applies to this probe.</p>
    {enumeration&&<p>TLS 1.2 enumeration: {enumeration.status || 'unknown'} · {enumeration.candidate_count ?? 'unknown'} local-client candidates · {enumeration.attempted_count ?? 'unknown'} attempted · {enumeration.accepted_count ?? 'unknown'} accepted · {enumeration.rejected_count ?? 'unknown'} rejected · {enumeration.unknown_count ?? 'unknown'} unknown. Scope: {enumeration.scope || 'not supplied'}. These candidates are not every possible cipher suite.</p>}
    <details><summary>Independent handshake provenance ({tls.probes?.length || 0})</summary><p>Leaf fingerprint correlation can be matched, mismatched or unknown. Even matching leaves do not establish one connection or shared negotiated parameters.</p><div className="release-table-wrap"><table className="release-table"><thead><tr>{['Stage / outcome','Client','Leaf fingerprint / correlation','Probe identity / time','Error category'].map(label=><th key={label} scope="col">{label}</th>)}</tr></thead><tbody>{(tls.probes || []).map(probe=><tr key={probe.id}><td>{probe.stage}<small>{probe.status} / {probe.outcome}</small>{probe.protocol || probe.cipher_name}</td><td>{typeof probe.client==='object'?Object.entries(probe.client).map(([k,v])=>k+': '+v).join(' · '):probe.client || 'Unknown'}</td><td>{probe.certificate_fingerprint_sha256 || 'Unknown'}<small>{probe.correlation_to_inspection || 'unknown'}</small></td><td>{probe.id}<small>{probe.timestamp}</small><small>{typeof probe.endpoint==='object'?JSON.stringify(probe.endpoint):probe.endpoint}</small><small>Peer: {typeof probe.peer_address==='object'?JSON.stringify(probe.peer_address):probe.peer_address || 'Unknown'}</small><small>{typeof probe.attribution==='object'?JSON.stringify(probe.attribution):probe.attribution}</small></td><td>{probe.error_category || 'None reported'}</td></tr>)}</tbody></table></div>{!tls.probes?.length&&<p>No per-probe provenance supplied. Legacy observations cannot reconstruct it.</p>}</details>
  </section>;
}
