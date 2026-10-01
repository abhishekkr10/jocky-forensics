import { useCallback, useEffect, useId, useMemo, useState, type CSSProperties } from 'react';
import { ArrowRight, GitBranch } from 'lucide-react';
import { useDialogFocus } from './useDialogFocus';

type Row = Record<string, any>;
const digest = (value?: string) => value ? `${value.slice(0, 8)}…` : 'Unavailable';
const stamp = (value?: string) => value && Number.isFinite(Date.parse(value)) ? new Date(value).toISOString().replace('T', ' ').replace('.000Z', ' UTC') : 'Not recorded';

export function Sparkline({ values, label }: { values: (number | null)[]; label: string }) {
  const known = values.filter((value): value is number => value !== null && Number.isFinite(value));
  const max = Math.max(1, ...known);
  const points = values.map((value, index) => value === null || !Number.isFinite(value) ? null : ({ x: 4 + index * 112 / Math.max(1, values.length - 1), y: 32 - value / max * 26, value }));
  const path = points.map((point, index) => point ? `${index === 0 || !points[index - 1] ? 'M' : 'L'}${point.x},${point.y}` : '').join(' ');
  return <div className="metric-history"><svg viewBox="0 0 120 38" role="img" aria-label={`${label}: ${values.map(value => value === null ? 'unavailable' : value).join(', ')}`}><path d={path} fill="none" className="sparkline-path"/>{points.map((point, index) => point && <circle key={index} cx={point.x} cy={point.y} r="2"><title>{point.value}</title></circle>)}</svg><small>{known.length ? label : 'No comparable history available'}{known.length && known.length < values.length ? ' · gaps unavailable' : ''}</small></div>;
}

export function Count({ value }: { value: number }) {
  const [display, setDisplay] = useState(value);
  useEffect(() => {
    if (matchMedia('(prefers-reduced-motion: reduce)').matches) { setDisplay(value); return; }
    let frame = 0;
    const start = performance.now();
    const tick = (now: number) => {
      const progress = Math.min(1, (now - start) / 600);
      setDisplay(Math.round(value * (1 - (1 - progress) ** 3)));
      if (progress < 1) frame = requestAnimationFrame(tick);
    };
    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, [value]);
  return <span>{display.toLocaleString()}</span>;
}

export function IntegrityChain({ evidence, verification, onOpen, limit = 8 }: { evidence: Row[]; verification: Row; onOpen: (id?: string) => void; limit?: number }) {
  const rows = evidence.slice(0, limit);
  const state = verification?.integrity || 'pending';
  return <section className="panel integrity-chain">
    <div className="panel-heading"><div><h2>Integrity chain</h2><p className="panel-note">Record digests and previous chain hashes · {rows.length} of {evidence.length} loaded records</p></div><span className={`badge ${state === 'valid' ? 'green' : state === 'invalid' ? 'red' : 'muted'}`}>{state}</span></div>
    {state === 'invalid' && <p className="alert error" role="alert">{verification.error || 'Checkpoint verification failed.'} Individual records are not certified by this result.</p>}
    <ol className={'hash-chain '+(state==='valid'?'chain-verified':'')} key={JSON.stringify(verification)}>{rows.map((row, i) => <li key={row.evidence_id} style={{ animationDelay: `${Math.min(i, 8) * 60}ms` }}>
      <button className="hash-entry" onClick={() => onOpen(row.evidence_id)} aria-label={`Inspect chain record ${row.sequence}`}>
        <span className="chain-sequence">{String(row.sequence).padStart(3, '0')}</span>
        <span className="chain-content"><strong>{row.artifact_type}<small>{row.endpoint_id}</small></strong><code title={row.previous_hash}>← prev chain: {digest(row.previous_hash)}</code><span>Event: {stamp(row.event_time)}</span><span>Observed: {stamp(row.observed_at)}</span></span>
        <span className="chain-digest"><code title={row.record_digest}>{digest(row.record_digest)}</code><small>record SHA-256</small><span className={`badge ${state === 'valid' ? 'green' : state === 'invalid' ? 'red' : 'muted'}`}>{state === 'valid' ? 'Verified bundle' : state === 'invalid' ? 'Unverified record' : 'Pending'}</span></span>
      </button>
    </li>)}</ol>
    {!rows.length && <p className="panel-note">No evidence records loaded.</p>}
    <button className="text-button chain-open" onClick={() => onOpen()}>Inspect checkpoint <ArrowRight size={14}/></button>
  </section>;
}

export function RiskGauge({ risk, detections, onEvidence }: { risk: Row; detections: Row[]; onEvidence: (id: string) => void }) {
  const score = Math.max(0, Math.min(100, Number(risk?.score) || 0));
  const [needle, setNeedle] = useState(0);
  useEffect(() => { const frame = requestAnimationFrame(() => setNeedle(score)); return () => cancelAnimationFrame(frame); }, [score]);
  const level = score <= 25 ? 'LOW' : score <= 50 ? 'MEDIUM' : score <= 75 ? 'HIGH' : 'CRITICAL';
  return <section className="panel risk-panel"><div className="panel-heading"><h2>{risk?.label || 'Triage score'}</h2><span className="badge">HEURISTIC</span></div>
    <div className="risk-gauge"><svg viewBox="0 0 240 200" role="img" aria-label={`${score} of 100, ${level.toLowerCase()} triage score`}>
      <circle className="gauge-track" cx="120" cy="110" r="82" pathLength="100" strokeDasharray="75 25" transform="rotate(135 120 110)"/>
      {['#22D3A0', '#F59E0B', '#f07840', '#FF4757'].map((color, i) => <circle key={color} cx="120" cy="110" r="82" fill="none" stroke={color} strokeWidth="9" pathLength="100" strokeDasharray="17.75 82.25" transform={`rotate(${135 + i * 67.5} 120 110)`}/>)}
      <g className="gauge-needle" style={{ transform: `rotate(${-135 + needle * 2.7}deg)` }}><path d="M120 45 L116 65 L124 65 Z" fill="currentColor"/></g>
      <text x="120" y="112" textAnchor="middle" className="gauge-score">{score}</text><text x="120" y="137" textAnchor="middle" className="gauge-limit">/ 100</text><text x="120" y="164" textAnchor="middle" className="gauge-level">{level} TRIAGE SCORE</text>
    </svg></div>
    <div className="risk-contributions">{(risk?.contributions || []).map((part: Row, index: number) => {
      const detection = detections.find(d => d.id === part.detection_id);
      const ids: string[] = detection?.evidence_ids || [];
      return <div className="risk-contribution" key={`${part.detection_id}-${index}`}><div><strong>{part.reason}</strong><span>+{part.points}</span></div><meter min="0" max="100" value={part.points} aria-label={part.reason}/><div className="risk-evidence">{ids.map(id => <button key={id} onClick={() => onEvidence(id)}>Inspect {id.slice(0, 8)} <ArrowRight size={12}/></button>)}</div></div>;
    })}</div><p className="panel-note">Triage heuristic, not a probability of compromise. Missing telemetry never means low risk.</p>
  </section>;
}

export function TimeAxis({ timeline, onEvent }: { timeline: Row[]; onEvent: (id: string) => void }) {
  const rows = timeline.filter(t => t && Number.isFinite(Date.parse(t.event_time || t.observed_at))).slice(0, 40);
  if (!rows.length) return <section className="panel time-axis-panel"><div className="panel-heading"><h2>Observed time axis</h2><span className="badge">0 EVENTS</span></div><div className="graph-empty">No timestamped observations in this run.</div></section>;
  const times = rows.map(t => Date.parse(t.event_time || t.observed_at));
  const min = Math.min(...times), max = Math.max(...times), same = min === max;
  const lab = rows.every(t => t.provenance_kind === 'synthetic');
  const label = (time: number) => lab ? `T+${((time - min) / 1000).toFixed(1)}s` : new Date(time).toISOString().slice(11, 23) + ' UTC';
  return <section className="panel time-axis-panel"><div className="panel-heading"><div><h2>Observed time axis</h2><p className="panel-note">{same ? 'All observations share one timestamp; separated below for selection, not elapsed time.' : 'Event timestamps where recorded; observation timestamps otherwise.'}</p></div><span className="badge">{rows.length} EVENTS</span></div><div className="time-axis"><div className="time-axis-line"/>{rows.map((row, index) => <button key={index} disabled={!row.evidence_ids?.length} className={`time-axis-event ${row.detection_ids?.length ? 'hit' : ''}`} style={{ left: `${2 + (same ? index / Math.max(1, rows.length - 1) : (times[index] - min) / (max - min)) * 96}%` }} title={`${row.summary} · ${stamp(row.event_time || row.observed_at)}`} aria-label={`Inspect event: ${row.summary}`} onClick={() => onEvent(row.evidence_ids[0])}>●</button>)}</div><div className="time-axis-labels"><span>{label(min)}</span>{!same && <><span>{label(min + (max - min) / 2)}</span><span>{label(max)}</span></>}</div></section>;
}

type Node = { id: string; label: string; type: string; record: Row; x: number; y: number };
export function EvidenceGraph({ evidence, detections, edges, onEvidence }: { evidence: Row[]; detections: Row[]; edges: Row[]; onEvidence: (id: string) => void }) {
  const marker = useId().replace(/:/g, '');
  const [hover, setHover] = useState<string | null>(null);
  const [selected, setSelected] = useState<Row | null>(null);
  const [nodeDetail, setNodeDetail] = useState<Node | null>(null);
  const closeDetail = useCallback(() => setNodeDetail(null), []);
  useDialogFocus(Boolean(nodeDetail), closeDetail);
  useEffect(() => { setSelected(null); setNodeDetail(null); setHover(null); }, [edges]);
  const { nodes, links } = useMemo(() => {
    const linked = new Set(edges.flatMap(e => [e.source, e.target]));
    const raw = [...evidence.filter(e => linked.has(e.evidence_id)).map(e => ({ id: e.evidence_id, label: e.payload?.summary || e.artifact_type, type: e.artifact_type, record: e })), ...detections.filter(d => linked.has(d.id)).map(d => ({ id: d.id, label: d.rule, type: 'detection', record: d }))].slice(0, 60);
    const nodes: Node[] = raw.map((n, i) => ({ ...n, x: 360 + Math.cos(i * 2 * Math.PI / Math.max(raw.length, 1)) * 240, y: 210 + Math.sin(i * 2 * Math.PI / Math.max(raw.length, 1)) * 145 }));
    const byId = new Map(nodes.map(n => [n.id, n]));
    const links = edges.filter(e => byId.has(e.source) && byId.has(e.target));
    // Bounded deterministic spring layout. No additional runtime dependency.
    for (let step = 0; step < 90; step++) {
      for (let i = 0; i < nodes.length; i++) for (let j = i + 1; j < nodes.length; j++) {
        const a = nodes[i], b = nodes[j], dx = a.x - b.x, dy = a.y - b.y, distance = Math.max(1, Math.hypot(dx, dy));
        const force = Math.min(5, 12000 / (distance * distance));
        a.x += dx / distance * force; a.y += dy / distance * force; b.x -= dx / distance * force; b.y -= dy / distance * force;
      }
      for (const edge of links) {
        const a = byId.get(edge.source)!, b = byId.get(edge.target)!, dx = b.x - a.x, dy = b.y - a.y, distance = Math.max(1, Math.hypot(dx, dy));
        const force = (distance - 180) * .012;
        a.x += dx / distance * force; a.y += dy / distance * force; b.x -= dx / distance * force; b.y -= dy / distance * force;
      }
      nodes.forEach(n => { n.x = Math.max(65, Math.min(655, n.x)); n.y = Math.max(45, Math.min(360, n.y)); });
    }
    return { nodes, links };
  }, [evidence, detections, edges]);
  const byId = new Map(nodes.map(n => [n.id, n]));
  const focus = hover ? byId.get(hover) : null;
  const connected = new Set(links.filter(l => l.source === hover || l.target === hover).flatMap(l => [l.source, l.target]));
  const open = (node: Node) => { if (node.type === 'detection') setNodeDetail(node); else onEvidence(node.id); };
  return <section className="panel graph-panel"><div className="panel-heading"><div><h2>Investigation graph</h2><p className="panel-note">Observed relationships · hover to isolate, select to inspect</p></div><span className="badge">{links.length} / {edges.length} LINKS</span></div>
    {links.length ? <><svg className="evidence-graph" viewBox="0 0 720 420" role="group" aria-label="Evidence relationship graph"><defs><marker id={marker} markerWidth="7" markerHeight="7" refX="15" refY="3.5" orient="auto"><path d="M0 0L7 3.5L0 7" fill="context-stroke"/></marker></defs>
      {links.map((edge, i) => { const a = byId.get(edge.source)!, b = byId.get(edge.target)!; return <g key={i} className="relation-link" role="button" tabIndex={0} aria-label={`Inspect relationship: ${edge.reason}`} style={{ opacity: hover && edge.source !== hover && edge.target !== hover ? .2 : 1 }} onClick={() => setSelected(edge)} onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setSelected(edge); } }}><line className="edge-hit" x1={a.x} y1={a.y} x2={b.x} y2={b.y}/><line className={`relation-edge ${b.type === 'detection' ? 'detection' : ''}`} x1={a.x} y1={a.y} x2={b.x} y2={b.y} markerEnd={`url(#${marker})`}/></g>; })}
      {nodes.map(node => <g key={node.id} transform={`translate(${node.x.toFixed(2)} ${node.y.toFixed(2)})`} style={{ opacity: hover && !connected.has(node.id) && hover !== node.id ? .2 : 1, '--node-x': `${node.x}px`, '--node-y': `${node.y}px` } as CSSProperties} className={`relation-node ${node.type}`} role="button" tabIndex={0} aria-label={`Inspect ${node.label}`} onMouseEnter={() => setHover(node.id)} onMouseLeave={() => setHover(null)} onFocus={() => setHover(node.id)} onBlur={() => setHover(null)} onClick={() => open(node)} onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); open(node); } }}><g className="node-shape">{node.type === 'detection' ? <polygon points="-20,0 -10,-17 10,-17 20,0 10,17 -10,17"/> : node.type === 'processes' ? <polygon points="0,-17 17,0 0,17 -17,0"/> : node.type === 'files' ? <rect x="-14" y="-14" width="28" height="28" rx="3"/> : <circle r="16"/>}</g><text y="34" textAnchor="middle">{node.label.length > 24 ? node.label.slice(0, 22) + '…' : node.label}</text><title>{node.label}</title></g>)}
    {focus?.type === 'detection' && <g className="graph-tooltip" transform={`translate(${Math.min(490,Math.max(10,focus.x-105))} ${Math.max(8,focus.y-105)})`} aria-hidden="true"><rect width="220" height="75" rx="6"/><text x="12" y="20">{focus.label.slice(0,29)}</text><text x="12" y="42">{focus.record.engine} · {focus.record.severity}</text><text x="12" y="61">{focus.record.evidence_ids?.length||0} supporting record(s)</text></g>}
    </svg><div className="graph-legend"><span>◇ Process</span><span>□ File</span><span>○ Evidence / network</span><span>⬡ Detection</span></div>
    <div className="graph-context" aria-live="polite">{focus ? <><strong>{focus.label}</strong><small>{focus.type === 'detection' ? `${focus.record.engine} · ${focus.record.severity} · ${focus.record.evidence_ids.length} evidence record(s)` : `${focus.type} · ${focus.record.endpoint_id}`}</small></> : <span>Only supported relationships are drawn. Up to 60 linked nodes are shown.</span>}</div>
    {selected && <div className="graph-inspector"><strong>{selected.reason}</strong><small>{selected.confidence} confidence · {selected.profile || selected.profile_id}</small><div>{(selected.evidence_ids || []).filter((id: string) => evidence.some(e => e.evidence_id === id)).map((id: string) => <button key={id} className="text-button" onClick={() => onEvidence(id)}>Inspect {id.slice(0, 8)} <ArrowRight size={13}/></button>)}</div></div>}
    </> : <div className="graph-empty"><GitBranch/><strong>No supported relationships in this run</strong><span>Collect related telemetry and run a correlation profile.</span></div>}
    {nodeDetail && <div className="drawer-backdrop" onClick={() => setNodeDetail(null)}><aside className="drawer" role="dialog" aria-modal="true" aria-label="Detection details" onClick={e => e.stopPropagation()}><button className="secondary" onClick={() => setNodeDetail(null)}>Close detection</button><h2>{nodeDetail.label}</h2><p>{nodeDetail.record.reason}</p>{(nodeDetail.record.evidence_ids || []).map((id: string) => <button key={id} className="text-button" onClick={() => { setNodeDetail(null); onEvidence(id); }}>Inspect evidence {id.slice(0, 8)}</button>)}<pre className="json">{JSON.stringify(nodeDetail.record, null, 2)}</pre></aside></div>}
  </section>;
}
