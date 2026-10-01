import { useEffect, useRef, useState } from 'react';
import { ArrowRight, Code2, Copy, Database, Fingerprint, GitBranch, ShieldCheck } from 'lucide-react';
import { EvidenceGraph, IntegrityChain } from './InvestigationVisuals';
import sample from './lab-preview.json';
import './landing.css';

const stages = [
  ['Script', 'Describe targets, bounded collection, rule packs and outputs.'],
  ['Compile', 'Validate capabilities and lower source to deterministic IR.'],
  ['Collect', 'Retain source spans, timestamps and explicit provenance.'],
  ['Detect', 'Evaluate supported Sigma predicates and YARA-X rules.'],
  ['Verify', 'Check stream chains and an Ed25519 completion checkpoint.'],
];
const requirements = [
  ['Custom programming language', 'Implemented', 'JOCKY DSL with Rust compiler and source diagnostics.'],
  ['Custom intermediate representation', 'Implemented', 'Deterministic plans, dependency checks and plan digests.'],
  ['Signature defeat', 'Excluded', 'No antivirus bypass or undetectability claim.'],
  ['Polymorphic artifacts', 'Excluded', 'No evasion-oriented binary mutation pipeline.'],
  ['In-memory injection', 'Excluded', 'Lab techniques produce labelled synthetic telemetry only.'],
  ['Direct syscall hook bypass', 'Excluded', 'Native collection uses conventional operating-system interfaces.'],
  ['Vulnerable driver inventory', 'Not implemented', 'Synthetic driver indicators are not live driver enumeration.'],
  ['Multi-endpoint management', 'Partial', 'Merged lab endpoint analysis; remote agent transport is not implemented.'],
  ['Evidence integrity', 'Implemented', 'SHA-256 per-stream chains and signed completion checkpoints.'],
  ['Sigma + YARA detection', 'Implemented', 'Supported Sigma predicate lowering and YARA-X file scanning.'],
  ['CDN / domain fronting', 'Excluded', 'Static website hosting does not provide agent transport.'],
];

function CopyCommand({ command }: { command: string }) {
  const [message, setMessage] = useState('');
  return <div className="copy-command"><code>{command}</code><button aria-label={`Copy ${command}`} onClick={async () => { try { await navigator.clipboard.writeText(command); setMessage('Copied'); } catch { setMessage('Select the command to copy'); } }}><Copy size={15}/></button><small role="status">{message}</small></div>;
}

export default function Showcase() {
  const root = useRef<HTMLDivElement>(null);
  const [tab, setTab] = useState('Editor');
  const [record, setRecord] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);
  const [checked, setChecked] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  useEffect(() => {
    const observer = new IntersectionObserver(entries => entries.forEach(entry => { if (entry.isIntersecting) { entry.target.classList.add('is-visible'); observer.unobserve(entry.target); } }), { rootMargin: '0px 0px -20% 0px', threshold: .1 });
    root.current?.querySelectorAll('.reveal').forEach(node => observer.observe(node));
    return () => { observer.disconnect(); clearTimeout(timer.current); };
  }, []);
  const selected = sample.evidence.find(e => e.evidence_id === record);
  const openEvidence = (id: string) => { setRecord(id); setTab('Evidence'); };
  return <div className="landing" ref={root}>
    <header className="landing-nav"><a className="brand" href="#" aria-label="JOCKY home"><span className="brand-mark"><Fingerprint/></span>JOCKY<span className="version">0.1</span></a><nav aria-label="Product navigation"><a href="#architecture">Architecture</a><a href="#demo">Lab demo</a><a href="#coverage">Coverage</a></nav><a className="secondary" href="#/app">Open console <ArrowRight size={15}/></a></header>
    <main className="landing-main">
      <section className="landing-hero"><div className="hero-copy reveal"><span className="hero-kicker">SIH26148 / NTRO PROBLEM STATEMENT</span><h1>Forensic analysis.<br/><em>Evidence you can trace.</em></h1><p>A purpose-built language for bounded system collection, rule evaluation and verifiable investigations on Windows and Linux.</p><div className="hero-actions"><a className="primary" href="#demo">Explore the lab demo <ArrowRight size={16}/></a><a className="secondary" href="#architecture">Read the architecture</a></div><div className="trust-strip"><span>Sigma evaluated</span><span>YARA-X scanning</span><span>Ed25519 signed</span></div><small>Research prototype · Platform coverage and implementation limits are listed below.</small></div>
        <div className="hero-editor reveal"><div className="editor-caption"><Code2 size={16}/><span>triage.jky</span><span className="badge amber">LAB</span></div><pre aria-label="JOCKY script example"><code>{sample.source.split('\n').filter(line => !line.startsWith('#')).slice(0, 12).map((line, i) => <span className="script-line" key={i} style={{ animationDelay: `${i * 70}ms` }}><span>{String(i + 1).padStart(2, '0')}</span>{line || ' '}{'\n'}</span>)}</code></pre><div className="example-check"><button className="secondary" disabled={checking} onClick={() => { setChecking(true); setChecked(false); timer.current = setTimeout(() => { setChecking(false); setChecked(true); }, 650); }}>{checking ? 'Showing example…' : 'Show compiled example'} <ArrowRight size={14}/></button><small role="status">{checked ? `${sample.operations.length} operation results in the reference lab run` : 'Illustration only · no code executes here'}</small></div></div>
      </section>
      <section id="architecture" className="landing-section reveal"><div className="section-title"><span>01 / ARCHITECTURE</span><h2>From script to verified evidence.</h2><p>Each stage preserves the context needed to inspect the next.</p></div><div className="architecture-pipeline">{stages.map(([name, detail], i) => <article key={name}><span className="stage-number">0{i + 1}</span><h3>{name}</h3><p>{detail}</p>{i < 4 && <ArrowRight size={17}/>}</article>)}</div><details className="language-notes"><summary>Language and execution contract</summary><p>Rust validates dataset dependencies and collector capabilities before producing versioned JSON IR. FastAPI coordinates bounded native workers, rule evaluation and SQLite persistence. Every evidence record retains its collecting operation and source location. The current runtime is local; remote agents are not connected.</p><pre><code>source → spanned AST → semantic checks → deterministic IR → bounded runtime</code></pre></details></section>
      <section className="landing-section reveal"><div className="section-title"><span>02 / ANALYST WORKFLOW</span><h2>Inspect the finding. Keep its context.</h2></div><div className="capability-grid">{[{icon:GitBranch,title:'Evidence relationships',text:'Inspect supported identities and rule-evaluation links. Every edge carries its reason and confidence.'},{icon:Fingerprint,title:'Verifiable records',text:'Read record digests and previous chain hashes. Verify integrity separately from collection completeness.'},{icon:Database,title:'Explicit provenance',text:'Synthetic lab records remain labelled. Live observations retain endpoint and collection timestamps.'},{icon:ShieldCheck,title:'Portable investigation',text:'Keep source, detections and evidence context together in HTML reports and JSON bundles.'}].map(({icon:Icon,title,text}) => <article key={title}><Icon size={22}/><h3>{title}</h3><p>{text}</p></article>)}</div></section>
      <section id="demo" className="landing-section reveal"><div className="section-title"><span>03 / REFERENCE INVESTIGATION</span><h2>Explore a complete lab run.</h2><p>A captured synthetic result: {sample.evidence.length} records, {sample.detections.length} detections. This demo does not collect data or run verification.</p></div><div className="demo-console"><div className="demo-caption"><span>JOCKY / INVESTIGATION CONSOLE</span><span className="badge amber">STATIC LAB SNAPSHOT</span></div><div className="demo-tabs" role="tablist" aria-label="Lab demo views">{['Editor','Workspace','Evidence','Integrity'].map(name => <button key={name} id={`tab-${name}`} role="tab" aria-controls={`view-${name}`} aria-selected={name === tab} onClick={() => setTab(name)}>{name}</button>)}</div><div className="demo-content" role="tabpanel" id={`view-${tab}`} aria-labelledby={`tab-${tab}`}>
        {tab === 'Editor' && <><pre className="demo-source"><code>{sample.source}</code></pre><p className="demo-footnote">The simulate statement creates telemetry records. It does not execute injection.</p></>}
        {tab === 'Workspace' && <EvidenceGraph evidence={sample.evidence} detections={sample.detections} edges={sample.analysis.edges} onEvidence={openEvidence}/>}
        {tab === 'Evidence' && <><div className="table-scroll"><table><thead><tr><th>Seq.</th><th>Artifact</th><th>Observation</th><th>Provenance</th></tr></thead><tbody>{sample.evidence.map(row => <tr key={row.evidence_id}><td>{String(row.sequence).padStart(3,'0')}</td><td>{row.artifact_type}</td><td><button className="text-button" onClick={() => setRecord(row.evidence_id)}>{row.payload.summary}</button></td><td><span className="badge amber">SYNTHETIC</span></td></tr>)}</tbody></table></div>{selected && <details open className="demo-record"><summary>Selected reference record</summary><pre className="json">{JSON.stringify(selected,null,2)}</pre></details>}</>}
        {tab === 'Integrity' && <><p className="demo-footnote">Snapshot of a previously verified synthetic run; no verification occurs in this preview.</p><IntegrityChain evidence={sample.evidence} verification={{integrity:'snapshot'}} onOpen={id => {if(id)openEvidence(id)}}/></>}
      </div></div><div className="demo-action"><span>Use the real console to compile, collect, inspect and verify.</span><a className="primary" href="#/app">Open investigation console <ArrowRight size={16}/></a></div></section>
      <section id="coverage" className="landing-section reveal"><div className="section-title"><span>04 / IMPLEMENTATION STATUS</span><h2>SIH26148 requirements coverage.</h2><p>Implemented capabilities and explicit limits. No claim of operating undetected.</p></div><div className="table-scroll requirements"><table><thead><tr><th>Requirement</th><th>Status</th><th>Implementation notes</th></tr></thead><tbody>{requirements.map(([name,status,note]) => <tr key={name}><td>{name}</td><td><span className={`badge ${status === 'Implemented' ? 'green' : status === 'Partial' ? 'amber' : 'muted'}`}>{status}</span></td><td>{note}</td></tr>)}</tbody></table></div></section>
      <section id="setup" className="landing-section setup-section reveal"><div className="section-title"><span>05 / LOCAL WORKSPACE</span><h2>Run the investigation console.</h2><p>The native worker and persistent evidence store run with the backend. The public website alone cannot investigate your computer.</p></div><div className="setup-commands"><p>From an existing checkout with dependencies installed and Rust on PATH:</p><CopyCommand command="cargo build --workspace"/><CopyCommand command="python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000"/><CopyCommand command="npm --prefix frontend run dev"/><p>First installation also requires the Python environment and frontend dependencies described in the repository README. Initial credentials are written to <code>data/first-login.txt</code>; they are removed after successful first use. Existing accounts keep their passwords.</p></div></section>
    </main><footer className="landing-footer"><span>JOCKY · SIH26148 research prototype</span><a href="#/app">Investigation console <ArrowRight size={14}/></a></footer>
  </div>;
}
