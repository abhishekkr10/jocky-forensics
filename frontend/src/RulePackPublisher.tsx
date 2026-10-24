import { useState } from 'react';
import { api } from './api';

export default function RulePackPublisher({onChange}:{onChange:()=>Promise<unknown>}){
 const [engine,setEngine]=useState('sigma'),[version,setVersion]=useState('1.0.0'),[source,setSource]=useState(''),[message,setMessage]=useState(''),[error,setError]=useState(''),[busy,setBusy]=useState(false);
 return <section className="panel"><div className="panel-heading"><div><h2>Publish an immutable rule pack</h2><p className="panel-note">Rules are validated before publication. The engine, version and source are pinned together by SHA-256. Sigma currently supports Windows process-creation telemetry.</p></div></div><form className="rule-publication" onSubmit={async event=>{event.preventDefault();setBusy(true);setError('');setMessage('');try{const published=await api('/rule-packs',{engine,version,source});setMessage(`Published ${published.id}`);await onChange()}catch(e){setError((e as Error).message)}finally{setBusy(false)}}}>
 <div className="filters"><label>Rule engine<select aria-label="Rule engine" value={engine} onChange={event=>setEngine(event.target.value)}><option value="sigma">Sigma</option><option value="yara">YARA-X</option></select></label><label>Pack version<input required maxLength={50} pattern="[A-Za-z0-9._-]+" value={version} onChange={event=>setVersion(event.target.value)}/></label></div>
 <label className="rule-source">Rule source<textarea aria-label="Rule source" required maxLength={65536} rows={12} value={source} onChange={event=>setSource(event.target.value)} style={{width:'100%',display:'block',background:'var(--bg-base)',color:'var(--text)',fontFamily:'var(--mono)',border:'1px solid var(--line)',padding:12}}/></label><div className="filters"><button className="primary" disabled={busy}>{busy?'Validating…':'Validate and publish'}</button></div>{message&&<p role="status" className="panel-note mono">{message}</p>}{error&&<p role="alert" className="alert error">{error}</p>}
 </form></section>;
}
