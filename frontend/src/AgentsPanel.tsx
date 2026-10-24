import { useEffect, useState } from 'react';
import { api } from './api';

type Agent={id:string;hostname:string;platform:string;last_seen:string|null;revoked:number};
export default function AgentsPanel({onChange}:{onChange:()=>Promise<unknown>}) {
  const [agents,setAgents]=useState<Agent[]>([]);
  const [hostname,setHostname]=useState('');
  const [platform,setPlatform]=useState('windows');
  const [root,setRoot]=useState('');
  const [credential,setCredential]=useState('');
  const [error,setError]=useState('');
  const [busy,setBusy]=useState(false);
  const refresh=async()=>setAgents(await api<Agent[]>('/agents'));
  useEffect(()=>{let active=true;api<Agent[]>('/agents').then(rows=>{if(active)setAgents(rows)}).catch(e=>{if(active)setError(e.message)});return()=>{active=false}},[]);
  return <section className="panel"><div className="panel-heading"><div><h2>Endpoint enrollment</h2><p className="panel-note">Explicit authorization, pinned coordinator key and an approved file collection directory are required.</p></div><button className="secondary" disabled={busy} onClick={async()=>{try{await refresh()}catch(e){setError((e as Error).message)}}}>Refresh heartbeats</button></div>
    <form className="filters" onSubmit={async event=>{event.preventDefault();setBusy(true);setError('');setCredential('');try{const enrolled=await api('/agents',{hostname,platform,approved_root:root});setCredential(enrolled.credential);await refresh();await onChange()}catch(e){setError((e as Error).message)}finally{setBusy(false)}}}>
      <label>Hostname<input required maxLength={255} value={hostname} onChange={event=>setHostname(event.target.value)}/></label>
      <label>Platform<select aria-label="Platform" value={platform} onChange={event=>setPlatform(event.target.value)}><option value="windows">Windows</option><option value="ubuntu">Ubuntu</option></select></label>
      <label>Absolute approved directory on endpoint<input required maxLength={1024} value={root} onChange={event=>setRoot(event.target.value)}/></label>
      <button className="primary" disabled={busy}>{busy?'Enrolling…':'Enroll endpoint'}</button>
    </form>
    {error&&<p role="alert" className="alert error">{error}</p>}
    {credential&&<div className="settings-strip"><div><strong>Save the machine credential securely—it is shown once.</strong><p><code>{credential}</code></p><p>Configure the polling client as described in deploy/agents.md. Never share this credential.</p></div><button className="secondary" onClick={()=>setCredential('')}>Dismiss credential</button></div>}
    {!agents.length?<p className="panel-note">No enrolled agents. Local and synthetic investigations remain available.</p>:<div style={{overflowX:'auto'}}><table><thead><tr><th>Endpoint</th><th>Platform</th><th>Last heartbeat</th><th>Authorization</th></tr></thead><tbody>{agents.map(agent=><tr key={agent.id}><td><strong>{agent.hostname}</strong><p className="mono">{agent.id}</p></td><td>{agent.platform}</td><td>{agent.last_seen?new Date(agent.last_seen).toLocaleString():'Never received'}</td><td>{agent.revoked?'Revoked':<button className="secondary" disabled={busy} onClick={async()=>{setBusy(true);setError('');try{await api(`/agents/${agent.id}/revoke`,{});await refresh()}catch(e){setError((e as Error).message)}finally{setBusy(false)}}}>Revoke access</button>}</td></tr>)}</tbody></table></div>}
  </section>;
}
