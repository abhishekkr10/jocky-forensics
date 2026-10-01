import React, { lazy, Suspense, useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { Fingerprint, LoaderCircle } from 'lucide-react';
import ErrorBoundary from './ErrorBoundary';
import './styles.css';
import './theme.css';
import './landing.css';

const App = lazy(() => import('./App'));
const Showcase = lazy(() => import('./Showcase'));

function ConsoleConnection() {
  const [state, setState] = useState<'checking' | 'ready' | 'offline'>('checking');
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 6000);
    let active = true;
    setState('checking');
    fetch('/api/v1/health', { signal: controller.signal, credentials: 'same-origin' })
      .then(async response => {
        if (!response.ok || !response.headers.get('content-type')?.includes('application/json')) throw new Error('Backend unavailable');
        const health = await response.json();
        if (health.status !== 'ok' || typeof health.version !== 'string') throw new Error('Backend unavailable');
        if (active) setState('ready');
      }).catch(() => { if (active) setState('offline'); }).finally(() => clearTimeout(timeout));
    return () => { active = false; clearTimeout(timeout); controller.abort(); };
  }, [attempt]);
  if (state === 'checking') return <div className="splash"><LoaderCircle className="spin"/> Connecting to investigation service…</div>;
  if (state === 'ready') return <App/>;
  return <div className="connection-page"><section><Fingerprint size={32}/><h1>Investigation service unavailable.</h1><p>The console needs a running JOCKY backend on this site's API address. This deployment currently has no reachable investigation service.</p><p>Your local workspace, cases and credentials are separate from this website. Start your local backend to use the full console.</p><div className="button-row"><button className="primary" onClick={() => setAttempt(x => x + 1)}>Retry connection</button><a className="secondary" href="http://127.0.0.1:8000/#/app">Open local console</a></div><a href="/#setup">Setup instructions</a><p><small>No credentials are requested while the backend is unavailable.</small></p></section></div>;
}

function Root() {
  const [route, setRoute] = useState(() => window.location.hash);
  useEffect(() => { const update = () => setRoute(window.location.hash); window.addEventListener('hashchange', update); return () => window.removeEventListener('hashchange', update); }, []);
  const consoleRoute = route === '#/app' || window.location.pathname.replace(/\/$/, '') === '/app';
  return <ErrorBoundary><Suspense fallback={<div className="splash">Opening JOCKY…</div>}>{consoleRoute ? <ConsoleConnection/> : <Showcase/>}</Suspense></ErrorBoundary>;
}

createRoot(document.getElementById('root')!).render(<React.StrictMode><Root/></React.StrictMode>);
