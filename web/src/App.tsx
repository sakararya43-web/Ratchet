import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from 'react';
import { ArrowLeft, ArrowRight, ArrowUpRight, RefreshCw, LayoutDashboard, GitPullRequest, Network, ScanLine, ScrollText, Siren, ListChecks, Fingerprint, LogOut, ShieldCheck } from 'lucide-react';
import { ApiError, enterDemo, login, request, rpc, session, type Bootstrap, type Change, type Document, type Session } from './lib/api';
import { AuthorityPanel } from './AuthorityPanel';
import { Brand, Mechanism } from './Brand';
import { Landing } from './Landing';
import { AuditTab } from './console/AuditTab';
import { ChangesTab } from './console/ChangesTab';
import { ConsoleContext, tabs, type ConsoleContextValue, type Focus, type Tab } from './console/context';
import { EntityInspector } from './console/EntityInspector';
import { ImpactTab } from './console/ImpactTab';
import { IncidentsTab } from './console/IncidentsTab';
import { InfrastructureTab } from './console/InfrastructureTab';
import { OverviewTab } from './console/OverviewTab';
import { PasskeysTab } from './console/PasskeysTab';
import { PolicyTab } from './console/PolicyTab';
import './console/console.css';

const tabIcons = [LayoutDashboard, GitPullRequest, Network, ScanLine, ScrollText, Siren, ListChecks, Fingerprint];
const tabDescriptions: Record<Tab, string> = { Overview: 'Your point of control.', Changes: 'Every permission starts with a decision.', Infrastructure: 'The relationships behind the access.', Impact: 'Understand the consequence before the change.', 'Security policy': 'Authority, with a record.', Incidents: 'Plan the response. Preserve the evidence.', Audit: 'Follow the change, from intent to outcome.', Passkeys: 'Your signature. Bound to your identity.' };
function Fields({ names }: { names: string[] }) { return <>{names.map(name => <label key={name}>{name}<input name={name} required autoComplete="off" /></label>)}</>; }

// The server pages one ledger snapshot oldest-first behind a signed cursor. Follow it
// (up to 1,000 requests) and show newest first, so new requests are never on a later page.
async function allChanges(tenantId: string): Promise<Change[]> {
  const all: Change[] = []; let pageToken = '';
  for (let page = 0; page < 5; page++) {
    const r = await rpc<{ requests?: Change[]; nextPageToken?: string }>('ChangeService', 'ListChanges', { tenantId, pageSize: 200, pageToken });
    all.push(...(r.requests ?? [])); pageToken = r.nextPageToken ?? '';
    if (!pageToken) break;
  }
  return all.reverse();
}

export function App() {
  const [consoleRoute, setConsoleRoute] = useState(() => location.hash.startsWith('#/console'));
  useEffect(() => {
    const update = () => { const next = location.hash.startsWith('#/console'); setConsoleRoute(previous => { if (previous !== next) window.scrollTo(0, 0); return next; }); };
    window.addEventListener('hashchange', update);
    return () => window.removeEventListener('hashchange', update);
  }, []);
  return consoleRoute ? <Console /> : <Landing />;
}

function Console() {
  const [enteringDemo, setEnteringDemo] = useState(() => location.hash.includes('demo=1'));
  const [setup, setSetup] = useState<boolean|null>(null);
  const [governance, setGovernance] = useState(false);
  const [identity, setIdentity] = useState<Session | null>(null);
  const [bootstrap, setBootstrap] = useState<Bootstrap | null>(null);
  const [tab, setTab] = useState<Tab>('Overview');
  const [focus, setFocus] = useState<Focus>(null);
  const [inspecting, setInspecting] = useState<string | null>(null);
  const [result, setResult] = useState<unknown>(null);
  const [changes, setChanges] = useState<Change[]>([]);
  const [next, setNext] = useState('');
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);
  const [pollRetry, setPollRetry] = useState(0);
  const pollFailures = useRef(0);
  const [restricted, setRestricted] = useState(false);
  const tenantId = identity?.principal.tenant_id;
  const work = useCallback(async (action: () => Promise<void>) => { setBusy(true); setError(''); setNotice(''); try { await action(); } catch (e) { setError(e instanceof Error ? e.message : String(e)); } finally { setBusy(false); } }, []);
  useEffect(() => { void request<{mode:string;governance?:boolean}>('/api/setup').then(r=>{const active=r.mode==='AUTHORITY_GENESIS';setSetup(active);setGovernance(active||!!r.governance);if(active)setTab('Passkeys');}).catch(()=>setSetup(false));void (location.hash.includes('demo=1') ? enterDemo() : session()).then(setIdentity).catch(() => { if (location.hash.includes('demo=1')) setError('Automatic demo entry is unavailable. Sign in manually below.'); }).finally(() => setEnteringDemo(false)); }, []);
  // Only the most recent result request may render: a slower tab load must not
  // overwrite a newer, narrower query such as a request-specific audit search.
  const resultTicket = useRef(0);
  // The request an audit search is narrowed to. Every audit query reads it, whenever it is issued.
  const auditFilter = useRef('');
  const reloadChanges = useCallback(async () => { if (tenantId) setChanges(await allChanges(tenantId)); }, [tenantId]);
  async function load(pageToken = '') {
    const ticket = ++resultTicket.current;
    if (!tenantId) return;
    setResult(null); setNext(''); setRestricted(false);
    if (setup && tab!=='Passkeys') return;
    if (tab === 'Infrastructure' || tab === 'Impact') return;
    if (tab === 'Changes') { setChanges(await allChanges(tenantId)); return; }
    if (tab === 'Passkeys') { setResult(await request('/api/passkeys/list')); return; }
    const [service, method] = tab === 'Overview' ? ['OverviewService', 'GetAttentionItems'] : tab === 'Security policy' ? ['ChangeService', 'ListPolicyHistory'] : tab === 'Incidents' ? ['IncidentService', 'ListIncidents'] : ['AuditService', 'QueryAuditEvents'];
    try {
      const r = await rpc<Document>(service, method, { tenantId, ...(tab === 'Audit' && auditFilter.current ? { requestId: auditFilter.current } : {}), ...(tab === 'Overview' ? {} : { pageSize: tab === 'Incidents' ? 20 : 50, ...(tab === 'Security policy' ? { afterEventPosition: pageToken || '0' } : { pageToken }) }) });
      if (ticket !== resultTicket.current) return;
      setResult(r); setNext(String(r.nextPageToken ?? (r.hasMore ? r.nextEventPosition : '') ?? ''));
    } catch (e) {
      if (e instanceof ApiError && e.status === 403 && ['Security policy', 'Incidents', 'Audit'].includes(tab)) { setRestricted(true); return; }
      throw e;
    }
  }
  useEffect(() => { if (identity && setup!==null) void work(async () => { if(!setup)setBootstrap(await request<Bootstrap>('/api/console/bootstrap')); await load(); }); }, [identity, tab, setup]); // eslint-disable-line react-hooks/exhaustive-deps
  // Every workspace shares one view of the requests the signed-in identity may see.
  useEffect(() => { if (identity && setup === false && tab !== 'Changes') void allChanges(identity.principal.tenant_id).then(setChanges).catch(() => undefined); }, [identity, setup, tab]);
  useEffect(() => {
    if (!identity || (tab !== 'Changes' && tab !== 'Overview') || busy || next) return;
    let cancelled = false;
    // A failed refresh schedules another one: a single transient error must not stop
    // live status updates for the rest of the session. Persistent failures are shown.
    // Refresh quickly only while a visible change can still move; the list is costly to build.
    const inFlight = changes.some(c => ['SUBMITTED', 'ASSESSED', 'ALLOWED', 'AWAITING_APPROVAL', 'APPROVED', 'EXECUTING'].includes(c.status) || c.expiryStatus === 'SCHEDULED' || c.expiryStatus === 'REVOKING');
    const timer = setTimeout(() => { void allChanges(tenantId!).then(all => { if (cancelled) return; pollFailures.current = 0; setChanges(all); }).catch(e => { if (cancelled) return; pollFailures.current++; if (pollFailures.current >= 3) setError(String(e)); setPollRetry(n => n + 1); }); }, inFlight ? 2000 : 8000);
    return () => { cancelled = true; clearTimeout(timer); };
  }, [identity, tab, busy, changes, next, pollRetry]); // eslint-disable-line react-hooks/exhaustive-deps
  function form(e: FormEvent<HTMLFormElement>, action: (values: Record<string, string>) => Promise<void>) { e.preventDefault(); const element = e.currentTarget; const data = Object.fromEntries(new FormData(element)) as Record<string, string>; void work(async () => { await action(data); element.reset(); }); }
  function reset() { auditFilter.current = ''; setIdentity(null); setBootstrap(null); setChanges([]); setResult(null); setNext(''); setNotice(''); setRestricted(false); setFocus(null); setInspecting(null); setTab('Overview'); }
  const go = useCallback((target: Tab, nextFocus: Focus = null) => {
    auditFilter.current = target === 'Audit' && nextFocus?.requestId ? nextFocus.requestId : '';
    setInspecting(null); setFocus(nextFocus); setTab(target);
    if (target === tab && target === 'Audit') void work(async () => load());
  }, [tab]); // eslint-disable-line react-hooks/exhaustive-deps
  const context: ConsoleContextValue | null = useMemo(() => identity ? {
    tenantId: identity.principal.tenant_id, actor: identity.principal.actor_id, scope: bootstrap?.scope ?? 'SELF', organization: bootstrap?.scope === 'ORGANIZATION',
    bootstrap, changes, busy, focus, go, inspect: setInspecting, work, notify: setNotice, reloadChanges,
  } : null, [identity, bootstrap, changes, busy, focus, go, work, reloadChanges]);
  if (!identity && enteringDemo) return <main className="demo-opening"><Brand/><p role="status">Opening the requester demo…</p></main>;
  if (!identity || !context) return <div className="login-shell"><div className="login-art"><a href="#" aria-label="Ratchet home"><Brand/></a><div><p className="eyebrow">THE SECURITY CONTROL PLANE</p><h1>Access with<br/><span className="serif-word">intention.</span></h1><Mechanism/><p>Independent review.<br/>Verifiable change.</p></div><span className="login-edition">RATCHET / LOCAL PROTOTYPE</span></div><main className="login"><a href="#" className="back-link"><ArrowLeft size={16}/> Back to Ratchet</a><div className="login-form"><span className="login-icon"><Fingerprint size={28}/></span><p className="eyebrow">AUTHORIZED PERSONNEL</p><h2>Welcome to<br/>the control plane.</h2><p>Sign in with your operator-issued account.</p><form onSubmit={e => form(e, async v => { setIdentity(await login(v.Tenant, v.Actor, v.Password)); })}><Fields names={['Tenant', 'Actor']} /><label>Password<input name="Password" type="password" autoComplete="current-password" required /></label><button className="button-primary" disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}<ArrowRight size={18}/></button></form>{error && <p role="alert">{error}</p>}<p className="login-note"><ShieldCheck size={16}/> Approval actions require a separately enrolled passkey.</p></div><span className="login-edition">IDENTITY FIRST. AUTHORITY VERIFIED.</span></main></div>;
  const authority = !restricted && governance && tenantId ? <AuthorityPanel tenant={tenantId} actor={identity.principal.actor_id}/> : null;
  return <ConsoleContext.Provider value={context}><div className="console-shell"><a className="skip-link" href="#/console" onClick={e => { e.preventDefault(); document.getElementById("console-content")?.focus(); }}>Skip to content</a><aside className="console-sidebar"><a href="#" className="sidebar-brand" aria-label="Ratchet home"><Brand/></a><div className="workspace-label"><span className="live-dot"/> CONTROL PLANE <span>01</span></div><nav aria-label="Console">{tabs.filter(t=>!setup||t==='Passkeys'||t==='Security policy').map(t => { const Icon = tabIcons[tabs.indexOf(t)]; return <button disabled={busy} key={t} aria-current={t === tab ? 'page' : undefined} onClick={() => { auditFilter.current = ''; setFocus(null); setInspecting(null); setTab(t); }}><Icon size={18}/>{t}{t === tab && <span className="nav-active-dot"/>}</button>; })}</nav><div className="sidebar-foot"><div className="sidebar-note"><ShieldCheck size={21}/><p>Independent review.<br/>Verifiable change.</p></div><a href="#">Back to website <ArrowUpRight size={14}/></a></div></aside><div className="console-workspace"><header className="console-topbar"><div className="console-breadcrumb">Workspace <span>/</span> <strong>{tab}</strong></div><div className="account"><span className="avatar">{identity.principal.actor_id.replace('user:', '').slice(0,2).toUpperCase()}</span><span data-testid="signed-in-actor">{tenantId} / {identity.principal.actor_id}</span><button aria-label="Sign out" title="Sign out" disabled={busy} onClick={() => void work(async () => { await request('/api/auth/logout', {}); reset(); })}><LogOut size={17}/></button></div></header>
    <main className="console-main" id="console-content" tabIndex={-1}><div className="heading"><div><p className="eyebrow">WORKSPACE / {String(tabs.indexOf(tab)+1).padStart(2,'0')}</p><h2>{tab}</h2><p>{tabDescriptions[tab]}</p></div><button className="refresh-button" disabled={busy} onClick={() => void work(async () => { setBootstrap(await request<Bootstrap>('/api/console/bootstrap')); await load(); })}><RefreshCw size={15} className={busy ? 'is-spinning' : ''}/> Refresh</button></div>
      {location.hash.includes('demo=1') && identity.principal.actor_id === 'user:rahul-assistant' && <p className="demo-banner">DEMO WORKSPACE | Requester account | Independent reviewers approve sensitive changes.</p>}{error && <p role="alert">{error}</p>}{notice && <p role="status" className="notice">{notice}</p>}{busy && <p role="status">Processing your request. Complete the passkey prompt if one is open.</p>}
      {bootstrap && <p className="muted">Graph version {bootstrap.graph_version} | {bootstrap.scope === 'SELF' ? 'Your identity only; organization visibility requires investigator authorization.' : 'Organization visibility authorized by core policy.'}</p>}
      {restricted && <section className="access-restricted" data-testid="access-restricted" role="status"><ShieldCheck size={32} strokeWidth={1}/><p className="eyebrow">ACCOUNT PERMISSIONS</p><h3>Security lead access required</h3><p>{tab === 'Security policy' ? 'Security policy and governance history are available to security leads.' : tab === 'Audit' ? 'Organization audit records are available to authorized security leads.' : 'Incident records and containment planning are available to authorized security leads.'}</p><p>Your requester account can submit access changes and assess their impact. Use a security lead account to open this view.</p><div><button disabled={busy} onClick={() => go('Changes')}>Open access changes <ArrowRight size={15}/></button><button disabled={busy} onClick={() => void work(async () => { await request('/api/auth/logout', {}); reset(); location.hash = '#/console'; })}>Sign in with another account</button></div></section>}
      {setup&&<p role="status">Authority genesis enrollment. Register operator-authorized passkeys, enroll the configured leaders and sign the initial policy. Target execution becomes available only after the operator pins this genesis and starts the verified core.</p>}
      {setup && tab === 'Security policy' && authority}
      {!setup && tab === 'Overview' && <OverviewTab result={result}/>}
      {!setup && tab === 'Changes' && <ChangesTab/>}
      {!setup && tab === 'Infrastructure' && bootstrap && <InfrastructureTab/>}
      {!setup && tab === 'Impact' && <ImpactTab/>}
      {!setup && tab === 'Security policy' && !restricted && <PolicyTab result={result} authority={authority}/>}
      {!setup && tab === 'Incidents' && !restricted && <IncidentsTab result={result} refresh={() => load()}/>}
      {!setup && tab === 'Audit' && !restricted && <AuditTab result={result} filter={auditFilter.current} onSearch={async requestId => { auditFilter.current = requestId; await load(); }}/>}
      {tab === 'Passkeys' && <PasskeysTab result={result} reload={() => load()}/>}
      {next && (tab === 'Audit' || tab === 'Security policy') && <button disabled={busy} onClick={() => void work(() => load(next))}>Next page</button>}
    <footer className="console-footer"><span>RATCHET / SECURITY CONTROL PLANE</span><span>Every change has a consequence.</span></footer></main></div>
    {inspecting && <div className="inspector-float"><EntityInspector nodeId={inspecting} onClose={() => setInspecting(null)}/></div>}</div></ConsoleContext.Provider>;
}
