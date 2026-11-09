import { useEffect, useState, type FormEvent } from 'react';
import { Fingerprint, KeyRound, ShieldCheck } from 'lucide-react';
import { registerPasskey, revokePasskey } from '../lib/api';
import { passkeys, short, type Passkey } from './api';
import { useConsole } from './context';
import { Chips, Empty, Inspector, KeyValues, When } from './ui';

const views = ['Active', 'Revoked', 'All'] as const;
type View = typeof views[number];
const privileged = [
  ['Approve an access change', 'Binds your signature to the exact canonical change digest and your signed-in identity.'],
  ['Execute containment', 'Binds your signature to the exact containment plan digest.'],
  ['Sign Authority governance', 'Independent Authority members sign policy and registry artifacts; this is a separate, M-of-N process.'],
] as const;

export function PasskeysTab({ result, reload }: { result: unknown; reload: () => Promise<void> }) {
  const { busy, work, notify, actor } = useConsole();
  const [list, setList] = useState<Passkey[]>(Array.isArray(result) ? result as Passkey[] : []);
  const [view, setView] = useState<View>('Active');
  const [selected, setSelected] = useState<Passkey | null>(null);
  useEffect(() => { if (Array.isArray(result)) setList(result as Passkey[]); else void passkeys().then(setList).catch(() => undefined); }, [result]);
  const counts = { Active: list.filter(p => !p.revoked).length, Revoked: list.filter(p => p.revoked).length, All: list.length };
  const rows = list.filter(p => view === 'All' || (view === 'Active' ? !p.revoked : p.revoked)).sort((a, b) => (b.enrolled_at ?? '').localeCompare(a.enrolled_at ?? ''));
  const form = (action: (v: Record<string, string>) => Promise<void>) => (e: FormEvent<HTMLFormElement>) => { e.preventDefault(); const element = e.currentTarget; const v = Object.fromEntries(new FormData(element)) as Record<string, string>; void work(async () => { await action(v); element.reset(); }); };
  return <div className={selected ? 'workspace-split has-inspector' : 'workspace-split'}><div className="workspace-main">
    <section><div className="section-title"><h3>Registered passkeys</h3><span className="small-count">{counts.Active} active</span></div>
      <p>Passkeys bound to <strong>{actor}</strong>. Console sign-in uses your password session; every privileged action additionally requires one of these passkeys.</p>
      <Chips label="Credential status" options={views} value={view} onChange={setView} counts={counts}/>
      {rows.length ? <ul className="credential-list">{rows.map(p => <li key={p.credential_id}><button type="button" className={selected?.credential_id === p.credential_id ? 'is-selected' : ''} onClick={() => setSelected(p)}><KeyRound size={16}/><span><strong>{p.label || 'Unnamed passkey'}</strong><small><code>{short(p.credential_id, 16)}</code> · enrolled <When iso={p.enrolled_at}/></small></span><span className="eligibility" data-eligible={String(!p.revoked)}>{p.revoked ? 'Revoked' : 'Active'}</span></button></li>)}</ul>
        : <Empty title={list.length ? 'No credentials in this view.' : 'No passkeys registered.'}>{list.length ? 'Choose another status.' : 'Register a passkey with the one-use enrollment ticket your operator issued.'}</Empty>}
    </section>
    <section><h3>Register a passkey</h3><p>Use a one-use enrollment ticket issued by your operator. A signed-in session alone cannot change approval credentials.</p>
      <form onSubmit={form(async v => { await registerPasskey(v.Label, v.Ticket); await reload(); setList(await passkeys()); notify('Passkey registered for this signed-in account.'); })}><label>Label<input name="Label" required autoComplete="off"/></label><label>Enrollment ticket<input name="Ticket" type="password" autoComplete="off" required/></label><button disabled={busy}><Fingerprint size={14}/> Register with your authenticator</button></form>
      <h3>Revoke a credential</h3>
      <form onSubmit={form(async v => { await revokePasskey(v.Credential, v.RevocationTicket); await reload(); setList(await passkeys()); notify('Credential revoked.'); })}><label>Credential<input name="Credential" required autoComplete="off"/></label><label>Revocation ticket<input name="RevocationTicket" type="password" autoComplete="off" required/></label><button disabled={busy}>Revoke credential</button></form>
    </section>
    <section><h3>Operations that require a passkey</h3><ul className="plain-list privileged-list">{privileged.map(([title, detail]) => <li key={title}><ShieldCheck size={14}/><span><strong>{title}</strong><small>{detail}</small></span></li>)}</ul>
      <p className="muted">Console authentication (password session) only identifies you. The Independent Authority's signing process is separate: its members are enrolled through governance and sign policy artifacts under the current quorum.</p></section>
  </div>{selected && <Inspector eyebrow="PASSKEY" title={selected.label || 'Unnamed passkey'} onClose={() => setSelected(null)} testId="passkey-inspector">
    <KeyValues rows={[['Credential ID', <code>{selected.credential_id}</code>], ['Status', selected.revoked ? 'Revoked' : 'Active'], ['Enrolled', selected.enrolled_at ?? '—'], ['Last used', selected.last_used_at || 'Not recorded by the server'], ['Device / platform', 'Not disclosed: the server stores only the public key and credential ID']]}/>
    {!selected.revoked && <p className="muted">To revoke it, ask your operator for a one-use revocation ticket and use the form with this credential ID.</p>}</Inspector>}</div>;
}
