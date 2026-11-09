// Demo-only controls: who you are viewing as, and a way back to the start.
import { ArrowRight, Compass, RotateCcw } from 'lucide-react';
import { personas } from './personas';

// Sign-in in demo mode: pick a persona instead of entering credentials.
export function DemoPersonas({ busy, onPick }: { busy: boolean; onPick: (actor: string) => void }) {
  return <div className="demo-personas" data-testid="demo-personas">
    <p className="demo-badge">Demo data · fictional exchange</p>
    <p>Northwind Exchange is fictional. Choose who to sign in as; each person sees only what RATCHET allows them to see.</p>
    <ul>{personas.map(p => <li key={p.id}><button type="button" disabled={busy} onClick={() => onPick(p.id)}>
      <span><strong>{p.name}</strong><small>{p.role}</small><small>{p.summary}</small></span>
      <span className="demo-scope" data-scope={p.scope}>{p.scope === 'ORGANIZATION' ? 'Organization view' : 'Own view'}</span><ArrowRight size={16}/></button></li>)}</ul>
  </div>;
}

// Top-bar strip: the demo label, the persona switcher, the tour and a reset.
export function DemoBar({ actor, busy, onSwitch, onTour, onReset }: { actor: string; busy: boolean; onSwitch: (actor: string) => void; onTour?: () => void; onReset: () => void }) {
  return <div className="demo-bar" data-testid="demo-bar">
    <span className="demo-badge" title="All records on this site are fictional and live only in this browser tab.">Demo data · fictional exchange</span>
    <label><span>View as</span><select aria-label="View the demo as" value={actor} disabled={busy} onChange={e => onSwitch(e.target.value)}>
      {personas.map(p => <option key={p.id} value={p.id}>{p.name} · {p.role.split(' · ')[0]}</option>)}</select></label>
    {onTour && <button type="button" disabled={busy} onClick={onTour}><Compass size={14}/> Guided tour</button>}
    <button type="button" disabled={busy} onClick={onReset} title="Restore the demo to its starting state"><RotateCcw size={14}/> Reset</button>
  </div>;
}
