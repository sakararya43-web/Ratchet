// Demo-only controls: who you are viewing as, and a way back to the start.
import { useState } from 'react';
import { ArrowLeft, ArrowRight, ChevronDown, ChevronUp, Compass, MousePointerClick, RotateCcw, X } from 'lucide-react';
import { personas } from './personas';
import { tour } from './tour';

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

// The guided tour card. It floats so the step stays visible while you scroll to act on it.
export function DemoTour({ step, busy, onStep, onClose }: { step: number; busy: boolean; onStep: (step: number) => void; onClose: () => void }) {
  const s = tour[step]; const last = step === tour.length - 1;
  const who = personas.find(p => p.id === s.persona);
  const [collapsed, setCollapsed] = useState(false);
  return <section className="demo-tour" data-collapsed={String(collapsed)} aria-label="Guided tour" data-testid="demo-tour">
    <div className="demo-tour-head"><span>GUIDED TOUR · {step + 1} / {tour.length}</span><span className="demo-tour-who">as {who?.name}</span><button type="button" aria-label={collapsed ? 'Expand tour' : 'Collapse tour'} aria-expanded={!collapsed} onClick={() => setCollapsed(c => !c)}>{collapsed ? <ChevronUp size={14}/> : <ChevronDown size={14}/>}</button><button type="button" aria-label="Close tour" onClick={onClose}><X size={14}/></button></div>
    <h3>{s.title}</h3>{!collapsed && <><p>{s.body}</p>
    {s.action && <p className="demo-tour-action"><MousePointerClick size={14}/><span>{s.action}</span></p>}</>}
    <div className="demo-tour-nav"><span className="demo-tour-dots" aria-hidden="true">{tour.map((_, i) => <i key={i} data-done={String(i <= step)}/>)}</span>
      <button type="button" disabled={busy || step === 0} onClick={() => onStep(step - 1)}><ArrowLeft size={14}/> Back</button>
      <button type="button" className="button-dark" disabled={busy} onClick={() => last ? onClose() : onStep(step + 1)}>{last ? 'Finish' : 'Next'} {!last && <ArrowRight size={14}/>}</button></div>
  </section>;
}
