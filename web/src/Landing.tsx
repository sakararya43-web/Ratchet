import { useEffect, useRef, useState } from 'react';
import { ArrowDown, ArrowRight, ArrowUpRight, Check, ChevronDown, Fingerprint, Menu, X } from 'lucide-react';
import { Brand, Mechanism } from './Brand';
import { LandingSections } from './LandingSections';

const chapters = ['Introduction', 'The protocol', 'The evidence', 'The access graph', 'The Binance case', 'Inside Ratchet', 'Enter Ratchet'];
const steps = [
  { title: 'See the consequence.', label: 'Assess', detail: 'A role is just a label. Ratchet follows the access graph to reveal the resources, identities, and critical paths a change would unlock.', code: '01 / GRAPH ASSESSMENT', status: 'Impact mapped', lines: ['Identity → requested role', 'Newly reachable resources', 'Critical access paths'] },
  { title: 'Make authority explicit.', label: 'Approve', detail: 'The right independent people review the exact change. Their passkeys bind approval to a verified envelope, with the required quorum enforced.', code: '02 / INDEPENDENT APPROVAL', status: 'Approval bound', lines: ['Exact change digest', 'Independent reviewers', 'Passkey-bound signatures'] },
  { title: 'Trust the outcome.', label: 'Verify', detail: 'A successful command is only the beginning. Independent target read-back confirms the change, and a hash-linked audit trail records what happened.', code: '03 / TARGET VERIFICATION', status: 'Outcome checked', lines: ['Target execution', 'Independent read-back', 'Hash-linked audit events'] },
];
const evidence = [
  ['The change you see is the change you sign.', 'The browser verifies the canonical approval envelope and impact digest before asking for a passkey. A changed request needs a fresh review.'],
  ['One person cannot become a quorum.', 'Requester self-approval and duplicate approvals are rejected. Policy determines the independent resource owners or security leads needed for a change.'],
  ['An execution claim needs evidence.', 'The core confirms execution with independent target read-back. Review the request, its decision evidence, and recorded audit events from the console.'],
];

export function Landing() {
  const [chapter, setChapter] = useState(0);
  const [stage, setStage] = useState(0);
  const [openEvidence, setOpenEvidence] = useState(0);
  const [menu, setMenu] = useState(false);
  const root = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const sections = root.current?.querySelectorAll<HTMLElement>('[data-chapter]');
    const observer = new IntersectionObserver(entries => {
      for (const entry of entries) if (entry.isIntersecting) setChapter(Number((entry.target as HTMLElement).dataset.chapter));
    }, { rootMargin: '-25% 0px -45% 0px', threshold: 0 });
    sections?.forEach(el => observer.observe(el));
    // No per-frame JS or inherited style updates. Native CSS scroll timelines
    // move the artwork/progress bar; this observer only updates chapter boundaries.
    return () => observer.disconnect();
  }, []);
  function go(index: number) { document.getElementById(`chapter-${index}`)?.scrollIntoView({ behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'instant' : 'smooth' }); setMenu(false); }
  return <div className="landing" ref={root}>
    <a className="skip-link" href="#landing-content" onClick={e => { e.preventDefault(); document.getElementById("landing-content")?.focus(); }}>Skip to content</a>
    <header className="landing-header"><a href="#chapter-0" aria-label="Ratchet home" onClick={e => { e.preventDefault(); go(0); }}><Brand /></a><nav aria-label="Main navigation" className={menu ? 'landing-nav is-open' : 'landing-nav'}><button onClick={() => go(1)}>The protocol</button><button onClick={() => go(2)}>Why Ratchet</button><button onClick={() => go(4)}>The Binance case</button><a className="nav-console" href="#/console?demo=1">Enter console <ArrowUpRight size={16}/></a></nav><button className="mobile-menu" aria-label={menu ? 'Close menu' : 'Open menu'} aria-expanded={menu} onClick={() => setMenu(!menu)}>{menu ? <X/> : <Menu/>}</button></header>
    <main id="landing-content" tabIndex={-1}>
      <section id="chapter-0" data-chapter="0" className="hero landing-section">
        <div className="section-kicker"><span className="hero-kicker-label"><span className="live-dot"/> CONSEQUENCE-DRIVEN ACCESS CONTROL</span> <span className="edition">ENGINEERED FOR ACCOUNTABILITY / V.01</span></div>
        <div className="hero-composition"><div className="hero-copy"><h1>Power needs<br/>a <span className="serif-word">boundary.</span></h1><p>Know what an access change makes possible.<br className="desktop-break"/> Decide who can approve it. Verify what happened.</p><a className="button-primary" href="#/console?demo=1">Enter the console <ArrowUpRight size={19}/></a><button className="text-link" onClick={() => go(1)}>Explore the protocol <ArrowDown size={15}/></button></div><div className="hero-instrument"><Mechanism stage={stage}/><div className="instrument-controls" aria-label="Explore protocol stages">{steps.map((step, i) => <button key={step.label} aria-pressed={stage === i} onClick={() => setStage(i)}><span>0{i + 1}</span>{step.label}</button>)}</div></div></div>
        <div className="hero-foot"><span>LESS ASSUMPTION.<br/>MORE CERTAINTY.</span><p>Access is a decision.<br/>Treat it like one.</p><button className="scroll-cue" onClick={() => go(1)} aria-label="Scroll to the protocol"><span className="scroll-wheel"><span/></span>SCROLL TO EXPLORE <ArrowDown size={14}/></button></div>
      </section>
      <section id="chapter-1" data-chapter="1" className="protocol landing-section">
        <div className="section-kicker"><span>01 — THE PROTOCOL</span><span>THREE STEPS. ONE ACCOUNTABLE CHANGE.</span></div>
        <div className="protocol-heading"><h2>From permission<br/>to <span className="serif-word">proof.</span></h2><p>Every access change has a consequence.<br/>Make it visible before it becomes real.</p></div>
        <div className="protocol-layout"><div className="protocol-steps">{steps.map((step, i) => <button className={`protocol-step ${stage === i ? 'is-active' : ''}`} key={step.label} onClick={() => setStage(i)} aria-expanded={stage === i} aria-controls="protocol-display"><span className="step-number">0{i+1}</span><span><span className="step-title">{step.title}</span><span className="step-detail">{step.detail}</span></span><ArrowUpRight size={22}/></button>)}</div><div id="protocol-display" className="protocol-display" aria-live="polite"><div className="display-top"><span>{steps[stage].code}</span><span className="display-signal"/></div><div className="signal-diagram"><div className="signal-source">REQUEST<br/><span>identity + role</span></div><div className="signal-line"/><div className="signal-core"><Fingerprint size={54} strokeWidth={1}/></div><div className="signal-line"/><div className="signal-target">{stage === 0 ? 'IMPACT' : stage === 1 ? 'QUORUM' : 'EVIDENCE'}<br/><span>{stage === 0 ? 'access graph' : stage === 1 ? 'independent' : 'target state'}</span></div></div><div className="display-lines">{steps[stage].lines.map((line, i) => <div key={line}><span>0{i+1} / {line}</span><Check size={15}/></div>)}</div><div className="display-bottom"><span><span className="live-dot"/>{steps[stage].status}</span><span>ILLUSTRATIVE FLOW</span></div></div></div>
        <div className="protocol-bottom"><span>DESIGNED TO MAKE TRUST INSPECTABLE.</span><button onClick={() => go(2)}>The details matter <ArrowDown size={16}/></button></div>
      </section>
      <section id="chapter-2" data-chapter="2" className="evidence landing-section"><div className="section-kicker"><span>02 — BUILT INTO THE PROCESS</span><span>VERIFY. DON’T ASSUME.</span></div><div className="evidence-layout"><div><h2>Good intentions.<br/><span className="serif-word">Hard boundaries.</span></h2><p>Approval is more than a button.<br/>The rules hold at every step.</p><div className="evidence-stamp"><Fingerprint size={38} strokeWidth={1}/><span>BOUND TO THE CHANGE.<br/>SIGNED BY THE PERSON.</span></div></div><div className="evidence-list">{evidence.map(([title, body], i) => <article key={title}><h3><button aria-expanded={openEvidence === i} aria-controls={`evidence-${i}`} onClick={() => setOpenEvidence(openEvidence === i ? -1 : i)}><span className="evidence-number">0{i+1}</span><span>{title}</span><ChevronDown size={20} className={openEvidence === i ? 'rotated' : ''}/></button></h3><div id={`evidence-${i}`} hidden={openEvidence !== i}><p>{body}</p></div></article>)}</div></div></section>
      <LandingSections/>
      <section id="chapter-6" data-chapter="6" className="entry landing-section"><div className="section-kicker"><span>03 — TAKE CONTROL</span><span>RATCHET / SECURITY CONTROL PLANE</span></div><a className="entry-link" href="#/console?demo=1"><span>Make the<br/><span className="serif-word">next move.</span></span><ArrowUpRight aria-hidden="true"/></a><div className="entry-bottom"><p>Explore the access-review prototype.<br/>Sign in with your operator-issued account.</p><a href="#/console?demo=1">Open the console <ArrowRight size={20}/></a></div></section>
    </main>
    <footer className="landing-footer"><a href="#chapter-0" onClick={e => { e.preventDefault(); go(0); }} aria-label="Back to top"><Brand/></a><p>Independent review. Verifiable change.</p><span>LOCAL PROTOTYPE / 2026</span></footer>
    <aside className="chapter-dock" aria-label="Page chapters"><span className="chapter-count">0{chapter+1}<span>/0{chapters.length}</span></span><div>{chapters.map((label, i) => <button key={label} onClick={() => go(i)} aria-label={label} aria-current={chapter === i ? 'location' : undefined}><span/></button>)}</div><span className="chapter-progress"/></aside>
  </div>;
}
