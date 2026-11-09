export function Brand({ compact = false }: { compact?: boolean }) {
  return <span className="brand"><svg viewBox="0 0 32 32" fill="none" aria-hidden="true"><path d="M5 5h16l6 6v8l-6 8H5V5Z" stroke="currentColor" strokeWidth="3"/><path d="M11 11h9v6h-9m4 0 6 10M11 11v16" stroke="currentColor" strokeWidth="3"/></svg>{!compact && <span>ratchet<span className="brand-dot">®</span></span>}</span>;
}

export function Mechanism({ stage = 0 }: { stage?: number }) {
  return <svg className="mechanism" viewBox="0 0 600 600" fill="none" role="img" aria-label={`Permission review mechanism, stage ${stage + 1} of 3`}>
    <defs><pattern id="microgrid" width="24" height="24" patternUnits="userSpaceOnUse"><circle cx="1" cy="1" r="1" fill="currentColor" opacity=".13"/></pattern></defs>
    <rect x="0" y="0" width="600" height="600" fill="url(#microgrid)"/>
    <g className="mechanism-guides" stroke="currentColor" opacity=".18"><path d="M300 0v600M0 300h600"/><circle cx="300" cy="300" r="248"/><circle cx="300" cy="300" r="150"/><path d="m90 90 420 420M90 510 510 90" strokeDasharray="3 7"/></g>
    <g className="mechanism-outer" style={{ transform: `rotate(${stage * 35}deg)` }}>
      {Array.from({ length: 60 }, (_, i) => <path key={i} d={i % 5 === 0 ? 'M300 61v20' : 'M300 61v8'} transform={`rotate(${i * 6} 300 300)`} stroke="currentColor" strokeWidth={i % 5 === 0 ? 2 : 1} opacity={i % 5 === 0 ? '.7' : '.25'} />)}
      <path d="M300 99a201 201 0 0 1 174 100" stroke="var(--accent)" strokeWidth="8"/>
      <path d="M474 401a201 201 0 0 1-348 0" stroke="currentColor" strokeWidth="2"/>
      <circle cx="126" cy="199" r="8" fill="var(--accent)"/>
    </g>
    <g className="mechanism-rotor" style={{ transform: `rotate(${stage * 120}deg)` }}>
      {[0, 120, 240].map(angle => <g key={angle} transform={`rotate(${angle} 300 300)`}><path d="M300 124 384 172 384 254 338 228 338 200 300 178 262 200 216 174Z" fill="currentColor"/><path d="m300 134 73 43" stroke="var(--surface)" opacity=".25"/></g>)}
    </g>
    <circle cx="300" cy="300" r="69" fill="var(--surface)" stroke="currentColor" strokeWidth="1"/>
    <path d="m274 300 18 18 35-38" stroke="var(--accent)" strokeWidth="7"/>
    <g fill="currentColor" className="diagram-type"><text x="28" y="35">FIG. 01 / AUTHORITY</text><text x="28" y="575">INDEPENDENT BY DESIGN</text><text x="512" y="575">0{stage + 1}/03</text></g>
    <g stroke="currentColor"><path d="M15 60V15h45M540 15h45v45M15 540v45h45M540 585h45v-45"/></g>
  </svg>;
}
