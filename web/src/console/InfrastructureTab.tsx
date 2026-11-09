import { useEffect, useMemo, useState } from 'react';
import { Crosshair, Eye, Route as RouteIcon, UserX } from 'lucide-react';
import { pathsToCritical, reach, type Route } from './api';
import { useConsole } from './context';
import { edgeLabel, GraphCanvas, type CanvasEdge, type CanvasNode } from './GraphCanvas';
import { RoutePath } from './impact';
import { Chips, EntityLink, TierBadge } from './ui';

const categories = ['All', 'Human identities', 'Service accounts', 'Groups', 'Roles', 'Permissions', 'Resources', 'Safeguards', 'Sessions'] as const;
type Category = typeof categories[number];
const categoryType: Record<Category, string | null> = { All: null, 'Human identities': 'Human', 'Service accounts': 'ServiceAccount', Groups: 'Group', Roles: 'Role', Permissions: 'Permission', Resources: 'Resource', Safeguards: 'Safeguard', Sessions: 'Session' };
const tiered = (type: string) => type === 'Resource' || type === 'Safeguard';
const legend = ['GRANTS', 'CAN_MODIFY', 'CAN_ASSUME', 'CAN_ADMINISTER', 'CAN_APPROVE', 'PROTECTED_BY', 'ASSIGNED', 'MEMBER_OF'];

export function InfrastructureTab() {
  const { bootstrap, tenantId, inspect, focus, organization } = useConsole();
  const [category, setCategory] = useState<Category>('All');
  const [search, setSearch] = useState('');
  const [selected, setSelected] = useState<string | undefined>(undefined);
  const [depth, setDepth] = useState(0);
  const [routes, setRoutes] = useState<Route[] | null>(null);
  const [mode, setMode] = useState<'none' | 'trace' | 'reach' | 'takeover'>('none');
  const [reachIds, setReachIds] = useState<Set<string>>(new Set());
  useEffect(() => { if (focus?.nodeId) { setSelected(focus.nodeId); setDepth(focus.trace ? 0 : 1); if (focus.trace) void trace(focus.nodeId); } }, [focus]); // eslint-disable-line react-hooks/exhaustive-deps
  const nodes = bootstrap?.nodes ?? [];
  const edges = bootstrap?.edges ?? [];
  const counts = useMemo(() => Object.fromEntries(categories.map(c => [c, categoryType[c] ? nodes.filter(n => n.type === categoryType[c]).length : nodes.length])) as Record<Category, number>, [nodes]);
  // A focused neighbourhood keeps the picture readable; depth 0 shows the whole visible graph.
  const neighbourhood = useMemo(() => {
    if (!selected || depth === 0) return new Set(nodes.map(n => n.id));
    const keep = new Set([selected]); let frontier = [selected];
    for (let d = 0; d < depth; d++) { const next: string[] = []; for (const e of edges) { if (frontier.includes(e.source) && !keep.has(e.target)) { keep.add(e.target); next.push(e.target); } if (frontier.includes(e.target) && !keep.has(e.source)) { keep.add(e.source); next.push(e.source); } } frontier = next; }
    return keep;
  }, [selected, depth, nodes, edges]);
  const canvasNodes: CanvasNode[] = nodes.filter(n => neighbourhood.has(n.id)).map(n => ({ id: n.id, type: n.type, label: n.display_name || n.id, tier: n.tier }));
  const canvasEdges: CanvasEdge[] = edges.filter(e => neighbourhood.has(e.source) && neighbourhood.has(e.target)).map(e => ({ source: e.source, target: e.target, kind: e.kind }));
  const highlight = useMemo(() => {
    const hotNodes = new Set<string>(); const hotEdges = new Set<string>();
    if (mode === 'trace') for (const r of routes ?? []) { const ids = r.nodeIds ?? []; ids.forEach(id => hotNodes.add(id)); ids.slice(1).forEach((id, i) => hotEdges.add(`${ids[i]}>${id}>${r.edgeKinds?.[i]}`)); }
    if (mode === 'reach') reachIds.forEach(id => hotNodes.add(id));
    if (mode === 'takeover') for (const e of canvasEdges) if (e.kind === 'CAN_ADMINISTER' || e.kind === 'CAN_ASSUME') { hotEdges.add(`${e.source}>${e.target}>${e.kind}`); hotNodes.add(e.target); }
    return { nodes: hotNodes, edges: hotEdges };
  }, [mode, routes, reachIds, canvasEdges]);
  async function trace(id: string) { setMode('trace'); setRoutes(null); try { setRoutes((await pathsToCritical(tenantId, id)).routes ?? []); } catch { setRoutes([]); } }
  async function showReach(id: string) { setMode('reach'); try { const r = await reach(tenantId, id); setReachIds(new Set((r.reachableNodes ?? []).map(n => n.id))); } catch { setReachIds(new Set()); } }
  const rows = nodes.filter(n => (!categoryType[category] || n.type === categoryType[category]) && `${n.id} ${n.display_name} ${n.type}`.toLowerCase().includes(search.toLowerCase()));
  const degree = (id: string) => edges.filter(e => e.source === id || e.target === id).length;
  const selectedNode = nodes.find(n => n.id === selected);
  return <>
    {!organization && <p className="inline-note">Your account sees only your own identity. The organization graph is visible to investigators authorized by core policy.</p>}
    {bootstrap && nodes.length > 0 && <section className="graph-section"><div className="section-title"><h3>Relationship graph</h3><span className="small-count">{canvasNodes.length} nodes · {canvasEdges.length} edges · graph {bootstrap.graph_version}</span></div>
      <div className="graph-toolbar">
        <label className="compact-select">Focus<select value={selected ?? ''} onChange={e => { setSelected(e.target.value || undefined); setMode('none'); if (e.target.value && depth === 0) setDepth(1); }}><option value="">Whole visible graph</option>{nodes.map(n => <option key={n.id} value={n.id}>{n.display_name || n.id}</option>)}</select></label>
        <label className="compact-select">Neighbourhood<select value={depth} onChange={e => setDepth(Number(e.target.value))} disabled={!selected}><option value={0}>Everything</option><option value={1}>1 step</option><option value={2}>2 steps</option><option value={3}>3 steps</option></select></label>
        <button type="button" disabled={!selected} onClick={() => selected && void trace(selected)}><RouteIcon size={13}/> Trace to tier 0</button>
        <button type="button" disabled={!selected} onClick={() => selected && void showReach(selected)}><Eye size={13}/> View reach</button>
        <button type="button" onClick={() => setMode(mode === 'takeover' ? 'none' : 'takeover')} aria-pressed={mode === 'takeover'}><UserX size={13}/> Takeover relationships</button>
        {selected && <button type="button" onClick={() => inspect(selected)}><Crosshair size={13}/> Inspect {selectedNode?.display_name || selected}</button>}
      </div>
      <GraphCanvas label="Observed access graph" nodes={canvasNodes} edges={canvasEdges} selected={selected} highlight={mode === 'none' ? undefined : highlight} onSelect={id => { setSelected(id); setMode('none'); }}/>
      <div className="graph-legend">{legend.map(kind => <span key={kind}><i data-kind={kind}/>{edgeLabel[kind]}</span>)}<span><i className="legend-critical"/>tier-0 resource or safeguard</span></div>
      {mode === 'trace' && <div className="trace-result"><h4>Routes to tier-0 assets from {selectedNode?.display_name || selected}</h4>{routes === null ? <p className="muted">Tracing…</p> : routes.length ? routes.map((r, i) => <RoutePath key={i} route={r}/>) : <p className="muted">No route from this entity reaches a tier-0 asset in the current graph.</p>}</div>}
      {mode === 'reach' && <p className="muted trace-result">{reachIds.size} reachable nodes highlighted.</p>}
    </section>}
    <section><div className="section-title"><h3>Entity explorer</h3><span className="small-count">{nodes.length} nodes</span></div>
      <Chips label="Entity category" options={categories} value={category} onChange={setCategory} counts={counts}/>
      <label className="request-filter">Find an observed node<input type="search" placeholder="Search name, type, or identity" value={search} onChange={e => setSearch(e.target.value)}/></label>
      <table><thead><tr><th>Name</th><th>Type</th><th>Tier</th><th>Identity</th><th>Relationships</th></tr></thead><tbody>{rows.map(n => <tr key={n.id} className={`is-clickable${tiered(n.type) && n.tier === 0 ? ' tier-zero' : ''}${n.id === selected ? ' is-selected' : ''}`} onClick={() => { setSelected(n.id); setMode('none'); if (depth === 0) setDepth(1); inspect(n.id); }}><td><EntityLink id={n.id} label={n.display_name || n.id}/></td><td>{n.type}</td><td>{!tiered(n.type) ? '—' : n.tier === 0 ? <strong className="tier-zero-label">Tier 0 · critical</strong> : <TierBadge tier={n.tier}/>}</td><td>{n.id}</td><td>{degree(n.id)}</td></tr>)}</tbody></table>
      {!rows.length && <p className="muted">No observed node matches this search and category.</p>}
      <details><summary>Observed relationships ({edges.length})</summary><ul className="plain-list">{edges.map(e => <li key={e.id}><EntityLink id={e.source}/> <span className="route-kind">{edgeLabel[e.kind] ?? e.kind}</span> <EntityLink id={e.target}/></li>)}</ul></details>
    </section>
  </>;
}
