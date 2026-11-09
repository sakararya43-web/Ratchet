import { useMemo, useRef, useState, type PointerEvent, type WheelEvent } from 'react';
import { Maximize2, Minus, Plus } from 'lucide-react';

export type CanvasNode = { id: string; type: string; label: string; tier?: number };
export type CanvasEdge = { source: string; target: string; kind: string; action?: string };

// Columns follow how authority flows: who acts, what they hold, what it grants, what it reaches.
const columns: Record<string, number> = { Session: 0, Human: 1, ServiceAccount: 1, Group: 2, Role: 3, Permission: 4, Resource: 5, Safeguard: 6 };
export const edgeLabel: Record<string, string> = {
  GRANTS: 'has access to', ASSIGNED: 'assigned', MEMBER_OF: 'member of', CAN_ASSUME: 'can assume', CAN_ADMINISTER: 'can take over',
  CAN_MODIFY: 'can modify', CAN_APPROVE: 'can approve', PROTECTED_BY: 'protected by', HAS_SESSION: 'has session',
};
const short = (text: string) => (text.length > 26 ? `${text.slice(0, 24)}…` : text);

export function GraphCanvas({ nodes, edges, selected, highlight, onSelect, height, label }: {
  nodes: CanvasNode[]; edges: CanvasEdge[]; selected?: string; highlight?: { nodes: Set<string>; edges: Set<string> }; onSelect: (id: string) => void; height?: number; label: string;
}) {
  const layout = useMemo(() => {
    const byColumn = new Map<number, CanvasNode[]>();
    for (const node of nodes) { const c = columns[node.type] ?? 3; byColumn.set(c, [...(byColumn.get(c) ?? []), node]); }
    const used = [...byColumn.keys()].sort((a, b) => a - b);
    const positions = new Map<string, { x: number; y: number }>();
    const width = Math.max(1, used.length) * 210;
    const tallest = Math.max(1, ...[...byColumn.values()].map(list => list.length));
    used.forEach((column, index) => {
      const list = (byColumn.get(column) ?? []).sort((a, b) => (a.tier ?? 9) - (b.tier ?? 9) || a.label.localeCompare(b.label));
      list.forEach((node, row) => positions.set(node.id, { x: 105 + index * 210, y: 60 + (row + (tallest - list.length) / 2) * 74 }));
    });
    const natural = Math.max(220, tallest * 74 + 60);
    const drawWidth = Math.max(width + 70, 980); const offset = (drawWidth - width - 70) / 2;
    if (offset > 0) positions.forEach(p => { p.x += offset; });
    return { positions, width: drawWidth, height: natural };
  }, [nodes]);
  const [view, setView] = useState<{ x: number; y: number; scale: number }>({ x: 0, y: 0, scale: 1 });
  const drag = useRef<{ x: number; y: number; vx: number; vy: number } | null>(null);
  const wheel = (e: WheelEvent<SVGSVGElement>) => { e.preventDefault(); const factor = e.deltaY > 0 ? 0.9 : 1.1; setView(v => ({ ...v, scale: Math.min(2.5, Math.max(0.4, v.scale * factor)) })); };
  const down = (e: PointerEvent<SVGSVGElement>) => { if ((e.target as Element).closest('[data-node]')) return; drag.current = { x: e.clientX, y: e.clientY, vx: view.x, vy: view.y }; (e.currentTarget as Element).setPointerCapture(e.pointerId); };
  const move = (e: PointerEvent<SVGSVGElement>) => { const d = drag.current; if (d) setView(v => ({ ...v, x: d.vx + (e.clientX - d.x) / v.scale, y: d.vy + (e.clientY - d.y) / v.scale })); };
  const up = () => { drag.current = null; };
  const key = (e: CanvasEdge) => `${e.source}>${e.target}>${e.kind}`;
  if (!nodes.length) return null;
  return <div className="graph-canvas" style={{ height: height ?? Math.min(560, Math.max(240, layout.height + 40)) }}>
    <div className="graph-controls"><button type="button" aria-label="Zoom in" onClick={() => setView(v => ({ ...v, scale: Math.min(2.5, v.scale * 1.2) }))}><Plus size={14}/></button><button type="button" aria-label="Zoom out" onClick={() => setView(v => ({ ...v, scale: Math.max(0.4, v.scale / 1.2) }))}><Minus size={14}/></button><button type="button" aria-label="Reset view" onClick={() => setView({ x: 0, y: 0, scale: 1 })}><Maximize2 size={14}/></button></div>
    <svg role="img" aria-label={label} viewBox={`0 0 ${layout.width} ${layout.height}`} onWheel={wheel} onPointerDown={down} onPointerMove={move} onPointerUp={up} onPointerLeave={up}>
      <defs><marker id="graph-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0 0 10 5 0 10z" fill="#9aa587"/></marker><marker id="graph-arrow-hot" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0 0 10 5 0 10z" fill="#e35b35"/></marker></defs>
      <g transform={`scale(${view.scale}) translate(${view.x} ${view.y})`} style={{ transformOrigin: 'center' }}>
        {edges.map((edge, index) => { const a = layout.positions.get(edge.source), b = layout.positions.get(edge.target); if (!a || !b) return null; const hot = highlight?.edges.has(key(edge));
          // Forward edges run side to side; backward edges reverse; same-column edges arc to the right.
          const d = b.x > a.x ? `M${a.x + 60} ${a.y} C${(a.x + b.x) / 2} ${a.y} ${(a.x + b.x) / 2} ${b.y} ${b.x - 63} ${b.y}`
            : b.x < a.x ? `M${a.x - 60} ${a.y} C${(a.x + b.x) / 2} ${a.y} ${(a.x + b.x) / 2} ${b.y} ${b.x + 63} ${b.y}`
            : `M${a.x + 60} ${a.y} C${a.x + 105} ${a.y} ${b.x + 105} ${b.y} ${b.x + 63} ${b.y}`;
          return <g key={`${key(edge)}>${edge.action ?? ''}>${index}`} className={hot ? 'graph-edge is-hot' : 'graph-edge'}><path d={d} markerEnd={hot ? 'url(#graph-arrow-hot)' : 'url(#graph-arrow)'}/><title>{`${edge.source} ${edgeLabel[edge.kind] ?? edge.kind}${edge.action ? ` (${edge.action})` : ''} ${edge.target}`}</title></g>; })}
        {nodes.map(node => { const p = layout.positions.get(node.id); if (!p) return null; const hot = highlight?.nodes.has(node.id);
          return <g key={node.id} data-node={node.id} className={`graph-node${node.id === selected ? ' is-selected' : ''}${hot ? ' is-hot' : ''}${node.tier === 0 && (node.type === 'Resource' || node.type === 'Safeguard') ? ' is-critical' : ''}`} transform={`translate(${p.x - 60} ${p.y - 21})`} tabIndex={0} role="button" aria-label={`${node.type} ${node.label}`} onClick={() => onSelect(node.id)} onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onSelect(node.id); } }}>
            <rect width="120" height="42" rx="3"/><text x="9" y="16" className="graph-type">{node.type.toUpperCase()}{node.tier === 0 && (node.type === 'Resource' || node.type === 'Safeguard') ? ' · TIER 0' : ''}</text><text x="9" y="32" className="graph-label">{short(node.label)}</text><title>{`${node.label} (${node.id})`}</title>
          </g>; })}
      </g>
    </svg>
  </div>;
}
