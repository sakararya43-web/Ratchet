import { useMemo, useState, type ReactNode } from 'react';
import { ArrowDown, ArrowUp, ChevronLeft, ChevronRight, ShieldCheck, X } from 'lucide-react';
import { nodeName, useConsole } from './context';

export function StatusBadge({ status }: { status: string }) {
  return <strong className="status-badge" data-status={status}>{status}</strong>;
}
export function DecisionBadge({ decision }: { decision: string }) {
  return <span className="decision-badge" data-decision={decision}>{decision.replace('_', ' ')}</span>;
}
export function TierBadge({ tier }: { tier?: number }) {
  if (tier === undefined || tier === null) return <span className="tier-chip">—</span>;
  return <span className="tier-chip" data-tier={tier}>Tier {tier}</span>;
}

export function ago(iso?: string): string {
  if (!iso) return '—';
  const at = Date.parse(iso);
  if (Number.isNaN(at) || at < 0) return '—';
  const delta = Math.round((Date.now() - at) / 1000);
  // Expiry times lie in the future; say so instead of clamping them to "0s ago".
  const seconds = Math.abs(delta);
  const span = seconds < 60 ? `${seconds}s` : seconds < 3600 ? `${Math.floor(seconds / 60)}m` : seconds < 86400 ? `${Math.floor(seconds / 3600)}h` : `${Math.floor(seconds / 86400)}d`;
  return delta < -5 ? `in ${span}` : `${span} ago`;
}
export function When({ iso }: { iso?: string }) {
  return <time dateTime={iso} title={iso}>{ago(iso)}</time>;
}

// Opens the shared entity inspector for any identity, role or resource.
export function EntityLink({ id, label }: { id?: string; label?: string }) {
  const { inspect, bootstrap } = useConsole();
  if (!id) return <span>—</span>;
  return <button type="button" className="entity-link" onClick={e => { e.stopPropagation(); inspect(id); }} title={id}>{label ?? nodeName(bootstrap, id)}</button>;
}

export function Empty({ title, children, action }: { title: string; children?: ReactNode; action?: ReactNode }) {
  return <div className="empty-state"><ShieldCheck size={28} strokeWidth={1}/><h4>{title}</h4>{children && <p>{children}</p>}{action}</div>;
}

export function Chips<T extends string>({ options, value, onChange, counts, label }: { options: readonly T[]; value: T; onChange: (value: T) => void; counts?: Partial<Record<T, number>>; label: string }) {
  return <div className="chips" role="group" aria-label={label}>{options.map(option => <button type="button" key={option} aria-pressed={value === option} onClick={() => onChange(option)}>{option}{counts?.[option] !== undefined && <span>{counts[option]}</span>}</button>)}</div>;
}

export function KeyValues({ rows }: { rows: [string, ReactNode][] }) {
  return <dl className="key-values">{rows.map(([key, value]) => <div key={key}><dt>{key}</dt><dd>{value ?? '—'}</dd></div>)}</dl>;
}

// A side inspector that keeps the workspace visible beside it.
export function Inspector({ title, eyebrow, onClose, children, testId }: { title: ReactNode; eyebrow?: string; onClose: () => void; children: ReactNode; testId?: string }) {
  return <aside className="inspector" aria-label="Inspector" data-testid={testId}><div className="inspector-head"><div>{eyebrow && <p className="eyebrow">{eyebrow}</p>}<h3>{title}</h3></div><button type="button" aria-label="Close inspector" onClick={onClose}><X size={16}/></button></div><div className="inspector-body">{children}</div></aside>;
}

export function Tabs<T extends string>({ options, value, onChange }: { options: readonly T[]; value: T; onChange: (value: T) => void }) {
  return <div className="inspector-tabs" role="tablist">{options.map(option => <button type="button" role="tab" key={option} aria-selected={value === option} onClick={() => onChange(option)}>{option}</button>)}</div>;
}

export type Column<Row> = { key: string; label: string; render: (row: Row) => ReactNode; sort?: (row: Row) => string | number; width?: string };

// Sortable, paginated table. Rows are buttons-in-disguise: clicking opens a detail view.
export function DataTable<Row>({ columns, rows, rowKey, onRow, rowTestId, selected, pageSize = 50, initialSort, empty }: {
  columns: Column<Row>[]; rows: Row[]; rowKey: (row: Row) => string; onRow?: (row: Row) => void; rowTestId?: (row: Row) => string | undefined;
  selected?: string; pageSize?: number; initialSort?: { key: string; descending: boolean }; empty?: ReactNode;
}) {
  const [sort, setSort] = useState(initialSort ?? null);
  const [page, setPage] = useState(0);
  const sorted = useMemo(() => {
    const column = columns.find(c => c.key === sort?.key);
    if (!column?.sort || !sort) return rows;
    const by = column.sort;
    return [...rows].sort((a, b) => { const x = by(a), y = by(b); const order = x < y ? -1 : x > y ? 1 : 0; return sort.descending ? -order : order; });
  }, [rows, sort, columns]);
  const pages = Math.max(1, Math.ceil(sorted.length / pageSize));
  const current = Math.min(page, pages - 1);
  const visible = sorted.slice(current * pageSize, current * pageSize + pageSize);
  if (!rows.length) return <>{empty}</>;
  return <div className="data-table"><table><colgroup>{columns.map(c => <col key={c.key} style={c.width ? { width: c.width } : undefined}/>)}</colgroup>
    <thead><tr>{columns.map(c => <th key={c.key} aria-sort={sort?.key === c.key ? (sort.descending ? 'descending' : 'ascending') : undefined}>{c.sort ? <button type="button" className="sort-button" onClick={() => setSort(s => ({ key: c.key, descending: s?.key === c.key ? !s.descending : false }))}>{c.label}{sort?.key === c.key && (sort.descending ? <ArrowDown size={11}/> : <ArrowUp size={11}/>)}</button> : c.label}</th>)}</tr></thead>
    <tbody>{visible.map(row => { const key = rowKey(row); return <tr key={key} data-testid={rowTestId?.(row)} className={selected === key ? 'is-selected' : onRow ? 'is-clickable' : undefined} onClick={onRow ? () => onRow(row) : undefined}>{columns.map(c => <td key={c.key}>{c.render(row)}</td>)}</tr>; })}</tbody></table>
    {pages > 1 && <div className="table-pager"><span>{current * pageSize + 1}–{Math.min(sorted.length, (current + 1) * pageSize)} of {sorted.length}</span><button type="button" aria-label="Previous page" disabled={current === 0} onClick={() => setPage(current - 1)}><ChevronLeft size={14}/></button><button type="button" aria-label="Next page" disabled={current >= pages - 1} onClick={() => setPage(current + 1)}><ChevronRight size={14}/></button></div>}
  </div>;
}
