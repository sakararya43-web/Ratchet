import React from 'react';
import { OrgState } from '../lib/api';
import { Shield, AlertTriangle, Key, Layers, Activity, FileText } from 'lucide-react';

interface Props {
  org: OrgState;
  onNavigateToReview: () => void;
  onNavigateToMap: () => void;
  onNavigateToSimulator: () => void;
}

export const SecurityOverview: React.FC<Props> = ({
  org,
  onNavigateToReview,
  onNavigateToMap,
  onNavigateToSimulator,
}) => {
  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="bg-[#111726] border border-[#1f293d] rounded-xl p-5 shadow-lg flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-semibold text-white flex items-center gap-2">
            <Activity className="w-5 h-5 text-emerald-400" />
            Security Control Plane Overview
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Real-time attention queue, governance posture, and target synchronization health.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <span className="text-[11px] font-mono px-2.5 py-1 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
            Broker Mode Active
          </span>
          <span className="text-[11px] font-mono px-2.5 py-1 rounded bg-blue-500/10 text-blue-400 border border-blue-500/30">
            M-of-N Quorum: 2-of-3
          </span>
        </div>
      </div>

      {/* Attention Items Queue (PRD §5.8 / FR-O1) */}
      <div className="bg-[#111726] border border-[#1f293d] rounded-xl p-5 space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="font-medium text-white text-sm flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-amber-400" />
            Work Needing Attention
          </h3>
          <span className="text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20">
            Action Required
          </span>
        </div>

        <div className="space-y-3">
          {/* Item 1: Sensitive escalation pending */}
          <div className="p-4 rounded-lg bg-[#090d16] border border-red-500/40 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-red-500/20 text-red-400 border border-red-500/30 font-mono">
                  SENSITIVE ESCALATION
                </span>
                <span className="text-xs font-semibold text-white">
                  Rahul Sharma &rarr; Exchange Super Admin
                </span>
              </div>
              <p className="text-xs text-slate-400">
                New traversable path detected to cryptocurrency wallet signer (<code className="text-red-400">svc:wallet-signer</code>). Requires 2 independent Security Leads.
              </p>
            </div>

            <button
              onClick={onNavigateToReview}
              className="px-3 py-1.5 rounded bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium self-start sm:self-auto shrink-0 transition-colors shadow"
            >
              Review Change
            </button>
          </div>

          {/* Item 2: Ordinary Request */}
          <div className="p-4 rounded-lg bg-[#090d16] border border-[#1f293d] flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-blue-500/20 text-blue-400 border border-blue-500/30 font-mono">
                  ORDINARY ACCESS
                </span>
                <span className="text-xs font-semibold text-white">
                  Finance Analyst Access Request
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Read access requested for <code className="text-slate-300">res:finance-reports</code>. Awaiting Resource Owner approval (Priya Patel).
              </p>
            </div>

            <button
              onClick={onNavigateToReview}
              className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium self-start sm:self-auto shrink-0 transition-colors"
            >
              Inspect
            </button>
          </div>
        </div>
      </div>

      {/* Governance & Target Synchronization Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Card 1: Authority Status */}
        <div className="bg-[#111726] border border-[#1f293d] rounded-xl p-5 space-y-3">
          <div className="flex items-center justify-between">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
              <Key className="w-3.5 h-3.5 text-blue-400" />
              Independent Authority
            </h4>
            <span className="text-[10px] font-mono text-emerald-400 font-bold">GENESIS ACTIVE</span>
          </div>

          <div className="space-y-1.5 text-xs text-slate-300">
            <div className="flex justify-between">
              <span className="text-slate-400">Threshold:</span>
              <span className="font-mono font-bold text-slate-200">2-of-3 Leaders</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Active Policy:</span>
              <span className="font-mono text-blue-400">bundle v1.0.0</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Authority Epoch:</span>
              <span className="font-mono text-slate-200">Epoch 1</span>
            </div>
          </div>
        </div>

        {/* Card 2: Simulator Target Health */}
        <div className="bg-[#111726] border border-[#1f293d] rounded-xl p-5 space-y-3">
          <div className="flex items-center justify-between">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
              <Layers className="w-3.5 h-3.5 text-emerald-400" />
              Target Connector
            </h4>
            <span className="text-[10px] font-mono text-emerald-400 font-bold">SYNCHRONIZED</span>
          </div>

          <div className="space-y-1.5 text-xs text-slate-300">
            <div className="flex justify-between">
              <span className="text-slate-400">Target System:</span>
              <span className="font-mono text-slate-200">ratchet-sim</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Source Revision:</span>
              <span className="font-mono font-bold text-emerald-400">{org.revision}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Ingested Nodes:</span>
              <span className="font-mono text-slate-200">
                {org.identities.length + org.roles.length + org.resources.length}
              </span>
            </div>
          </div>
        </div>

        {/* Card 3: Quick Tools */}
        <div className="bg-[#111726] border border-[#1f293d] rounded-xl p-5 space-y-3">
          <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
            <Shield className="w-3.5 h-3.5 text-indigo-400" />
            Control Plane Tools
          </h4>

          <div className="space-y-2">
            <button
              onClick={onNavigateToSimulator}
              className="w-full text-left p-2 rounded bg-[#090d16] hover:bg-slate-800/60 border border-[#1f293d] text-xs text-slate-200 flex items-center justify-between transition-colors"
            >
              <span>Impact Simulator</span>
              <span className="text-[10px] text-blue-400">Open &rarr;</span>
            </button>

            <button
              onClick={onNavigateToMap}
              className="w-full text-left p-2 rounded bg-[#090d16] hover:bg-slate-800/60 border border-[#1f293d] text-xs text-slate-200 flex items-center justify-between transition-colors"
            >
              <span>Authorization Map</span>
              <span className="text-[10px] text-blue-400">Open &rarr;</span>
            </button>
          </div>
        </div>
      </div>

      {/* Target Audit Log Preview */}
      <div className="bg-[#111726] border border-[#1f293d] rounded-xl p-5 space-y-3">
        <h3 className="font-medium text-white text-sm flex items-center gap-2">
          <FileText className="w-4 h-4 text-slate-400" />
          Recent Target Audit Activity
        </h3>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="border-b border-[#1f293d] text-[10px] uppercase font-mono text-slate-400">
              <tr>
                <th className="py-2 px-3">Revision</th>
                <th className="py-2 px-3">Timestamp</th>
                <th className="py-2 px-3">Actor</th>
                <th className="py-2 px-3">Action</th>
                <th className="py-2 px-3">Target</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1f293d]/50 font-mono text-[11px]">
              {org.audit_log.slice(-5).map((entry, idx) => (
                <tr key={idx} className="hover:bg-[#090d16]/50">
                  <td className="py-2 px-3 text-emerald-400">{entry.revision}</td>
                  <td className="py-2 px-3 text-slate-400">{entry.timestamp.substring(0, 19)}</td>
                  <td className="py-2 px-3 text-slate-200">{entry.actor_id}</td>
                  <td className="py-2 px-3 text-blue-400 font-bold">{entry.action}</td>
                  <td className="py-2 px-3 text-slate-300">{entry.target}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
