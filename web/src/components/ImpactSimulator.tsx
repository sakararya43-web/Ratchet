import React, { useState } from 'react';
import { OrgState, computeSimulationDiff, ImpactDiff } from '../lib/api';
import { Sparkles, AlertTriangle, ArrowRight, ShieldAlert, CheckCircle, Flame, Layers } from 'lucide-react';

interface Props {
  org: OrgState;
}

export const ImpactSimulator: React.FC<Props> = ({ org }) => {
  const [selectedIdentityId, setSelectedIdentityId] = useState<string>('user:rahul');
  const [proposedRoleId, setProposedRoleId] = useState<string>('role:exchange-admin');
  const [activeDiff, setActiveDiff] = useState<ImpactDiff | null>(null);

  const handleSimulate = () => {
    const diff = computeSimulationDiff(org, selectedIdentityId, proposedRoleId);
    setActiveDiff(diff);
  };

  return (
    <div className="space-y-6">
      {/* Simulation Configuration Bar */}
      <div className="bg-[#111726] border border-[#1f293d] rounded-xl p-5 shadow-lg">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <h2 className="text-lg font-semibold text-white flex items-center gap-2">
              <Sparkles className="w-5 h-5 text-amber-400" />
              Pre-Execution Impact Simulator
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Evaluate what privilege expansion and critical crown jewel routes a draft change would create.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <div>
              <label className="text-[11px] text-slate-400 block mb-1">Target Account:</label>
              <select
                value={selectedIdentityId}
                onChange={(e) => {
                  setSelectedIdentityId(e.target.value);
                  setActiveDiff(null);
                }}
                className="bg-[#090d16] border border-[#1f293d] text-xs text-slate-200 rounded-lg px-3 py-1.5 focus:outline-none focus:border-blue-500"
              >
                {org.identities.map((id) => (
                  <option key={id.id} value={id.id}>
                    {id.display_name} ({id.id})
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="text-[11px] text-slate-400 block mb-1">Proposed Role Assignment:</label>
              <select
                value={proposedRoleId}
                onChange={(e) => {
                  setProposedRoleId(e.target.value);
                  setActiveDiff(null);
                }}
                className="bg-[#090d16] border border-[#1f293d] text-xs text-slate-200 rounded-lg px-3 py-1.5 focus:outline-none focus:border-blue-500"
              >
                {org.roles.map((r) => (
                  <option key={r.id} value={r.id}>
                    {r.display_name} ({r.id})
                  </option>
                ))}
              </select>
            </div>

            <div className="self-end pt-1">
              <button
                onClick={handleSimulate}
                className="px-4 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-medium transition-colors shadow flex items-center gap-1.5"
              >
                <Sparkles className="w-3.5 h-3.5" />
                Simulate Impact
              </button>
            </div>
          </div>
        </div>

        {/* Isolation Notice Banner */}
        <div className="mt-4 p-2.5 rounded-lg bg-blue-500/10 border border-blue-500/20 text-xs text-blue-300 flex items-center justify-between">
          <span className="flex items-center gap-2">
            <CheckCircle className="w-4 h-4 text-blue-400 shrink-0" />
            Evaluation runs on an isolated in-memory overlay (Graph Revision {org.revision}). Shared target state remains unmodified.
          </span>
          <span className="text-[11px] font-mono text-blue-400/80">FR-I1 / FR-I2</span>
        </div>
      </div>

      {/* Results View */}
      {activeDiff ? (
        <div className="space-y-6">
          {/* Top Metric Cards: Blast Radius Changes */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="p-4 rounded-xl bg-[#111726] border border-red-500/30 space-y-1">
              <div className="flex items-center justify-between text-xs text-slate-400">
                <span>Tier-0 Crown Jewels</span>
                <Flame className="w-4 h-4 text-red-400" />
              </div>
              <div className="text-2xl font-bold text-red-400 font-mono">
                +{activeDiff.blast_radius_delta.tier0}
              </div>
              <p className="text-[11px] text-red-300/80">New direct/indirect critical assets</p>
            </div>

            <div className="p-4 rounded-xl bg-[#111726] border border-amber-500/30 space-y-1">
              <div className="flex items-center justify-between text-xs text-slate-400">
                <span>Tier-1 High Impact</span>
                <Layers className="w-4 h-4 text-amber-400" />
              </div>
              <div className="text-2xl font-bold text-amber-400 font-mono">
                +{activeDiff.blast_radius_delta.tier1}
              </div>
              <p className="text-[11px] text-amber-300/80">Infrastructure & service accounts</p>
            </div>

            <div className="p-4 rounded-xl bg-[#111726] border border-blue-500/30 space-y-1">
              <div className="flex items-center justify-between text-xs text-slate-400">
                <span>New Tier-0 Routes</span>
                <AlertTriangle className="w-4 h-4 text-blue-400" />
              </div>
              <div className="text-2xl font-bold text-blue-400 font-mono">
                {activeDiff.new_tier0_paths_count}
              </div>
              <p className="text-[11px] text-blue-300/80">Traversable escalation paths</p>
            </div>

            <div className="p-4 rounded-xl bg-[#111726] border border-purple-500/30 space-y-1">
              <div className="flex items-center justify-between text-xs text-slate-400">
                <span>Weakened Safeguards</span>
                <ShieldAlert className="w-4 h-4 text-purple-400" />
              </div>
              <div className="text-2xl font-bold text-purple-400 font-mono">
                {activeDiff.safeguards_weakened.length}
              </div>
              <p className="text-[11px] text-purple-300/80">Security control bypasses</p>
            </div>
          </div>

          {/* Side-by-Side: Before vs After Reach */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Left: Newly Exposed Critical Assets */}
            <div className="bg-[#111726] border border-[#1f293d] rounded-xl p-5 space-y-4">
              <h3 className="font-medium text-white flex items-center gap-2 text-sm">
                <Flame className="w-4 h-4 text-red-400" />
                Newly Exposed Resources ({activeDiff.new_resources.length})
              </h3>

              {activeDiff.new_resources.length === 0 ? (
                <p className="text-xs text-slate-500 italic">No new resources exposed.</p>
              ) : (
                <div className="space-y-3">
                  {activeDiff.new_resources.map((res) => (
                    <div
                      key={res.id}
                      className={`p-3 rounded-lg bg-[#090d16] border ${
                        res.tier === 0
                          ? 'border-red-500/60 bg-red-950/20'
                          : 'border-[#1f293d]'
                      } flex items-center justify-between`}
                    >
                      <div>
                        <div className="font-medium text-xs text-slate-200 flex items-center gap-1.5">
                          {res.tier === 0 && (
                            <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
                          )}
                          {res.display_name}
                        </div>
                        <div className="text-[11px] font-mono text-slate-400">{res.id}</div>
                      </div>

                      <span
                        className={`text-[10px] px-2 py-0.5 rounded font-mono font-bold ${
                          res.tier === 0
                            ? 'bg-red-500/30 text-red-400 border border-red-500/50'
                            : 'bg-slate-800 text-slate-300'
                        }`}
                      >
                        Tier {res.tier}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Right: Concrete Paths to Tier 0 Assets */}
            <div className="bg-[#111726] border border-[#1f293d] rounded-xl p-5 space-y-4">
              <h3 className="font-medium text-white flex items-center gap-2 text-sm">
                <ShieldAlert className="w-4 h-4 text-amber-400" />
                Detected Paths to Crown Jewels (Tier 0)
              </h3>

              {activeDiff.sample_tier0_routes.length === 0 ? (
                <p className="text-xs text-slate-500 italic">No direct or indirect routes to Tier 0 detected.</p>
              ) : (
                <div className="space-y-3">
                  {activeDiff.sample_tier0_routes.map((route, idx) => (
                    <div
                      key={idx}
                      className="p-3 rounded-lg bg-[#090d16] border border-amber-500/30 space-y-2"
                    >
                      <div className="text-[11px] font-semibold text-amber-300">
                        Route #{idx + 1} to Critical Resource
                      </div>

                      <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
                        {route.node_ids.map((node, i) => (
                          <React.Fragment key={i}>
                            <span
                              className={`px-2 py-1 rounded ${
                                i === route.node_ids.length - 1
                                  ? 'bg-red-500/20 text-red-300 border border-red-500/40 font-bold'
                                  : 'bg-slate-800 text-slate-300 border border-slate-700'
                              }`}
                            >
                              {node}
                            </span>
                            {i < route.node_ids.length - 1 && (
                              <ArrowRight className="w-3.5 h-3.5 text-slate-500" />
                            )}
                          </React.Fragment>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {/* Weakened Safeguards */}
              {activeDiff.safeguards_weakened.length > 0 && (
                <div className="pt-3 border-t border-[#1f293d] space-y-2">
                  <h4 className="text-xs font-semibold text-purple-400">
                    Weakened Safeguards (Requires Authority Quorum)
                  </h4>
                  {activeDiff.safeguards_weakened.map((sg) => (
                    <div
                      key={sg.id}
                      className="p-2.5 rounded-lg bg-purple-950/20 border border-purple-500/30 text-xs space-y-1"
                    >
                      <div className="font-semibold text-purple-300">{sg.id} (Tier {sg.tier})</div>
                      <p className="text-[11px] text-slate-400">{sg.description}</p>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      ) : (
        <div className="p-12 text-center rounded-xl bg-[#111726] border border-[#1f293d] border-dashed space-y-3">
          <Sparkles className="w-10 h-10 text-slate-500 mx-auto" />
          <h3 className="text-sm font-medium text-slate-300">No active simulation overlay</h3>
          <p className="text-xs text-slate-500 max-w-md mx-auto">
            Select a target account and a proposed role above, then click &ldquo;Simulate Impact&rdquo; to compute the diff without altering target state.
          </p>
        </div>
      )}
    </div>
  );
};
