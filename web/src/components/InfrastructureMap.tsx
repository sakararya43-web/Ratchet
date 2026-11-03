import React, { useState } from 'react';
import { OrgState } from '../lib/api';
import { Shield, User, Database, Key, AlertTriangle } from 'lucide-react';

interface Props {
  org: OrgState;
}

export const InfrastructureMap: React.FC<Props> = ({ org }) => {
  const [selectedIdentityId, setSelectedIdentityId] = useState<string>(
    org.identities[0]?.id || 'user:rahul'
  );

  const selectedIdentity = org.identities.find((i) => i.id === selectedIdentityId);

  // Active grants for selected identity
  const userGrants = org.grants.filter((g) => g.identity_id === selectedIdentityId);
  const userRoles = org.roles.filter((r) => userGrants.some((g) => g.role_id === r.id));

  // Resources reachable by selected identity
  const reachableResources: Array<{
    resource: (typeof org.resources)[0];
    viaRole: string;
    action: string;
  }> = [];

  for (const role of userRoles) {
    for (const perm of role.permissions) {
      const lastColon = perm.lastIndexOf(':');
      const resId = lastColon !== -1 ? perm.substring(0, lastColon) : perm;
      const action = lastColon !== -1 ? perm.substring(lastColon + 1) : 'access';
      const res = org.resources.find((r) => r.id === resId);
      if (res && !reachableResources.some((item) => item.resource.id === res.id)) {
        reachableResources.push({ resource: res, viaRole: role.display_name, action });
      }
    }
  }

  // Controllable identities (ControlSet)
  const controlledIdentities = org.control_relations
    .filter((cr) => cr.controller_id === selectedIdentityId)
    .map((cr) => {
      const target = org.identities.find((i) => i.id === cr.controlled_id);
      return { relation: cr, identity: target };
    });

  // Active sessions
  const activeSessions = org.sessions.filter(
    (s) => s.identity_id === selectedIdentityId && !s.is_revoked
  );

  return (
    <div className="space-y-6">
      {/* Top Controls / Identity Selector */}
      <div className="bg-[#111726] border border-[#1f293d] rounded-xl p-5 shadow-lg">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h2 className="text-lg font-semibold text-white flex items-center gap-2">
              <Shield className="w-5 h-5 text-blue-400" />
              Infrastructure Authorization Map
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Focused neighborhood view of permissions, reachability, and takeover relationships.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <label className="text-xs font-medium text-slate-300">Select Identity:</label>
            <select
              value={selectedIdentityId}
              onChange={(e) => setSelectedIdentityId(e.target.value)}
              className="bg-[#090d16] border border-[#1f293d] text-sm text-slate-200 rounded-lg px-3 py-1.5 focus:outline-none focus:border-blue-500"
            >
              {org.identities.map((id) => (
                <option key={id.id} value={id.id}>
                  {id.display_name} ({id.id})
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* Grid: Identity Profile, Roles & Reach */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Principal Summary */}
        <div className="bg-[#111726] border border-[#1f293d] rounded-xl p-5 space-y-4">
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-blue-500/10 border border-blue-500/30 flex items-center justify-center text-blue-400">
                <User className="w-5 h-5" />
              </div>
              <div>
                <h3 className="font-medium text-white">{selectedIdentity?.display_name}</h3>
                <span className="text-xs text-slate-400">{selectedIdentity?.id}</span>
              </div>
            </div>

            {selectedIdentity?.is_disabled ? (
              <span className="px-2 py-0.5 text-xs font-semibold bg-red-500/20 text-red-400 border border-red-500/30 rounded">
                RESTRICTED
              </span>
            ) : (
              <span className="px-2 py-0.5 text-xs font-semibold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 rounded">
                ACTIVE
              </span>
            )}
          </div>

          <div className="text-xs space-y-1.5 pt-2 border-t border-[#1f293d] text-slate-300">
            <div className="flex justify-between py-1">
              <span className="text-slate-400">Department:</span>
              <span className="font-mono">{selectedIdentity?.department || 'N/A'}</span>
            </div>
            <div className="flex justify-between py-1">
              <span className="text-slate-400">Email:</span>
              <span className="font-mono">{selectedIdentity?.email || 'N/A'}</span>
            </div>
            <div className="flex justify-between py-1">
              <span className="text-slate-400">Active Sessions:</span>
              <span className="font-mono text-emerald-400">{activeSessions.length} active</span>
            </div>
          </div>

          {/* Control Set (Takeover identities) */}
          <div className="pt-3 border-t border-[#1f293d]">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2 flex items-center gap-1.5">
              <Key className="w-3.5 h-3.5 text-amber-400" />
              Control Set (Takeover Reach)
            </h4>
            {controlledIdentities.length === 0 ? (
              <p className="text-xs text-slate-500 italic">No subordinate accounts controlled.</p>
            ) : (
              <div className="space-y-2">
                {controlledIdentities.map(({ relation, identity }) => (
                  <div
                    key={relation.controlled_id}
                    className="p-2.5 rounded-lg bg-[#090d16] border border-amber-500/20 text-xs flex items-center justify-between"
                  >
                    <div>
                      <div className="font-medium text-amber-300">{identity?.display_name}</div>
                      <div className="text-slate-500 text-[11px] font-mono">{identity?.id}</div>
                    </div>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/30 font-mono">
                      {relation.kind}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Center Column: Direct Assigned Roles */}
        <div className="bg-[#111726] border border-[#1f293d] rounded-xl p-5 space-y-4">
          <h3 className="font-medium text-white flex items-center gap-2 text-sm">
            <Shield className="w-4 h-4 text-indigo-400" />
            Assigned Roles ({userRoles.length})
          </h3>

          {userRoles.length === 0 ? (
            <p className="text-xs text-slate-500 italic">No roles directly assigned.</p>
          ) : (
            <div className="space-y-3">
              {userRoles.map((role) => (
                <div
                  key={role.id}
                  className="p-3 rounded-lg bg-[#090d16] border border-[#1f293d] space-y-2"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-medium text-sm text-slate-200">{role.display_name}</span>
                    <span className="text-[10px] font-mono text-slate-400">{role.id}</span>
                  </div>
                  <p className="text-xs text-slate-400">{role.description}</p>
                  <div className="flex flex-wrap gap-1.5 pt-1">
                    {role.permissions.map((p) => (
                      <span
                        key={p}
                        className="px-2 py-0.5 rounded bg-blue-500/10 text-blue-300 border border-blue-500/20 font-mono text-[10px]"
                      >
                        {p}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Right Column: Computed Reachable Resources */}
        <div className="bg-[#111726] border border-[#1f293d] rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="font-medium text-white flex items-center gap-2 text-sm">
              <Database className="w-4 h-4 text-emerald-400" />
              Reachable Assets ({reachableResources.length})
            </h3>
            <span className="text-[11px] font-mono text-slate-400">Revision {org.revision}</span>
          </div>

          {reachableResources.length === 0 ? (
            <p className="text-xs text-slate-500 italic">No target resources reachable.</p>
          ) : (
            <div className="space-y-3">
              {reachableResources.map(({ resource, viaRole, action }) => {
                const isTier0 = resource.tier === 0;
                return (
                  <div
                    key={resource.id}
                    className={`p-3 rounded-lg bg-[#090d16] border ${
                      isTier0 ? 'border-red-500/50 bg-red-950/10' : 'border-[#1f293d]'
                    } space-y-1.5`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-medium text-xs text-slate-200 flex items-center gap-1.5">
                        {isTier0 && <AlertTriangle className="w-3.5 h-3.5 text-red-400" />}
                        {resource.display_name}
                      </span>
                      <span
                        className={`text-[10px] px-2 py-0.5 rounded font-mono font-bold ${
                          isTier0
                            ? 'bg-red-500/20 text-red-400 border border-red-500/40'
                            : resource.tier === 2
                            ? 'bg-amber-500/10 text-amber-300 border border-amber-500/30'
                            : 'bg-slate-700/50 text-slate-300'
                        }`}
                      >
                        Tier {resource.tier}
                      </span>
                    </div>

                    <p className="text-[11px] text-slate-400">{resource.description}</p>

                    <div className="text-[10px] text-slate-400 flex items-center gap-1 pt-1 font-mono">
                      <span>Action:</span>
                      <span className="text-blue-300 font-semibold">{action}</span>
                      <span className="text-slate-600">|</span>
                      <span>Via:</span>
                      <span className="text-slate-300">{viaRole}</span>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
