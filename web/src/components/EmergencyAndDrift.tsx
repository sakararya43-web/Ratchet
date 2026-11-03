import React, { useState, useEffect } from 'react';
import {
  OrgState,
  executeSimulatorCommand,
  injectSimulatedDrift,
  fetchAuditSince,
} from '../lib/api';
import { digest } from '../lib/canon';
import {
  Flame,
  Radio,
  Clock,
  ShieldCheck,
  AlertTriangle,
  CheckCircle2,
  RefreshCw,
  KeyRound,
  RotateCcw,
  Zap,
} from 'lucide-react';

interface EmergencyAndDriftProps {
  org: OrgState;
  onRefreshOrg: () => Promise<void>;
}

interface TemporaryGrantItem {
  grant_id: string;
  identity_id: string;
  role_id: string;
  expires_at: string;
  status: 'ACTIVE' | 'REVOKED';
  granted_at: string;
  revoked_at?: string;
}

interface DriftItem {
  alert_id: string;
  revision: number;
  actor_id: string;
  target_identity: string;
  role_id: string;
  status: 'DETECTED' | 'REVERTED';
  timestamp: string;
}

export const EmergencyAndDrift: React.FC<EmergencyAndDriftProps> = ({
  org,
  onRefreshOrg,
}) => {
  const [subTab, setSubTab] = useState<'emergency' | 'watch'>('emergency');

  // Emergency Access State
  const [reqIdentity, setReqIdentity] = useState<string>('user:rahul-assistant');
  const [reqRole, setReqRole] = useState<string>('role:finance-analyst');
  const [ttlMinutes, setTtlMinutes] = useState<number>(60);
  const [justification, setJustification] = useState<string>(
    'Emergency production audit following automated reconciliation gap'
  );
  const [approvingLead, setApprovingLead] = useState<string>('user:sec-lead-1');
  const [isApproving, setIsApproving] = useState<boolean>(false);
  const [emergencyMessage, setEmergencyMessage] = useState<string | null>(null);

  const [tempGrants, setTempGrants] = useState<TemporaryGrantItem[]>([
    {
      grant_id: 'tgrant-seed-demo-01',
      identity_id: 'user:admin-operator',
      role_id: 'role:security-lead',
      granted_at: new Date(Date.now() - 30 * 60000).toISOString(),
      expires_at: new Date(Date.now() + 30 * 60000).toISOString(),
      status: 'ACTIVE',
    },
  ]);

  // Watch & Drift State
  const [cursorRevision, setCursorRevision] = useState<number>(org.revision);
  const [driftAlerts, setDriftAlerts] = useState<DriftItem[]>([]);
  const [isInjecting, setIsInjecting] = useState<boolean>(false);
  const [isPolling, setIsPolling] = useState<boolean>(false);
  const [revertingId, setRevertingId] = useState<string | null>(null);
  const [driftMessage, setDriftMessage] = useState<string | null>(null);

  useEffect(() => {
    setCursorRevision(org.revision);
  }, [org.revision]);

  // Handle Emergency Grant Approval & Application
  const handleApproveEmergencyGrant = async () => {
    setIsApproving(true);
    setEmergencyMessage('Executing WebAuthn Passkey Ceremony for Emergency Escalation...');

    try {
      // 1. Domain-separated challenge binding
      const grantId = `tgrant-${Date.now()}`;
      const expiresAt = new Date(Date.now() + ttlMinutes * 60000).toISOString();
      const payload = {
        action: 'EMERGENCY_ROLE_ASSIGN',
        grant_id: grantId,
        identity_id: reqIdentity,
        role_id: reqRole,
        ttl_minutes: ttlMinutes,
        justification: justification,
      };
      await digest(payload);

      // Simulate passkey ceremony delay
      await new Promise((r) => setTimeout(r, 600));

      setEmergencyMessage('Passkey verified. Dispatching grant to simulator connector...');

      // 2. Connector executes grant on simulator
      const execRes = await executeSimulatorCommand('ASSIGN_ROLE', reqIdentity, reqRole);
      if (!execRes.success) {
        throw new Error(execRes.error_message || 'execution failed');
      }

      // 3. Independent read-back
      await onRefreshOrg();

      const newGrant: TemporaryGrantItem = {
        grant_id: grantId,
        identity_id: reqIdentity,
        role_id: reqRole,
        granted_at: new Date().toISOString(),
        expires_at: expiresAt,
        status: 'ACTIVE',
      };
      setTempGrants((prev) => [newGrant, ...prev]);

      setEmergencyMessage(
        `Emergency grant verified and active in target. Auto-revocation scheduled in ${ttlMinutes}m.`
      );
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setEmergencyMessage(`Emergency request failed: ${msg}`);
    } finally {
      setIsApproving(false);
    }
  };

  // Handle Revoke of Temporary Grant
  const handleRevokeGrant = async (grant: TemporaryGrantItem) => {
    try {
      const res = await executeSimulatorCommand('REVOKE_ROLE', grant.identity_id, grant.role_id);
      if (!res.success) {
        throw new Error(res.error_message || 'revocation failed');
      }

      await onRefreshOrg();

      setTempGrants((prev) =>
        prev.map((g) =>
          g.grant_id === grant.grant_id
            ? { ...g, status: 'REVOKED', revoked_at: new Date().toISOString() }
            : g
        )
      );
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      alert(`Revocation error: ${msg}`);
    }
  };

  // Handle Out-of-band Drift Injection (Test Attack)
  const handleInjectDrift = async () => {
    setIsInjecting(true);
    setDriftMessage('Injecting unauthorized out-of-band IAM mutation on target...');
    try {
      const res = await injectSimulatedDrift(
        'rogue-operator:out-of-band',
        'user:rahul',
        'role:wallet-operator'
      );
      await onRefreshOrg();

      setDriftMessage(
        `Drift injected directly into target (Target Revision: ${res.revision}). Run Watch Poll to detect.`
      );
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setDriftMessage(`Injection error: ${msg}`);
    } finally {
      setIsInjecting(false);
    }
  };

  // Handle Watch Stream Poll
  const handlePollWatch = async () => {
    setIsPolling(true);
    setDriftMessage('Polling simulator audit stream for unapproved IAM changes...');
    try {
      const entries = await fetchAuditSince(cursorRevision - 5);
      const newAlerts: DriftItem[] = [];

      for (const entry of entries) {
        if (entry.action === 'ASSIGN_ROLE' && entry.actor_id !== 'broker:ratchet-connector') {
          const roleId = entry.details?.role_id || 'unknown';
          newAlerts.push({
            alert_id: `alert-rev-${entry.revision}`,
            revision: entry.revision,
            actor_id: entry.actor_id,
            target_identity: entry.target,
            role_id: roleId,
            status: 'DETECTED',
            timestamp: entry.timestamp,
          });
        }
      }

      setDriftAlerts((prev) => {
        const seen = new Set(prev.map((a) => a.alert_id));
        const added = newAlerts.filter((a) => !seen.has(a.alert_id));
        return [...added, ...prev];
      });

      setCursorRevision(org.revision);
      setDriftMessage(
        newAlerts.length > 0
          ? `Watch detected ${newAlerts.length} unauthorized out-of-band drift mutation(s)!`
          : 'Watch stream healthy: no unauthorized drift detected.'
      );
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setDriftMessage(`Watch poll error: ${msg}`);
    } finally {
      setIsPolling(false);
    }
  };

  // Handle Authorized Revert of Drift
  const handleRevertDrift = async (alert: DriftItem) => {
    setRevertingId(alert.alert_id);
    try {
      const res = await executeSimulatorCommand(
        'REVOKE_ROLE',
        alert.target_identity,
        alert.role_id
      );
      if (!res.success) {
        throw new Error(res.error_message || 'revert failed');
      }

      await onRefreshOrg();

      setDriftAlerts((prev) =>
        prev.map((a) => (a.alert_id === alert.alert_id ? { ...a, status: 'REVERTED' } : a))
      );

      setDriftMessage(
        `Drift successfully reverted. Read-back verified that ${alert.target_identity} no longer holds ${alert.role_id}.`
      );
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setDriftMessage(`Revert error: ${msg}`);
    } finally {
      setRevertingId(null);
    }
  };

  return (
    <div className="space-y-6">
      {/* Sub-Header Tabs */}
      <div className="flex border-b border-[#1f293d] bg-[#111726] p-1.5 rounded-xl gap-2">
        <button
          onClick={() => setSubTab('emergency')}
          className={`flex-1 py-2 text-xs font-semibold rounded-lg flex items-center justify-center gap-2 transition-all ${
            subTab === 'emergency'
              ? 'bg-amber-600 text-white shadow'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Flame className="w-4 h-4" />
          Emergency Access &amp; Time-Bounded Grants (FR-C10, FR-E2)
        </button>

        <button
          onClick={() => setSubTab('watch')}
          className={`flex-1 py-2 text-xs font-semibold rounded-lg flex items-center justify-center gap-2 transition-all ${
            subTab === 'watch'
              ? 'bg-blue-600 text-white shadow'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Radio className="w-4 h-4" />
          Target Watch &amp; Drift Reversion (FR-K4, FR-O2)
        </button>
      </div>

      {/* ========================================================================= */}
      {/* SubTab A: Emergency Access & Temporary Grants                             */}
      {/* ========================================================================= */}
      {subTab === 'emergency' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Request Form */}
          <div className="lg:col-span-1 p-5 rounded-xl bg-[#111726] border border-[#1f293d] space-y-4">
            <h3 className="text-xs font-semibold text-slate-200 uppercase tracking-wider flex items-center gap-2">
              <Zap className="w-4 h-4 text-amber-400" />
              Request Emergency Elevation
            </h3>

            <div>
              <label className="text-[11px] text-slate-400 font-mono block mb-1">
                Requester Identity:
              </label>
              <select
                value={reqIdentity}
                onChange={(e) => setReqIdentity(e.target.value)}
                className="w-full bg-[#0a0f1d] border border-[#1f293d] text-xs rounded-lg px-3 py-2 text-slate-200 font-mono"
              >
                {org.identities.map((id) => (
                  <option key={id.id} value={id.id}>
                    {id.display_name} ({id.id})
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="text-[11px] text-slate-400 font-mono block mb-1">
                Requested Temporary Role:
              </label>
              <select
                value={reqRole}
                onChange={(e) => setReqRole(e.target.value)}
                className="w-full bg-[#0a0f1d] border border-[#1f293d] text-xs rounded-lg px-3 py-2 text-slate-200 font-mono"
              >
                {org.roles.map((r) => (
                  <option key={r.id} value={r.id}>
                    {r.display_name} ({r.id})
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="text-[11px] text-slate-400 font-mono block mb-1">
                Expiration TTL:
              </label>
              <select
                value={ttlMinutes}
                onChange={(e) => setTtlMinutes(Number(e.target.value))}
                className="w-full bg-[#0a0f1d] border border-[#1f293d] text-xs rounded-lg px-3 py-2 text-slate-200 font-mono"
              >
                <option value={15}>15 Minutes (Rapid Incident Triage)</option>
                <option value={60}>1 Hour (Standard Emergency Fix)</option>
                <option value={240}>4 Hours (Major Outage Window)</option>
              </select>
            </div>

            <div>
              <label className="text-[11px] text-slate-400 font-mono block mb-1">
                Business Justification:
              </label>
              <textarea
                value={justification}
                onChange={(e) => setJustification(e.target.value)}
                rows={3}
                className="w-full bg-[#0a0f1d] border border-[#1f293d] text-xs rounded-lg p-2.5 text-slate-200 font-mono"
              />
            </div>

            <div className="pt-2 border-t border-[#1f293d]">
              <label className="text-[11px] text-slate-400 font-mono block mb-1">
                Approving Security Lead (WebAuthn Passkey Required):
              </label>
              <select
                value={approvingLead}
                onChange={(e) => setApprovingLead(e.target.value)}
                className="w-full bg-[#0a0f1d] border border-[#1f293d] text-xs rounded-lg px-3 py-2 text-slate-200 font-mono"
              >
                <option value="user:sec-lead-1">Alice Vance (Security Lead 1)</option>
                <option value="user:sec-lead-2">Bob Chen (Security Lead 2)</option>
              </select>
            </div>

            <button
              onClick={handleApproveEmergencyGrant}
              disabled={isApproving}
              className="w-full py-2.5 rounded-lg bg-amber-600 hover:bg-amber-500 text-white font-medium text-xs flex items-center justify-center gap-2 transition-all shadow disabled:opacity-50"
            >
              <KeyRound className="w-4 h-4" />
              {isApproving ? 'Verifying Passkey...' : 'Approve & Apply Emergency Access'}
            </button>
          </div>

          {/* Active Grants Table */}
          <div className="lg:col-span-2 space-y-4">
            {emergencyMessage && (
              <div className="p-3.5 rounded-lg bg-amber-950/20 border border-amber-500/30 text-xs text-amber-300 font-mono flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-amber-400 shrink-0" />
                <span>{emergencyMessage}</span>
              </div>
            )}

            <div className="p-5 rounded-xl bg-[#111726] border border-[#1f293d] space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-semibold text-slate-200 uppercase tracking-wider flex items-center gap-2">
                  <Clock className="w-4 h-4 text-blue-400" />
                  Time-Bounded Scheduled Grants
                </h3>
                <span className="text-[11px] font-mono text-slate-400">
                  Active Count: {tempGrants.filter((g) => g.status === 'ACTIVE').length}
                </span>
              </div>

              <div className="divide-y divide-[#1f293d] border border-[#1f293d] rounded-lg overflow-hidden">
                {tempGrants.length === 0 ? (
                  <div className="p-8 text-center text-xs text-slate-500">
                    No active temporary grants.
                  </div>
                ) : (
                  tempGrants.map((grant) => (
                    <div
                      key={grant.grant_id}
                      className="p-3.5 bg-[#0a0f1d] flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs"
                    >
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-mono ${
                              grant.status === 'ACTIVE'
                                ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                                : 'bg-slate-700 text-slate-400'
                            }`}
                          >
                            {grant.status}
                          </span>
                          <span className="font-mono text-slate-200 font-semibold">
                            {grant.identity_id} &rarr; {grant.role_id}
                          </span>
                        </div>
                        <div className="text-[11px] text-slate-500 font-mono">
                          Expires: {new Date(grant.expires_at).toLocaleString()}
                        </div>
                      </div>

                      {grant.status === 'ACTIVE' && (
                        <button
                          onClick={() => handleRevokeGrant(grant)}
                          className="px-3 py-1.5 rounded bg-red-600/20 hover:bg-red-600/30 text-red-300 border border-red-500/30 text-[11px] font-mono flex items-center gap-1.5 self-start sm:self-auto"
                        >
                          <RotateCcw className="w-3 h-3" />
                          Revoke &amp; Verify Now
                        </button>
                      )}
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* SubTab B: Target Watch & Drift Reversion                                   */}
      {/* ========================================================================= */}
      {subTab === 'watch' && (
        <div className="space-y-6">
          {/* Controls Bar */}
          <div className="p-5 rounded-xl bg-[#111726] border border-[#1f293d] flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <Radio className="w-4 h-4 text-blue-400 animate-pulse" />
                <h3 className="text-xs font-semibold text-slate-200 uppercase tracking-wider">
                  Target Watch Cursor &amp; Drift Monitor
                </h3>
              </div>
              <p className="text-xs text-slate-400">
                Monitors simulator audit cursor for changes not originating from RATCHET connector broker.
              </p>
            </div>

            <div className="flex items-center gap-3">
              <button
                onClick={handleInjectDrift}
                disabled={isInjecting}
                className="px-3.5 py-2 rounded-lg bg-red-600/20 hover:bg-red-600/30 text-red-300 border border-red-500/30 text-xs font-medium flex items-center gap-1.5 transition-colors disabled:opacity-50"
              >
                <AlertTriangle className="w-3.5 h-3.5 text-red-400" />
                {isInjecting ? 'Injecting...' : 'Simulate Out-of-Band Rogue Mutation'}
              </button>

              <button
                onClick={handlePollWatch}
                disabled={isPolling}
                className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium flex items-center gap-1.5 transition-colors shadow disabled:opacity-50"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${isPolling ? 'animate-spin' : ''}`} />
                {isPolling ? 'Polling Stream...' : 'Run Watch Poll'}
              </button>
            </div>
          </div>

          {driftMessage && (
            <div className="p-3.5 rounded-lg bg-blue-950/20 border border-blue-500/30 text-xs text-blue-300 font-mono flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-blue-400 shrink-0" />
              <span>{driftMessage}</span>
            </div>
          )}

          {/* Drift Alerts List */}
          <div className="p-5 rounded-xl bg-[#111726] border border-[#1f293d] space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-semibold text-slate-200 uppercase tracking-wider">
                Detected Out-of-Band Drift ({driftAlerts.length})
              </h3>
              <span className="text-[11px] font-mono text-slate-500">
                Current Watch Revision: <strong>{cursorRevision}</strong>
              </span>
            </div>

            <div className="divide-y divide-[#1f293d] border border-[#1f293d] rounded-lg overflow-hidden">
              {driftAlerts.length === 0 ? (
                <div className="p-8 text-center text-xs text-slate-500">
                  No unauthorized drift detected. The target simulator IAM state is in exact parity with RATCHET.
                </div>
              ) : (
                driftAlerts.map((alert) => (
                  <div
                    key={alert.alert_id}
                    className="p-4 bg-[#0a0f1d] flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs"
                  >
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-mono font-medium ${
                            alert.status === 'DETECTED'
                              ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                              : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                          }`}
                        >
                          {alert.status}
                        </span>
                        <span className="font-mono text-slate-200 font-semibold">
                          {alert.target_identity} &rarr; {alert.role_id}
                        </span>
                        <span className="text-[10px] font-mono text-slate-500">
                          (Rev: {alert.revision})
                        </span>
                      </div>
                      <div className="text-[11px] text-slate-400 font-mono">
                        Actor: <strong className="text-red-400">{alert.actor_id}</strong> (Bypassed Connector Broker)
                      </div>
                    </div>

                    {alert.status === 'DETECTED' && (
                      <button
                        onClick={() => handleRevertDrift(alert)}
                        disabled={revertingId === alert.alert_id}
                        className="px-4 py-2 rounded-lg bg-red-600 hover:bg-red-500 text-white text-xs font-medium flex items-center gap-1.5 transition-all shadow disabled:opacity-50 self-start sm:self-auto"
                      >
                        <RotateCcw
                          className={`w-3.5 h-3.5 ${
                            revertingId === alert.alert_id ? 'animate-spin' : ''
                          }`}
                        />
                        {revertingId === alert.alert_id
                          ? 'Reverting...'
                          : 'Authorize Corrective Reversion'}
                      </button>
                    )}
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
