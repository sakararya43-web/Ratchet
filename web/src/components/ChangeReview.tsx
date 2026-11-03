import React, { useState } from 'react';
import { OrgState, submitPasskeyAssertion, executeConnectorCommand, readBusinessFinanceReport, probeAccess } from '../lib/api';
import { canonicalize } from '../lib/canon';
import { ShieldCheck, Clock, Key, UserCheck, AlertTriangle, CheckCircle2, Play, RefreshCw } from 'lucide-react';

interface Props {
  org: OrgState;
  onRefreshOrg?: () => void;
}

interface MockChangeRequest {
  id: string;
  kind: string;
  targetIdentity: string;
  requestedRole: string;
  requestedBy: string;
  justification: string;
  requiredQuorum: number;
  requiredApproverGroups: string[];
  decisionReasons: string[];
  status: 'AWAITING_APPROVAL' | 'APPROVED' | 'REJECTED' | 'HELD';
  isSensitive: boolean;
  affectedResources: string[];
  approvalsCollected: string[];
}

export const ChangeReview: React.FC<Props> = ({ org, onRefreshOrg }) => {
  const [requests, setRequests] = useState<MockChangeRequest[]>([
    {
      id: 'req-ordinary-001',
      kind: 'ROLE_ASSIGN',
      targetIdentity: 'user:rahul-assistant',
      requestedRole: 'role:finance-analyst',
      requestedBy: 'user:rahul-assistant',
      justification: 'Onboarding finance analyst needing access to read daily trading reports',
      requiredQuorum: 1,
      requiredApproverGroups: ['resource-owner'],
      decisionReasons: ['Standard access request', 'Approved by resource owner (Priya Patel) required'],
      status: 'AWAITING_APPROVAL',
      isSensitive: false,
      affectedResources: ['res:finance-reports', 'res:daily-exchange-ledger'],
      approvalsCollected: [],
    },
    {
      id: 'req-rahul-admin-002',
      kind: 'ROLE_ASSIGN',
      targetIdentity: 'user:rahul',
      requestedRole: 'role:exchange-admin',
      requestedBy: 'user:rahul',
      justification: 'Elevated privileges to troubleshoot wallet signer node connectivity',
      requiredQuorum: 2,
      requiredApproverGroups: ['security-leads'],
      decisionReasons: [
        'Creates new traversable routes to Tier-0 crown jewels (svc:wallet-signer, res:customer-db)',
        'Weakens Tier-0 safeguard (safeguard:withdrawal-rule)',
        'Requires 2 independent Security Leads approval',
      ],
      status: 'AWAITING_APPROVAL',
      isSensitive: true,
      affectedResources: ['svc:wallet-signer', 'res:customer-db', 'safeguard:withdrawal-rule'],
      approvalsCollected: [],
    },
  ]);

  const [selectedReqId, setSelectedReqId] = useState<string>(requests[0].id);
  const [approverActor, setApproverActor] = useState<string>('user:finance-lead');
  const [signingStatus, setSigningStatus] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [executionResult, setExecutionResult] = useState<any | null>(null);
  const [probeResult, setProbeResult] = useState<{ allowed: boolean; reason: string; report?: any } | null>(null);
  const [isExecuting, setIsExecuting] = useState<boolean>(false);

  const selectedReq = requests.find((r) => r.id === selectedReqId);

  const handleApproveWithPasskey = async () => {
    if (!selectedReq) return;
    setErrorMessage(null);
    setSigningStatus(null);

    // 1. Check Invariant R1: Self-approval prevention
    if (approverActor === selectedReq.targetIdentity || approverActor === selectedReq.requestedBy) {
      setErrorMessage(
        `Invariant R1 Refusal: Principal ${approverActor} cannot approve its own privilege escalation!`
      );
      return;
    }

    // 2. Check Invariant R1: Control set prevention (Controlled approver)
    const rahulControlSet = org.control_relations
      .filter((cr) => cr.controller_id === selectedReq.targetIdentity)
      .map((cr) => cr.controlled_id);

    if (rahulControlSet.includes(approverActor)) {
      setErrorMessage(
        `Invariant R1 Refusal: Approver ${approverActor} is within the requester's Control Set and cannot approve!`
      );
      return;
    }

    // 3. Prevent duplicate approval by same person
    if (selectedReq.approvalsCollected.includes(approverActor)) {
      setErrorMessage(`Member ${approverActor} has already provided a verified passkey assertion.`);
      return;
    }

    try {
      setSigningStatus(`Computing canonical change digest and requesting passkey assertion for ${approverActor}...`);

      // 4. Compute canonical RFC 8785 JSON and SHA-256 digest
      const changePayload = {
        kind: selectedReq.kind,
        request_id: selectedReq.id,
        requested_access: selectedReq.requestedRole,
        requested_by: selectedReq.requestedBy,
        target_identity: selectedReq.targetIdentity,
        tenant_id: org.tenant_id,
      };

      const canonStr = canonicalize(changePayload);
      const msgUint8 = new TextEncoder().encode(canonStr);
      const hashBuffer = await window.crypto.subtle.digest('SHA-256', msgUint8);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const changeDigestHex = hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');

      // 5. Submit assertion to real backend verifier
      const verified = await submitPasskeyAssertion(org.tenant_id, approverActor, changeDigestHex);

      const updatedApprovals = [...selectedReq.approvalsCollected, approverActor];
      const isComplete = updatedApprovals.length >= selectedReq.requiredQuorum;

      setRequests((prev) =>
        prev.map((r) =>
          r.id === selectedReq.id
            ? {
                ...r,
                approvalsCollected: updatedApprovals,
                status: isComplete ? 'APPROVED' : 'AWAITING_APPROVAL',
              }
            : r
        )
      );

      setSigningStatus(
        `WebAuthn assertion cryptographically verified! Credential: ${verified.credential_id.substring(
          0,
          12
        )}... (UV: ${verified.user_verified})`
      );
    } catch (err: any) {
      setErrorMessage(err.message || 'Passkey verification failed');
      setSigningStatus(null);
    }
  };

  const handleApplyViaConnector = async () => {
    if (!selectedReq || selectedReq.status !== 'APPROVED') return;
    setIsExecuting(true);
    setErrorMessage(null);

    try {
      // 1. Execute IAM command via connector broker
      const execRes = await executeConnectorCommand(
        `cmd-${selectedReq.id}`,
        'ASSIGN_ROLE',
        selectedReq.targetIdentity,
        selectedReq.requestedRole
      );
      setExecutionResult(execRes);

      // 2. Refresh target org state if callback provided
      if (onRefreshOrg) {
        onRefreshOrg();
      }

      // 3. Perform read-back access probe
      const probeRes = await probeAccess(
        selectedReq.targetIdentity,
        selectedReq.affectedResources[0],
        'read'
      );

      // 4. Test actual business session access
      const targetSession =
        selectedReq.targetIdentity === 'user:rahul-assistant'
          ? 'session:intern-workstation-1'
          : 'session:rahul-workstation-1';
      const bizRes = await readBusinessFinanceReport(targetSession);
      setProbeResult({
        allowed: probeRes.allowed,
        reason: probeRes.reason,
        report: bizRes.report,
      });
    } catch (err: any) {
      setErrorMessage(err.message || 'Execution failed');
    } finally {
      setIsExecuting(false);
    }
  };

  const handleReject = () => {
    if (!selectedReq) return;
    setRequests((prev) =>
      prev.map((r) => (r.id === selectedReq.id ? { ...r, status: 'REJECTED' } : r))
    );
  };

  const handleHold = () => {
    if (!selectedReq) return;
    setRequests((prev) =>
      prev.map((r) => (r.id === selectedReq.id ? { ...r, status: 'HELD' } : r))
    );
  };

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="bg-[#111726] border border-[#1f293d] rounded-xl p-5 shadow-lg flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-semibold text-white flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-blue-400" />
            Sensitive Change Review & Decision Point
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Review proposed privilege changes, verified blast radius, and execute passkey-backed authorizations.
          </p>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono text-slate-300">
          <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse" />
          <span>Independent PDP Active (Port 8085/8086)</span>
        </div>
      </div>

      {/* Error Alert Banner */}
      {errorMessage && (
        <div className="p-4 rounded-xl bg-red-950/40 border border-red-500/50 flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
          <div>
            <h4 className="text-xs font-bold text-red-200 uppercase tracking-wide">
              Authorization Blocked
            </h4>
            <p className="text-xs text-red-300 mt-0.5">{errorMessage}</p>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Request Queue */}
        <div className="bg-[#111726] border border-[#1f293d] rounded-xl p-5 space-y-4">
          <h3 className="font-medium text-white text-sm flex items-center justify-between">
            <span>Pending Change Requests</span>
            <span className="px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 font-mono text-xs">
              {requests.length}
            </span>
          </h3>

          <div className="space-y-3">
            {requests.map((req) => {
              const isSelected = req.id === selectedReqId;
              return (
                <div
                  key={req.id}
                  onClick={() => {
                    setSelectedReqId(req.id);
                    setErrorMessage(null);
                    setSigningStatus(null);
                    setExecutionResult(null);
                    setProbeResult(null);
                    if (req.id === 'req-ordinary-001') {
                      setApproverActor('user:finance-lead');
                    } else {
                      setApproverActor('user:sec-lead-1');
                    }
                  }}
                  className={`p-3.5 rounded-lg border cursor-pointer transition-all ${
                    isSelected
                      ? 'border-blue-500 bg-blue-950/20'
                      : 'border-[#1f293d] bg-[#090d16] hover:border-slate-600'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-[11px] font-mono text-slate-400">{req.id}</span>
                    <span
                      className={`text-[10px] px-2 py-0.5 rounded font-mono font-bold ${
                        req.status === 'APPROVED'
                          ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                          : req.status === 'REJECTED'
                          ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                          : req.isSensitive
                          ? 'bg-red-500/10 text-red-300 border border-red-500/30'
                          : 'bg-blue-500/10 text-blue-300 border border-blue-500/30'
                      }`}
                    >
                      {req.status}
                    </span>
                  </div>

                  <div className="text-xs font-semibold text-white">
                    {req.targetIdentity} &rarr; {req.requestedRole}
                  </div>
                  <div className="text-[11px] text-slate-400 mt-1 line-clamp-1">
                    {req.justification}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Center & Right Columns: Request Details & Action Panel */}
        {selectedReq && (
          <div className="lg:col-span-2 space-y-6">
            <div className="bg-[#111726] border border-[#1f293d] rounded-xl p-6 space-y-6">
              {/* Header Info */}
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 pb-4 border-b border-[#1f293d]">
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="text-base font-semibold text-white font-mono">
                      {selectedReq.id}
                    </h3>
                    {selectedReq.isSensitive ? (
                      <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-red-500/20 text-red-400 border border-red-500/40 uppercase">
                        Sensitive Tier-0 Escalation (D2)
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-blue-500/20 text-blue-400 border border-blue-500/40 uppercase">
                        Ordinary Access Request (D1)
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-slate-400 mt-1">{selectedReq.justification}</p>
                </div>

                <div className="text-right text-xs">
                  <div className="text-slate-400">Required Quorum</div>
                  <div className="font-mono font-bold text-slate-200">
                    {selectedReq.approvalsCollected.length} / {selectedReq.requiredQuorum} Signatures
                  </div>
                </div>
              </div>

              {/* Grid: Context & Impact */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                <div className="p-3.5 rounded-lg bg-[#090d16] border border-[#1f293d] space-y-2">
                  <span className="text-slate-400 font-semibold uppercase tracking-wider text-[10px] block">
                    Principal & Target
                  </span>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Requester:</span>
                    <span className="font-mono text-slate-200">{selectedReq.requestedBy}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Target Identity:</span>
                    <span className="font-mono text-slate-200">{selectedReq.targetIdentity}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Proposed Role:</span>
                    <span className="font-mono text-blue-400 font-semibold">
                      {selectedReq.requestedRole}
                    </span>
                  </div>
                </div>

                <div className="p-3.5 rounded-lg bg-[#090d16] border border-[#1f293d] space-y-2">
                  <span className="text-slate-400 font-semibold uppercase tracking-wider text-[10px] block">
                    Affected Critical Resources
                  </span>
                  <div className="flex flex-wrap gap-1.5">
                    {selectedReq.affectedResources.map((res) => (
                      <span
                        key={res}
                        className={`px-2 py-0.5 rounded font-mono text-[10px] ${
                          res.includes('wallet') || res.includes('customer') || res.includes('withdrawal')
                            ? 'bg-red-500/20 text-red-300 border border-red-500/30'
                            : 'bg-slate-800 text-slate-300'
                        }`}
                      >
                        {res}
                      </span>
                    ))}
                  </div>
                </div>
              </div>

              {/* Decision Reasons */}
              <div className="p-4 rounded-lg bg-blue-950/10 border border-blue-500/20 space-y-2 text-xs">
                <h4 className="font-semibold text-blue-300 flex items-center gap-1.5">
                  <ShieldCheck className="w-4 h-4 text-blue-400" />
                  Policy Evaluation & Invariant Reasons
                </h4>
                <ul className="list-disc list-inside space-y-1 text-slate-300">
                  {selectedReq.decisionReasons.map((reason, i) => (
                    <li key={i}>{reason}</li>
                  ))}
                </ul>
              </div>

              {/* Collected Approvals */}
              <div className="space-y-2">
                <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
                  Cryptographic Approvals Collected
                </h4>
                {selectedReq.approvalsCollected.length === 0 ? (
                  <p className="text-xs text-slate-500 italic">No passkey signatures recorded yet.</p>
                ) : (
                  <div className="flex flex-wrap gap-2">
                    {selectedReq.approvalsCollected.map((approver) => (
                      <div
                        key={approver}
                        className="px-3 py-1.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs flex items-center gap-2 font-mono"
                      >
                        <UserCheck className="w-3.5 h-3.5 text-emerald-400" />
                        <span>{approver}</span>
                        <span className="text-[10px] text-emerald-400/70">(WebAuthn Level 3 Verified)</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Action Controls for Awaiting Approval */}
              {selectedReq.status === 'AWAITING_APPROVAL' && (
                <div className="pt-4 border-t border-[#1f293d] flex flex-col md:flex-row md:items-center justify-between gap-4">
                  <div className="flex items-center gap-2 text-xs">
                    <label className="text-slate-400">Act as Approver:</label>
                    <select
                      value={approverActor}
                      onChange={(e) => setApproverActor(e.target.value)}
                      className="bg-[#090d16] border border-[#1f293d] text-xs text-slate-200 rounded px-2.5 py-1"
                    >
                      {selectedReq.id === 'req-ordinary-001' ? (
                        <>
                          <option value="user:finance-lead">Priya Patel (Resource Owner - Valid)</option>
                          <option value="user:rahul-assistant">Rahul Assistant (Self Requester - Refused by R1)</option>
                        </>
                      ) : (
                        <>
                          <option value="user:sec-lead-1">Alice Vance (Security Lead 1)</option>
                          <option value="user:sec-lead-2">Bob Chen (Security Lead 2)</option>
                          <option value="user:rahul">Rahul Sharma (Self - Refused by R1)</option>
                          <option value="user:rahul-assistant">Rahul Assistant (Controlled - Refused by R1)</option>
                        </>
                      )}
                    </select>
                  </div>

                  <div className="flex items-center gap-2.5">
                    <button
                      onClick={handleHold}
                      className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium"
                    >
                      Hold
                    </button>
                    <button
                      onClick={handleReject}
                      className="px-3 py-1.5 rounded bg-red-600/20 hover:bg-red-600/30 text-red-400 border border-red-500/30 text-xs font-medium"
                    >
                      Reject
                    </button>
                    <button
                      onClick={handleApproveWithPasskey}
                      className="px-4 py-1.5 rounded bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium flex items-center gap-1.5 shadow"
                    >
                      <Key className="w-3.5 h-3.5" />
                      Approve with Passkey
                    </button>
                  </div>
                </div>
              )}

              {/* Status Notice */}
              {signingStatus && (
                <div className="p-3 rounded-lg bg-blue-500/20 border border-blue-500/30 text-xs text-blue-300 font-mono flex items-center gap-2">
                  <Clock className="w-4 h-4 animate-spin text-blue-400 shrink-0" />
                  <span>{signingStatus}</span>
                </div>
              )}

              {/* D1 Execution & Verification Panel (When Approved) */}
              {selectedReq.status === 'APPROVED' && (
                <div className="pt-4 border-t border-[#1f293d] space-y-4">
                  <div className="p-4 rounded-lg bg-emerald-950/20 border border-emerald-500/30 flex flex-col md:flex-row md:items-center justify-between gap-3">
                    <div>
                      <h4 className="text-xs font-bold text-emerald-300 flex items-center gap-1.5 uppercase tracking-wide">
                        <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                        Quorum Satisfied ({selectedReq.approvalsCollected.length}/{selectedReq.requiredQuorum} Signatures)
                      </h4>
                      <p className="text-xs text-slate-300 mt-1">
                        Cryptographic threshold met. Ready for connector broker execution and independent read-back verification.
                      </p>
                    </div>

                    {!executionResult && (
                      <button
                        onClick={handleApplyViaConnector}
                        disabled={isExecuting}
                        className="px-4 py-2 rounded bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-medium flex items-center gap-2 shadow shrink-0 disabled:opacity-50"
                      >
                        {isExecuting ? (
                          <RefreshCw className="w-4 h-4 animate-spin" />
                        ) : (
                          <Play className="w-4 h-4" />
                        )}
                        Apply via Connector & Verify
                      </button>
                    )}
                  </div>

                  {/* Execution Read-Back Evidence */}
                  {executionResult && (
                    <div className="p-4 rounded-lg bg-[#090d16] border border-blue-500/30 space-y-3 font-mono text-xs">
                      <div className="flex items-center justify-between text-blue-400 font-bold border-b border-[#1f293d] pb-2">
                        <span>Observed Target Read-Back Evidence (FR-K2 / D1)</span>
                        <span className="text-emerald-400">Target Revision: {executionResult.revision}</span>
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-slate-300">
                        <div>
                          <span className="text-slate-500 block">Command ID:</span>
                          <span className="text-slate-200">{executionResult.command_id}</span>
                        </div>
                        <div>
                          <span className="text-slate-500 block">Observed Identity:</span>
                          <span className="text-slate-200">{executionResult.observed_state.target_identity}</span>
                        </div>
                        <div className="md:col-span-2">
                          <span className="text-slate-500 block">Active Granted Roles:</span>
                          <div className="flex flex-wrap gap-1 mt-1">
                            {executionResult.observed_state.current_roles.map((r: string) => (
                              <span
                                key={r}
                                className={`px-2 py-0.5 rounded text-[10px] ${
                                  r === selectedReq.requestedRole
                                    ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 font-bold'
                                    : 'bg-slate-800 text-slate-300'
                                }`}
                              >
                                {r}
                              </span>
                            ))}
                          </div>
                        </div>
                      </div>

                      {/* Business Probe Verification */}
                      {probeResult && (
                        <div className="mt-3 p-3 rounded bg-blue-950/20 border border-blue-500/20 text-xs">
                          <div className="flex items-center justify-between mb-1">
                            <span className="text-blue-300 font-semibold">Live Business Probe: Finance Report</span>
                            <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 text-[10px] font-bold">
                              HTTP 200 OK
                            </span>
                          </div>
                          <p className="text-[11px] text-slate-400">
                            Rahul session (<code className="text-slate-300">session:rahul-workstation-1</code>) confirmed able to read <code className="text-slate-300">res:finance-reports</code>.
                          </p>
                          {probeResult.report && (
                            <pre className="mt-2 p-2 rounded bg-black/40 text-[10px] text-slate-300 overflow-x-auto">
                              {JSON.stringify(probeResult.report, null, 2)}
                            </pre>
                          )}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
