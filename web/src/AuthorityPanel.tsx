import { useState, useEffect, useCallback } from 'react';
import {
  AuthorityState,
  AuthorityCredential,
  getAuthorityState,
  getAuthorityCredentials,
  signAndApplyAuthority,
  digestHex,
} from './lib/authority.ts';

interface AuthorityPanelProps {
  actorId: string;
  tenantId: string;
}

export function AuthorityPanel({ actorId, tenantId: _tenantId }: AuthorityPanelProps) {
  const [state, setState] = useState<AuthorityState | null>(null);
  const [credentials, setCredentials] = useState<AuthorityCredential[]>([]);
  const [selectedCredentialId, setSelectedCredentialId] = useState<string>('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionInProgress, setActionInProgress] = useState(false);

  // Forms
  const [showProposeRegistry, setShowProposeRegistry] = useState(false);
  const [newThresholdM, setNewThresholdM] = useState<number>(2);
  const [selectedCandidate, setSelectedCandidate] = useState<string>('');

  const [showProposePolicy, setShowProposePolicy] = useState(false);
  const [policyVersion, setPolicyVersion] = useState<string>('1.0.0');
  const [policyDescription, setPolicyDescription] = useState<string>('Governed security policy');

  const loadState = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const [s, creds] = await Promise.all([
        getAuthorityState(),
        getAuthorityCredentials().catch(() => [] as AuthorityCredential[]),
      ]);
      setState(s);
      setCredentials(creds);
      if (creds.length > 0 && !selectedCredentialId) {
        setSelectedCredentialId(creds[0].credential_id);
      }
      if (s?.authority?.genesis?.threshold_m) {
        setNewThresholdM(s.authority.genesis.threshold_m);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, [selectedCredentialId]);

  useEffect(() => {
    loadState();
  }, [loadState]);

  const auth = state?.authority;
  const genesis = auth?.genesis;
  const members = genesis?.members ?? [];
  const candidates = Object.values(state?.candidates ?? {});
  const registryProposals = Object.values(auth?.registry_proposals ?? {});
  const policyProposals = Object.values(auth?.proposals ?? {});
  const activeBundle = auth?.active_bundle;
  const isEnrolled = candidates.some(c => c.actor_id === actorId) || members.some(m => m.actor_id === actorId);

  const handleEnroll = async () => {
    if (!state || credentials.length === 0) return;
    try {
      setActionInProgress(true);
      setError(null);
      const cred = credentials.find(c => c.credential_id === selectedCredentialId) || credentials[0];
      await signAndApplyAuthority({
        command_id: crypto.randomUUID(),
        operation: 'enroll',
        expected_epoch: genesis?.epoch ?? 0,
        member: {
          actor_id: actorId,
          credential_id: cred.credential_id,
          public_key: cred.public_key,
          is_active: true,
          rp_id: window.location.hostname,
          origins: [window.location.origin],
        },
      });
      await loadState();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setActionInProgress(false);
    }
  };

  const handleProposeRegistry = async () => {
    if (!genesis) return;
    try {
      setActionInProgress(true);
      setError(null);
      const updatedMembers = [...members];

      if (selectedCandidate && state?.candidates[selectedCandidate]) {
        const candidate = state.candidates[selectedCandidate];
        if (!updatedMembers.some(m => m.actor_id === candidate.actor_id)) {
          updatedMembers.push({ ...candidate, is_active: true });
        }
      }

      await signAndApplyAuthority({
        command_id: crypto.randomUUID(),
        operation: 'registry_propose',
        expected_epoch: genesis.epoch,
        threshold: newThresholdM,
        members: updatedMembers,
      });

      setShowProposeRegistry(false);
      await loadState();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setActionInProgress(false);
    }
  };

  const handleSignRegistry = async (proposalId: string) => {
    if (!genesis) return;
    try {
      setActionInProgress(true);
      setError(null);
      await signAndApplyAuthority({
        command_id: crypto.randomUUID(),
        operation: 'registry_sign',
        expected_epoch: genesis.epoch,
        proposal_id: proposalId,
      });
      await loadState();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setActionInProgress(false);
    }
  };

  const handleActivateRegistry = async (proposalId: string) => {
    if (!genesis) return;
    try {
      setActionInProgress(true);
      setError(null);
      await signAndApplyAuthority({
        command_id: crypto.randomUUID(),
        operation: 'registry_activate',
        expected_epoch: genesis.epoch,
        proposal_id: proposalId,
      });
      await loadState();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setActionInProgress(false);
    }
  };

  const handleProposePolicy = async () => {
    if (!genesis) return;
    try {
      setActionInProgress(true);
      setError(null);
      await signAndApplyAuthority({
        command_id: crypto.randomUUID(),
        operation: 'bundle_propose',
        expected_epoch: genesis.epoch,
        bundle_version: policyVersion,
        description: policyDescription,
        modules: { 'authz.rego': 'package ratchet.authz\ndefault allow = false\nallow if { true }' },
        data: {},
      });
      setShowProposePolicy(false);
      await loadState();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setActionInProgress(false);
    }
  };

  const handleSignPolicy = async (proposalId: string) => {
    if (!genesis) return;
    try {
      setActionInProgress(true);
      setError(null);
      await signAndApplyAuthority({
        command_id: crypto.randomUUID(),
        operation: 'bundle_sign',
        expected_epoch: genesis.epoch,
        proposal_id: proposalId,
      });
      await loadState();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setActionInProgress(false);
    }
  };

  const handleActivatePolicy = async (proposalId: string) => {
    if (!genesis) return;
    try {
      setActionInProgress(true);
      setError(null);
      await signAndApplyAuthority({
        command_id: crypto.randomUUID(),
        operation: 'bundle_activate',
        expected_epoch: genesis.epoch,
        proposal_id: proposalId,
      });
      await loadState();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setActionInProgress(false);
    }
  };

  if (loading && !state) {
    return <div className="p-4 text-slate-400">Loading Authority state...</div>;
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-slate-100">Independent Security Authority</h2>
          <p className="text-sm text-slate-400">
            Cryptographic governance with M-of-N hardware passkey threshold signing
          </p>
        </div>
        <button
          onClick={loadState}
          disabled={loading}
          className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-sm rounded border border-slate-700"
        >
          {loading ? 'Refreshing...' : 'Refresh'}
        </button>
      </div>

      {error && (
        <div className="p-3 bg-red-950/50 border border-red-500/50 rounded text-red-300 text-sm">
          {error}
        </div>
      )}

      {/* Epoch & Threshold Summary */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="p-4 bg-slate-900 border border-slate-800 rounded-lg">
          <div className="text-xs text-slate-400 uppercase tracking-wide">Registry Epoch</div>
          <div className="text-2xl font-bold text-slate-100 mt-1" data-testid="authority-epoch">
            {genesis ? genesis.epoch : 'Uninitialized'}
          </div>
        </div>
        <div className="p-4 bg-slate-900 border border-slate-800 rounded-lg">
          <div className="text-xs text-slate-400 uppercase tracking-wide">Required Quorum</div>
          <div className="text-2xl font-bold text-slate-100 mt-1" data-testid="authority-threshold">
            {genesis ? `${genesis.threshold_m} of ${genesis.total_n}` : 'Pending Genesis'}
          </div>
        </div>
        <div className="p-4 bg-slate-900 border border-slate-800 rounded-lg">
          <div className="text-xs text-slate-400 uppercase tracking-wide">Active Members</div>
          <div className="text-2xl font-bold text-emerald-400 mt-1">
            {members.filter(m => m.is_active).length}
          </div>
        </div>
      </div>

      {/* Candidate Enrollment */}
      {!isEnrolled && credentials.length > 0 && (
        <div className="p-4 bg-amber-950/20 border border-amber-600/30 rounded-lg space-y-3">
          <div className="flex items-center justify-between">
            <div>
              <div className="font-medium text-amber-300">You are not enrolled as an Authority candidate</div>
              <div className="text-sm text-slate-400">
                Submit your registered passkey as an Authority candidate with pinned origin/RP context.
              </div>
            </div>
            <button
              onClick={handleEnroll}
              disabled={actionInProgress}
              className="px-4 py-2 bg-amber-600 hover:bg-amber-500 text-slate-950 font-semibold text-sm rounded transition"
            >
              {actionInProgress ? 'Signing...' : 'Enroll as Candidate'}
            </button>
          </div>
          {credentials.length > 1 && (
            <div className="flex items-center space-x-2 text-xs text-slate-400">
              <span>Select registered passkey:</span>
              <select
                value={selectedCredentialId}
                onChange={e => setSelectedCredentialId(e.target.value)}
                className="bg-slate-900 border border-slate-700 rounded px-2 py-1 text-slate-200"
              >
                {credentials.map(c => (
                  <option key={c.credential_id} value={c.credential_id}>
                    {c.credential_id.slice(0, 16)}...
                  </option>
                ))}
              </select>
            </div>
          )}
        </div>
      )}

      {/* Current Members */}
      <div className="p-4 bg-slate-900 border border-slate-800 rounded-lg space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="font-semibold text-slate-200">Authority Members</h3>
          {genesis && (
            <div className="flex space-x-2">
              <button
                onClick={() => setShowProposePolicy(!showProposePolicy)}
                className="px-3 py-1 bg-emerald-700 hover:bg-emerald-600 text-white text-xs font-medium rounded"
              >
                {showProposePolicy ? 'Cancel Policy' : 'Propose Policy'}
              </button>
              <button
                onClick={() => setShowProposeRegistry(!showProposeRegistry)}
                className="px-3 py-1 bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-medium rounded"
              >
                {showProposeRegistry ? 'Cancel Registry' : 'Propose Registry Change'}
              </button>
            </div>
          )}
        </div>

        {/* Propose Policy Form */}
        {showProposePolicy && (
          <div className="p-4 bg-slate-800/80 border border-slate-700 rounded-lg space-y-3">
            <h4 className="text-sm font-medium text-slate-200">New Policy Bundle Proposal</h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div>
                <label className="block text-xs text-slate-400 mb-1">Bundle Version</label>
                <input
                  type="text"
                  value={policyVersion}
                  onChange={e => setPolicyVersion(e.target.value)}
                  className="w-full px-3 py-1.5 bg-slate-900 border border-slate-700 rounded text-slate-200 text-sm"
                />
              </div>
              <div>
                <label className="block text-xs text-slate-400 mb-1">Description</label>
                <input
                  type="text"
                  value={policyDescription}
                  onChange={e => setPolicyDescription(e.target.value)}
                  className="w-full px-3 py-1.5 bg-slate-900 border border-slate-700 rounded text-slate-200 text-sm"
                />
              </div>
            </div>
            <button
              onClick={handleProposePolicy}
              disabled={actionInProgress}
              className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white text-sm font-semibold rounded"
            >
              {actionInProgress ? 'Submitting...' : 'Sign & Submit Policy Proposal'}
            </button>
          </div>
        )}

        {/* Propose Registry Form */}
        {showProposeRegistry && (
          <div className="p-4 bg-slate-800/80 border border-slate-700 rounded-lg space-y-3">
            <h4 className="text-sm font-medium text-slate-200">New Registry Proposal</h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div>
                <label className="block text-xs text-slate-400 mb-1">New Threshold M</label>
                <input
                  type="number"
                  min="1"
                  max="10"
                  value={newThresholdM}
                  onChange={e => setNewThresholdM(parseInt(e.target.value) || 1)}
                  className="w-full px-3 py-1.5 bg-slate-900 border border-slate-700 rounded text-slate-200 text-sm"
                />
              </div>
              <div>
                <label className="block text-xs text-slate-400 mb-1">Add Candidate Member</label>
                <select
                  value={selectedCandidate}
                  onChange={e => setSelectedCandidate(e.target.value)}
                  className="w-full px-3 py-1.5 bg-slate-900 border border-slate-700 rounded text-slate-200 text-sm"
                >
                  <option value="">None (Threshold only)</option>
                  {candidates
                    .filter(c => !members.some(m => m.actor_id === c.actor_id))
                    .map(c => (
                      <option key={c.actor_id} value={c.actor_id}>
                        {c.actor_id}
                      </option>
                    ))}
                </select>
              </div>
            </div>
            <button
              onClick={handleProposeRegistry}
              disabled={actionInProgress}
              className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-semibold rounded"
            >
              {actionInProgress ? 'Submitting...' : 'Sign & Submit Registry Proposal'}
            </button>
          </div>
        )}

        <div className="divide-y divide-slate-800">
          {members.length === 0 ? (
            <div className="py-2.5 text-xs text-slate-500 italic">No members yet. Complete candidate enrollment to initialize genesis.</div>
          ) : (
            members.map(member => (
              <div key={member.actor_id} className="py-2.5 flex items-center justify-between text-sm">
                <div className="flex items-center space-x-2">
                  <span className={`w-2 h-2 rounded-full ${member.is_active ? 'bg-emerald-400' : 'bg-slate-600'}`} />
                  <span className="font-mono text-slate-200">{member.actor_id}</span>
                  {member.actor_id === actorId && (
                    <span className="px-1.5 py-0.5 bg-indigo-900/50 text-indigo-300 text-xs rounded">You</span>
                  )}
                </div>
                <span className="text-xs text-slate-500 font-mono">
                  {member.credential_id ? `${member.credential_id.slice(0, 16)}...` : 'enrolled'}
                </span>
              </div>
            ))
          )}
        </div>
      </div>

      {/* Active Policy Bundle */}
      {activeBundle && (
        <div className="p-4 bg-slate-900 border border-slate-800 rounded-lg space-y-2">
          <div className="flex items-center justify-between">
            <h3 className="font-semibold text-slate-200">Active Policy Bundle</h3>
            <span className="px-2 py-0.5 bg-emerald-950 border border-emerald-500 text-emerald-300 text-xs rounded font-medium">
              v{activeBundle.bundle_version}
            </span>
          </div>
          <p className="text-sm text-slate-400">{activeBundle.description}</p>
          <div className="text-xs text-slate-500 font-mono">
            Digest: {digestHex(activeBundle.bundle_digest).slice(0, 32)}...
          </div>
        </div>
      )}

      {/* Policy Proposals */}
      {policyProposals.length > 0 && (
        <div className="p-4 bg-slate-900 border border-slate-800 rounded-lg space-y-3">
          <h3 className="font-semibold text-slate-200">Policy Proposals</h3>
          <div className="space-y-3">
            {policyProposals.map(prop => {
              const hasSigned = prop.signatures?.some(s => s.actor_id === actorId);
              const signatureCount = prop.signatures?.length ?? 0;
              const canActivate = genesis ? signatureCount >= genesis.threshold_m : false;

              return (
                <div key={prop.proposal_id} className="p-3 bg-slate-800/50 border border-slate-700 rounded-lg space-y-2">
                  <div className="flex items-center justify-between text-sm">
                    <span className="font-mono text-xs text-slate-400">v{prop.bundle_version} ({prop.proposal_id})</span>
                    <span className="px-2 py-0.5 bg-slate-700 text-slate-300 text-xs rounded font-medium">
                      {prop.status}
                    </span>
                  </div>
                  <div className="text-sm text-slate-300">{prop.description}</div>
                  <div className="flex items-center justify-between pt-2 border-t border-slate-700/50">
                    <span className="text-xs text-slate-400">
                      Signatures: {signatureCount} of {genesis?.threshold_m ?? 2} required
                    </span>
                    <div className="flex space-x-2">
                      {!hasSigned && prop.status === 'PROPOSED' && (
                        <button
                          onClick={() => handleSignPolicy(prop.proposal_id)}
                          disabled={actionInProgress}
                          className="px-3 py-1 bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold rounded"
                        >
                          {actionInProgress ? 'Signing...' : 'Sign with Passkey'}
                        </button>
                      )}
                      {canActivate && prop.status === 'PROPOSED' && (
                        <button
                          onClick={() => handleActivatePolicy(prop.proposal_id)}
                          disabled={actionInProgress}
                          className="px-3 py-1 bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold rounded"
                        >
                          {actionInProgress ? 'Activating...' : 'Activate Policy'}
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Registry Proposals */}
      {registryProposals.length > 0 && (
        <div className="p-4 bg-slate-900 border border-slate-800 rounded-lg space-y-3">
          <h3 className="font-semibold text-slate-200">Pending Registry Proposals</h3>
          <div className="space-y-3">
            {registryProposals.map(prop => {
              const hasSigned = prop.signatures?.some(s => s.actor_id === actorId);
              const signatureCount = prop.signatures?.length ?? 0;
              const canActivate = genesis ? signatureCount >= genesis.threshold_m : false;

              return (
                <div key={prop.proposal_id} className="p-3 bg-slate-800/50 border border-slate-700 rounded-lg space-y-2">
                  <div className="flex items-center justify-between text-sm">
                    <span className="font-mono text-xs text-slate-400">{prop.proposal_id}</span>
                    <span className="px-2 py-0.5 bg-slate-700 text-slate-300 text-xs rounded font-medium">
                      {prop.status}
                    </span>
                  </div>
                  <div className="text-sm text-slate-300">
                    Proposed: Threshold <span className="font-bold">{prop.proposed_m}</span> of <span className="font-bold">{prop.proposed_n}</span>
                    {prop.proposed_members?.length > 0 && (
                      <span className="text-slate-400 ml-2">
                        ({prop.proposed_members.length} members)
                      </span>
                    )}
                  </div>
                  <div className="flex items-center justify-between pt-2 border-t border-slate-700/50">
                    <span className="text-xs text-slate-400">
                      Signatures: {signatureCount} of {genesis?.threshold_m ?? 2} required
                    </span>
                    <div className="flex space-x-2">
                      {!hasSigned && prop.status === 'PROPOSED' && (
                        <button
                          onClick={() => handleSignRegistry(prop.proposal_id)}
                          disabled={actionInProgress}
                          className="px-3 py-1 bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold rounded"
                        >
                          {actionInProgress ? 'Signing...' : 'Sign with Passkey'}
                        </button>
                      )}
                      {canActivate && prop.status === 'PROPOSED' && (
                        <button
                          onClick={() => handleActivateRegistry(prop.proposal_id)}
                          disabled={actionInProgress}
                          className="px-3 py-1 bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold rounded"
                        >
                          {actionInProgress ? 'Activating...' : 'Activate Registry'}
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
