import React, { useEffect, useState } from 'react';
import { fetchOrgState, OrgState } from './lib/api';
import { SecurityOverview } from './components/SecurityOverview';
import { ChangeReview } from './components/ChangeReview';
import { InfrastructureMap } from './components/InfrastructureMap';
import { ImpactSimulator } from './components/ImpactSimulator';
import { PolicyGovernance } from './components/PolicyGovernance';
import { IncidentContainment } from './components/IncidentContainment';
import { AuditHistory } from './components/AuditHistory';
import { RefreshCw, Layers, Sparkles, AlertCircle, ShieldCheck, Activity, Key, ShieldAlert, FileText } from 'lucide-react';

export const App: React.FC = () => {
  const [org, setOrg] = useState<OrgState | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'review' | 'map' | 'simulator' | 'governance' | 'containment' | 'audit'>('overview');

  const loadOrg = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchOrgState();
      setOrg(data);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadOrg();
  }, []);

  return (
    <div className="min-h-screen bg-[#090d16] text-slate-100 flex flex-col">
      {/* Top Navigation Bar */}
      <header className="border-b border-[#1f293d] bg-[#0c1220] px-6 py-3.5 sticky top-0 z-50 shadow-md">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-blue-600 flex items-center justify-center text-white font-bold tracking-widest text-sm shadow">
              R
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-sm font-bold tracking-wide text-white uppercase">
                  RATCHET Control Plane
                </h1>
                <span className="text-[10px] px-2 py-0.5 rounded bg-blue-500/20 text-blue-400 border border-blue-500/30 font-mono">
                  v1.0 (Half B)
                </span>
              </div>
              <p className="text-[11px] text-slate-400">
                Independent Security Governance & Privilege Containment
              </p>
            </div>
          </div>

          <div className="flex items-center gap-4 text-xs font-mono">
            {org && (
              <div className="hidden md:flex items-center gap-3 text-slate-400 bg-[#111726] px-3 py-1.5 rounded-lg border border-[#1f293d]">
                <span>
                  Tenant: <strong className="text-slate-200">{org.tenant_id}</strong>
                </span>
                <span className="text-slate-600">|</span>
                <span>
                  Revision: <strong className="text-emerald-400">{org.revision}</strong>
                </span>
              </div>
            )}

            <button
              onClick={loadOrg}
              disabled={loading}
              className="p-1.5 rounded-lg bg-[#111726] border border-[#1f293d] hover:bg-[#1f293d] text-slate-300 transition-colors"
              title="Refresh State"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-blue-400' : ''}`} />
            </button>
          </div>
        </div>
      </header>

      {/* Sub-Header Navigation Tabs */}
      <div className="border-b border-[#1f293d] bg-[#0d1424] px-6">
        <div className="max-w-7xl mx-auto flex gap-2 pt-2">
          <button
            onClick={() => setActiveTab('overview')}
            className={`px-4 py-2 text-xs font-medium border-b-2 flex items-center gap-2 transition-colors ${
              activeTab === 'overview'
                ? 'border-blue-500 text-blue-400 bg-blue-500/5'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Activity className="w-3.5 h-3.5" />
            Security Overview
          </button>

          <button
            onClick={() => setActiveTab('review')}
            className={`px-4 py-2 text-xs font-medium border-b-2 flex items-center gap-2 transition-colors ${
              activeTab === 'review'
                ? 'border-blue-500 text-blue-400 bg-blue-500/5'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <ShieldCheck className="w-3.5 h-3.5" />
            Change Review
          </button>

          <button
            onClick={() => setActiveTab('map')}
            className={`px-4 py-2 text-xs font-medium border-b-2 flex items-center gap-2 transition-colors ${
              activeTab === 'map'
                ? 'border-blue-500 text-blue-400 bg-blue-500/5'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            Infrastructure Map
          </button>

          <button
            onClick={() => setActiveTab('simulator')}
            className={`px-4 py-2 text-xs font-medium border-b-2 flex items-center gap-2 transition-colors ${
              activeTab === 'simulator'
                ? 'border-blue-500 text-blue-400 bg-blue-500/5'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Sparkles className="w-3.5 h-3.5" />
            Impact Simulator
          </button>

          <button
            onClick={() => setActiveTab('governance')}
            className={`px-4 py-2 text-xs font-medium border-b-2 flex items-center gap-2 transition-colors ${
              activeTab === 'governance'
                ? 'border-blue-500 text-blue-400 bg-blue-500/5'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Key className="w-3.5 h-3.5" />
            Policy Governance
          </button>

          <button
            onClick={() => setActiveTab('containment')}
            className={`px-4 py-2 text-xs font-medium border-b-2 flex items-center gap-2 transition-colors ${
              activeTab === 'containment'
                ? 'border-red-500 text-red-400 bg-red-500/5'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <ShieldAlert className="w-3.5 h-3.5" />
            Incident Containment
          </button>

          <button
            onClick={() => setActiveTab('audit')}
            className={`px-4 py-2 text-xs font-medium border-b-2 flex items-center gap-2 transition-colors ${
              activeTab === 'audit'
                ? 'border-blue-500 text-blue-400 bg-blue-500/5'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileText className="w-3.5 h-3.5" />
            Audit &amp; History
          </button>
        </div>
      </div>

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-6">
        {loading && !org && (
          <div className="p-12 text-center text-slate-400 flex flex-col items-center gap-3">
            <RefreshCw className="w-6 h-6 animate-spin text-blue-500" />
            <span className="text-xs">Connecting to simulator control plane...</span>
          </div>
        )}

        {error && (
          <div className="p-4 rounded-xl bg-red-950/20 border border-red-500/30 text-red-300 text-xs flex items-center justify-between">
            <div className="flex items-center gap-2">
              <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
              <span>Failed to fetch live target state: {error}</span>
            </div>
            <button
              onClick={loadOrg}
              className="px-3 py-1 rounded bg-red-500/20 hover:bg-red-500/30 text-red-300 border border-red-500/30"
            >
              Retry
            </button>
          </div>
        )}

        {org && activeTab === 'overview' && (
          <SecurityOverview
            org={org}
            onNavigateToReview={() => setActiveTab('review')}
            onNavigateToMap={() => setActiveTab('map')}
            onNavigateToSimulator={() => setActiveTab('simulator')}
          />
        )}
        {org && activeTab === 'review' && <ChangeReview org={org} onRefreshOrg={loadOrg} />}
        {org && activeTab === 'map' && <InfrastructureMap org={org} />}
        {org && activeTab === 'simulator' && <ImpactSimulator org={org} />}
        {org && activeTab === 'governance' && <PolicyGovernance tenantId={org.tenant_id} />}
        {org && activeTab === 'containment' && (
          <IncidentContainment
            org={org}
            onRefreshOrg={loadOrg}
            onNavigateToReview={() => setActiveTab('review')}
          />
        )}
        {org && activeTab === 'audit' && <AuditHistory org={org} />}
      </main>
    </div>
  );
};
