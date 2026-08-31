import { useState } from 'react';
import { ShieldAlert, ShieldCheck, Zap, AlertTriangle, ArrowRight, Eye, RefreshCw, Info } from 'lucide-react';

const API_BASE = 'http://localhost:8000/api/v1';

interface User {
  id: number;
  name: string;
  role: string;
  email: string;
  department: string;
  region: string;
  clearance: string;
  accountBalance: number;
  token?: string;
}


interface Props {
  currentUser: User;
  securityMode: 'vulnerable' | 'secure';
  onToggleMode: (mode: 'vulnerable' | 'secure') => void;
}

export function AttackLabView({ currentUser, securityMode, onToggleMode }: Props) {
  const [activeSubTab, setActiveSubTab] = useState<'BOLA' | 'BOPLA' | 'BFLA'>('BOLA');

  // BOLA State
  const [bolaObjectId, setBolaObjectId] = useState<number>(102);
  const [bolaResponse, setBolaResponse] = useState<any | null>(null);
  const [bolaLoading, setBolaLoading] = useState(false);

  // Multi-user BOLA lab state
  const [bolaLabResults, setBolaLabResults] = useState<any | null>(null);
  const [bolaLabLoading, setBolaLabLoading] = useState(false);

  // BOPLA State
  const [boplaRole, setBoplaRole] = useState('ADMIN');
  const [boplaBalance, setBoplaBalance] = useState(999999);
  const [boplaResponse, setBoplaResponse] = useState<any | null>(null);
  const [boplaLoading, setBoplaLoading] = useState(false);

  // BFLA State
  const [bflaEndpoint, setBflaEndpoint] = useState('/api/v1/bank/admin/users');
  const [bflaResponse, setBflaResponse] = useState<any | null>(null);
  const [bflaLoading, setBflaLoading] = useState(false);

  // Educational Modal State
  const [showExplainModal, setShowExplainModal] = useState(false);

  // Execute BOLA single attack
  const runBolaAttack = async () => {
    setBolaLoading(true);
    try {
      const res = await fetch(`${API_BASE}/bank/users/${bolaObjectId}`, {
        headers: { Authorization: `Bearer ${currentUser.token || 'token_' + currentUser.id}` },
      });
      const data = await res.json();
      setBolaResponse({ status: res.status, ok: res.ok, data });
    } catch (err: any) {
      setBolaResponse({ status: 500, ok: false, data: { error: err.message } });
    } finally {
      setBolaLoading(false);
    }
  };

  // Execute Multi-User BOLA Exposure Lab
  const runBolaExposureLab = async () => {
    setBolaLabLoading(true);
    try {
      const res = await fetch(`${API_BASE}/bank/demo/bola/users`, {
        headers: { Authorization: `Bearer ${currentUser.token || 'token_' + currentUser.id}` },
      });
      const data = await res.json();
      setBolaLabResults(data);
    } catch (err: any) {
      setBolaLabResults({ error: err.message });
    } finally {
      setBolaLabLoading(false);
    }
  };

  // Execute BOPLA attack
  const runBoplaAttack = async () => {
    setBoplaLoading(true);
    try {
      const res = await fetch(`${API_BASE}/bank/users/${currentUser.id}`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${currentUser.token || 'token_' + currentUser.id}`,
        },
        body: JSON.stringify({
          role: boplaRole,
          accountBalance: boplaBalance,
        }),
      });
      const data = await res.json();
      setBoplaResponse({ status: res.status, ok: res.ok, data });
    } catch (err: any) {
      setBoplaResponse({ status: 500, ok: false, data: { error: err.message } });
    } finally {
      setBoplaLoading(false);
    }
  };

  // Execute BFLA attack
  const runBflaAttack = async () => {
    setBflaLoading(true);
    try {
      const res = await fetch(`${API_BASE}/bank/admin/users`, {
        headers: { Authorization: `Bearer ${currentUser.token || 'token_' + currentUser.id}` },
      });
      const data = await res.json();
      setBflaResponse({ status: res.status, ok: res.ok, data });
    } catch (err: any) {
      setBflaResponse({ status: 500, ok: false, data: { error: err.message } });
    } finally {
      setBflaLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between bg-slate-900 border border-slate-800 p-6 rounded-2xl gap-4">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-rose-500/10 border border-rose-500/20 text-rose-400 rounded-xl">
              <Zap className="w-6 h-6" />
            </div>
            <div>
              <h2 className="text-xl font-bold text-white">Authorization Attack Lab</h2>
              <p className="text-xs text-slate-400">Interactive OWASP API Authorization Vulnerability Tester</p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => setShowExplainModal(true)}
            className="flex items-center gap-2 px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-xl transition border border-slate-700"
          >
            <Info className="w-4 h-4 text-cyan-400" />
            Explain This Finding
          </button>

          <button
            onClick={() => onToggleMode(securityMode === 'vulnerable' ? 'secure' : 'vulnerable')}
            className={`flex items-center gap-2 px-4 py-2 text-xs font-bold rounded-xl transition border ${
              securityMode === 'vulnerable'
                ? 'bg-rose-500/20 text-rose-300 border-rose-500/40 hover:bg-rose-500/30'
                : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40 hover:bg-emerald-500/30'
            }`}
          >
            {securityMode === 'vulnerable' ? <AlertTriangle className="w-4 h-4" /> : <ShieldCheck className="w-4 h-4" />}
            MODE: {securityMode.toUpperCase()}
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-slate-800 gap-2">
        <button
          onClick={() => setActiveSubTab('BOLA')}
          className={`px-5 py-3 text-sm font-semibold rounded-t-xl transition flex items-center gap-2 border-b-2 ${
            activeSubTab === 'BOLA'
              ? 'border-rose-500 text-rose-400 bg-slate-900/80'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <ShieldAlert className="w-4 h-4" />
          BOLA (Broken Object Level)
        </button>
        <button
          onClick={() => setActiveSubTab('BOPLA')}
          className={`px-5 py-3 text-sm font-semibold rounded-t-xl transition flex items-center gap-2 border-b-2 ${
            activeSubTab === 'BOPLA'
              ? 'border-amber-500 text-amber-400 bg-slate-900/80'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <ShieldAlert className="w-4 h-4" />
          BOPLA (Broken Property Level)
        </button>
        <button
          onClick={() => setActiveSubTab('BFLA')}
          className={`px-5 py-3 text-sm font-semibold rounded-t-xl transition flex items-center gap-2 border-b-2 ${
            activeSubTab === 'BFLA'
              ? 'border-purple-500 text-purple-400 bg-slate-900/80'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <ShieldAlert className="w-4 h-4" />
          BFLA (Broken Function Level)
        </button>
      </div>

      {/* ── BOLA TAB ──────────────────────────────────────────────────────── */}
      {activeSubTab === 'BOLA' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Attack Controls */}
          <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl space-y-5">
            <div>
              <span className="text-xs font-bold uppercase tracking-wider text-rose-400">OWASP API1:2023</span>
              <h3 className="text-lg font-bold text-white mt-1">Single Object ID Substitution Attack</h3>
              <p className="text-xs text-slate-400 mt-1">
                The authenticated user attempts to access an object identifier belonging to another user.
              </p>
            </div>

            <div className="bg-slate-950 p-4 rounded-xl space-y-3 text-xs border border-slate-800/80">
              <div className="flex justify-between">
                <span className="text-slate-400">Authenticated Identity:</span>
                <span className="font-bold text-cyan-300">{currentUser.name} (ID #{currentUser.id})</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">User Role:</span>
                <span className="px-2 py-0.5 bg-cyan-500/10 text-cyan-400 rounded text-[10px] font-bold">{currentUser.role}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Legitimate Object ID:</span>
                <span className="font-mono text-emerald-400">{currentUser.id}</span>
              </div>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Target Object ID to Request:</label>
              <div className="flex gap-2">
                <input
                  type="number"
                  value={bolaObjectId}
                  onChange={(e) => setBolaObjectId(Number(e.target.value))}
                  className="bg-slate-950 border border-slate-700 text-white font-mono text-sm px-3.5 py-2 rounded-xl flex-1 focus:outline-none focus:border-rose-500"
                />
                <button
                  onClick={runBolaAttack}
                  disabled={bolaLoading}
                  className="px-5 py-2 bg-rose-600 hover:bg-rose-500 text-white text-xs font-bold rounded-xl transition flex items-center gap-2 shadow-lg shadow-rose-900/30"
                >
                  {bolaLoading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />}
                  Execute Attack
                </button>
              </div>
            </div>

            <div className="border-t border-slate-800 pt-4">
              <div className="flex items-center justify-between mb-3">
                <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider">Multi-User Data Exposure Lab</h4>
                <button
                  onClick={runBolaExposureLab}
                  disabled={bolaLabLoading}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium rounded-lg transition flex items-center gap-1.5 border border-slate-700"
                >
                  {bolaLabLoading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Eye className="w-3.5 h-3.5 text-cyan-400" />}
                  Run 10-User Exposure Test
                </button>
              </div>

              {bolaLabResults && (
                <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-3">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-slate-400">Tested Objects: <strong className="text-white">{bolaLabResults.total_tested}</strong></span>
                    <span className="text-slate-400">Unauthorized Exposed: <strong className={bolaLabResults.unauthorized_accessible_objects > 0 ? "text-rose-400" : "text-emerald-400"}>{bolaLabResults.unauthorized_accessible_objects}</strong></span>
                  </div>
                  <div className={`p-2.5 rounded-lg text-xs font-bold text-center border ${
                    bolaLabResults.unauthorized_accessible_objects > 0
                      ? 'bg-rose-500/10 border-rose-500/30 text-rose-400'
                      : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                  }`}>
                    {bolaLabResults.bola_status}
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Response & Attack Analysis */}
          <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl flex flex-col justify-between space-y-4">
            <div>
              <div className="flex items-center justify-between mb-3">
                <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider">Live API Response Inspector</h4>
                {bolaResponse && (
                  <span className={`px-2.5 py-1 text-xs font-mono font-bold rounded-lg ${
                    bolaResponse.status === 200
                      ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                      : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                  }`}>
                    HTTP {bolaResponse.status}
                  </span>
                )}
              </div>

              {bolaResponse ? (
                <pre className="bg-slate-950 p-4 rounded-xl border border-slate-800 text-xs font-mono text-slate-300 overflow-x-auto max-h-72">
                  {JSON.stringify(bolaResponse.data, null, 2)}
                </pre>
              ) : (
                <div className="bg-slate-950 p-8 rounded-xl border border-slate-800 text-center text-slate-500 text-xs">
                  Click "Execute Attack" above to view live server response.
                </div>
              )}
            </div>

            {/* Attack Flow Diagram */}
            <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 text-xs space-y-2">
              <h5 className="font-bold text-slate-300 flex items-center gap-2">
                <ArrowRight className="w-4 h-4 text-cyan-400" />
                Attack to Mitigation Execution Flow
              </h5>
              <div className="grid grid-cols-3 gap-2 text-center text-[11px] pt-1">
                <div className="bg-slate-900 p-2 rounded border border-slate-800">
                  <span className="text-slate-400 block">Step 1</span>
                  <span className="text-white font-medium">Request ID #{bolaObjectId}</span>
                </div>
                <div className="bg-slate-900 p-2 rounded border border-slate-800">
                  <span className="text-slate-400 block">Step 2</span>
                  <span className="text-cyan-400 font-medium">Ownership Check</span>
                </div>
                <div className={`p-2 rounded border font-bold ${
                  securityMode === 'vulnerable' ? 'bg-rose-950/40 border-rose-800 text-rose-400' : 'bg-emerald-950/40 border-emerald-800 text-emerald-400'
                }`}>
                  <span className="block text-[10px] opacity-80">Step 3</span>
                  {securityMode === 'vulnerable' ? '⚠️ EXPOSED (200)' : '🛡️ BLOCKED (403)'}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── BOPLA TAB ─────────────────────────────────────────────────────── */}
      {activeSubTab === 'BOPLA' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl space-y-5">
            <div>
              <span className="text-xs font-bold uppercase tracking-wider text-amber-400">OWASP API3:2023</span>
              <h3 className="text-lg font-bold text-white mt-1">Property Injection & Privilege Escalation</h3>
              <p className="text-xs text-slate-400 mt-1">
                Attempts to inject privileged fields (<code className="text-amber-300">role</code>, <code className="text-amber-300">accountBalance</code>) into normal profile update payloads.
              </p>
            </div>

            <div className="space-y-3">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Inject Role Field:</label>
                <select
                  value={boplaRole}
                  onChange={(e) => setBoplaRole(e.target.value)}
                  className="bg-slate-950 border border-slate-700 text-white text-xs px-3.5 py-2 rounded-xl w-full focus:outline-none focus:border-amber-500"
                >
                  <option value="ADMIN">ADMIN (Privilege Escalation)</option>
                  <option value="MANAGER">MANAGER</option>
                  <option value="SUPPORT">SUPPORT</option>
                  <option value="CUSTOMER">CUSTOMER (Normal)</option>
                </select>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Inject Account Balance Field ($):</label>
                <input
                  type="number"
                  value={boplaBalance}
                  onChange={(e) => setBoplaBalance(Number(e.target.value))}
                  className="bg-slate-950 border border-slate-700 text-white font-mono text-xs px-3.5 py-2 rounded-xl w-full focus:outline-none focus:border-amber-500"
                />
              </div>

              <div className="bg-slate-950 p-3 rounded-xl border border-slate-800 font-mono text-[11px] text-amber-300">
                <span className="text-slate-500">// Payload to send via PATCH /api/v1/bank/users/{currentUser.id}</span>
                <br />
                {JSON.stringify({ name: currentUser.name, role: boplaRole, accountBalance: boplaBalance }, null, 2)}
              </div>

              <button
                onClick={runBoplaAttack}
                disabled={boplaLoading}
                className="w-full py-2.5 bg-amber-600 hover:bg-amber-500 text-white text-xs font-bold rounded-xl transition flex items-center justify-center gap-2 shadow-lg shadow-amber-900/30"
              >
                {boplaLoading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />}
                Inject Privileged Properties
              </button>
            </div>
          </div>

          <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl flex flex-col justify-between space-y-4">
            <div>
              <div className="flex items-center justify-between mb-3">
                <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider">Property Authorization Result</h4>
                {boplaResponse && (
                  <span className={`px-2.5 py-1 text-xs font-mono font-bold rounded-lg ${
                    boplaResponse.status === 200
                      ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                      : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                  }`}>
                    HTTP {boplaResponse.status}
                  </span>
                )}
              </div>

              {boplaResponse ? (
                <pre className="bg-slate-950 p-4 rounded-xl border border-slate-800 text-xs font-mono text-slate-300 overflow-x-auto max-h-72">
                  {JSON.stringify(boplaResponse.data, null, 2)}
                </pre>
              ) : (
                <div className="bg-slate-950 p-8 rounded-xl border border-slate-800 text-center text-slate-500 text-xs">
                  Click "Inject Privileged Properties" above to test property level authorization.
                </div>
              )}
            </div>

            <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 text-xs">
              <h5 className="font-bold text-slate-300 mb-1">Mitigation Architecture (BOPLA)</h5>
              <p className="text-slate-400 text-[11px]">
                Strict server-side DTO schemas enforce strict field whitelisting. Privileged properties like <code className="text-slate-200">role</code> and <code className="text-slate-200">accountBalance</code> are rejected before hitting business logic.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* ── BFLA TAB ─────────────────────────────────────────────────────── */}
      {activeSubTab === 'BFLA' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl space-y-5">
            <div>
              <span className="text-xs font-bold uppercase tracking-wider text-purple-400">OWASP API5:2023</span>
              <h3 className="text-lg font-bold text-white mt-1">Broken Function Level Authorization</h3>
              <p className="text-xs text-slate-400 mt-1">
                A non-administrative user (<code className="text-purple-300">{currentUser.role}</code>) attempts to execute administrative endpoints e.g. <code className="text-purple-300">/api/v1/bank/admin/users</code>.
              </p>
            </div>

            <div className="space-y-3">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Target Administrative Endpoint:</label>
                <input
                  type="text"
                  value={bflaEndpoint}
                  onChange={(e) => setBflaEndpoint(e.target.value)}
                  className="bg-slate-950 border border-slate-700 text-white font-mono text-xs px-3.5 py-2 rounded-xl w-full focus:outline-none focus:border-purple-500"
                />
              </div>

              <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 text-xs space-y-2">
                <div className="flex justify-between">
                  <span className="text-slate-400">Caller Role:</span>
                  <span className="font-bold text-purple-400">{currentUser.role}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Required Role:</span>
                  <span className="font-bold text-emerald-400">ADMIN</span>
                </div>
              </div>

              <button
                onClick={runBflaAttack}
                disabled={bflaLoading}
                className="w-full py-2.5 bg-purple-600 hover:bg-purple-500 text-white text-xs font-bold rounded-xl transition flex items-center justify-center gap-2 shadow-lg shadow-purple-900/30"
              >
                {bflaLoading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />}
                Invoke Administrative Endpoint
              </button>
            </div>
          </div>

          <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl flex flex-col justify-between space-y-4">
            <div>
              <div className="flex items-center justify-between mb-3">
                <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider">Function Authorization Result</h4>
                {bflaResponse && (
                  <span className={`px-2.5 py-1 text-xs font-mono font-bold rounded-lg ${
                    bflaResponse.status === 200
                      ? 'bg-purple-500/20 text-purple-400 border border-purple-500/30'
                      : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                  }`}>
                    HTTP {bflaResponse.status}
                  </span>
                )}
              </div>

              {bflaResponse ? (
                <pre className="bg-slate-950 p-4 rounded-xl border border-slate-800 text-xs font-mono text-slate-300 overflow-x-auto max-h-72">
                  {JSON.stringify(bflaResponse.data, null, 2)}
                </pre>
              ) : (
                <div className="bg-slate-950 p-8 rounded-xl border border-slate-800 text-center text-slate-500 text-xs">
                  Click "Invoke Administrative Endpoint" above to test function level authorization.
                </div>
              )}
            </div>

            <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 text-xs">
              <h5 className="font-bold text-slate-300 mb-1">BFLA Mitigation Rule</h5>
              <p className="text-slate-400 text-[11px]">
                Every endpoint handler is decorated with strict role/permission checks. Authenticated status alone does NOT imply function access.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* ── EXPLAIN THIS FINDING MODAL ────────────────────────────────────── */}
      {showExplainModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 max-w-2xl w-full rounded-2xl p-6 space-y-5 shadow-2xl">
            <div className="flex justify-between items-center border-b border-slate-800 pb-3">
              <h3 className="text-lg font-bold text-white flex items-center gap-2">
                <Info className="w-5 h-5 text-cyan-400" />
                Faculty Educational Reference — OWASP Authorization Flaws
              </h3>
              <button onClick={() => setShowExplainModal(false)} className="text-slate-400 hover:text-white">✕</button>
            </div>

            <div className="space-y-4 text-xs text-slate-300">
              <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-1">
                <h4 className="font-bold text-rose-400 text-sm">1. BOLA (Broken Object Level Authorization)</h4>
                <p>Occurs when an API endpoint accepts object identifiers (e.g. <code className="text-slate-200">/users/102</code>) without verifying whether the requesting user owns or has permission to access that specific object.</p>
              </div>

              <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-1">
                <h4 className="font-bold text-amber-400 text-sm">2. BOPLA (Broken Object Property Level Authorization)</h4>
                <p>Occurs when users can read or write sensitive properties (e.g. <code className="text-slate-200">role</code>, <code className="text-slate-200">balance</code>) that should be restricted to backend server logic or high-privilege administrators.</p>
              </div>

              <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-1">
                <h4 className="font-bold text-purple-400 text-sm">3. BFLA (Broken Function Level Authorization)</h4>
                <p>Occurs when sensitive administrative functions (e.g. <code className="text-slate-200">/admin/users</code>) check only if the caller is logged in, without checking if their assigned role permits administrative execution.</p>
              </div>
            </div>

            <div className="pt-2 text-right">
              <button onClick={() => setShowExplainModal(false)} className="px-5 py-2 bg-cyan-600 hover:bg-cyan-500 text-white font-bold rounded-xl text-xs">
                Close Explanation
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
