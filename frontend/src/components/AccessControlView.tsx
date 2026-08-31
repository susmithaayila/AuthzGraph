import { useState } from 'react';
import { Shield, Users, Layers, Key, CheckCircle, XCircle, RefreshCw, Lock } from 'lucide-react';


const API_BASE = 'http://localhost:8000/api/v1';

export function AccessControlView() {
  const [activeTab, setActiveTab] = useState<'RBAC' | 'ABAC' | 'MAC'>('RBAC');

  // RBAC Sim State
  const [rbacUserId, setRbacUserId] = useState(101);
  const [rbacAction, setRbacAction] = useState('View All Customers');
  const [rbacPerm, setRbacPerm] = useState('CUSTOMER_READ_ALL');
  const [rbacResult, setRbacResult] = useState<any | null>(null);
  const [rbacLoading, setRbacLoading] = useState(false);

  // ABAC Sim State
  const [abacUserId, setAbacUserId] = useState(301);
  const [abacDocId, setAbacDocId] = useState(503);
  const [abacResult, setAbacResult] = useState<any | null>(null);
  const [abacLoading, setAbacLoading] = useState(false);

  // MAC Sim State
  const [macUserId, setMacUserId] = useState(101);
  const [macDocId, setMacDocId] = useState(504);
  const [macResult, setMacResult] = useState<any | null>(null);
  const [macLoading, setMacLoading] = useState(false);

  // Run RBAC Simulator
  const runRbacSim = async () => {
    setRbacLoading(true);
    try {
      const res = await fetch(`${API_BASE}/bank/simulator/rbac`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user_id: rbacUserId, requested_action: rbacAction, required_permission: rbacPerm }),
      });
      const data = await res.json();
      setRbacResult(data);
    } catch (err: any) {
      setRbacResult({ error: err.message });
    } finally {
      setRbacLoading(false);
    }
  };

  // Run ABAC Simulator
  const runAbacSim = async () => {
    setAbacLoading(true);
    try {
      const res = await fetch(`${API_BASE}/bank/simulator/abac`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user_id: abacUserId, doc_id: abacDocId, requested_action: 'READ' }),
      });
      const data = await res.json();
      setAbacResult(data);
    } catch (err: any) {
      setAbacResult({ error: err.message });
    } finally {
      setAbacLoading(false);
    }
  };

  // Run MAC Simulator
  const runMacSim = async () => {
    setMacLoading(true);
    try {
      const res = await fetch(`${API_BASE}/bank/simulator/mac`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user_id: macUserId, doc_id: macDocId }),
      });
      const data = await res.json();
      setMacResult(data);
    } catch (err: any) {
      setMacResult({ error: err.message });
    } finally {
      setMacLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 rounded-xl">
            <Shield className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-white">Access Control Policy Engines</h2>
            <p className="text-xs text-slate-400">Formal Access Control Models: Role-Based (RBAC), Attribute-Based (ABAC), and Mandatory (MAC)</p>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-slate-800 gap-2">
        <button
          onClick={() => setActiveTab('RBAC')}
          className={`px-5 py-3 text-sm font-semibold rounded-t-xl transition flex items-center gap-2 border-b-2 ${
            activeTab === 'RBAC' ? 'border-cyan-500 text-cyan-400 bg-slate-900/80' : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Users className="w-4 h-4" />
          RBAC (Role-Based)
        </button>
        <button
          onClick={() => setActiveTab('ABAC')}
          className={`px-5 py-3 text-sm font-semibold rounded-t-xl transition flex items-center gap-2 border-b-2 ${
            activeTab === 'ABAC' ? 'border-indigo-500 text-indigo-400 bg-slate-900/80' : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Layers className="w-4 h-4" />
          ABAC (Attribute-Based)
        </button>
        <button
          onClick={() => setActiveTab('MAC')}
          className={`px-5 py-3 text-sm font-semibold rounded-t-xl transition flex items-center gap-2 border-b-2 ${
            activeTab === 'MAC' ? 'border-emerald-500 text-emerald-400 bg-slate-900/80' : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Lock className="w-4 h-4" />
          MAC (Mandatory Access)
        </button>
      </div>

      {/* ── RBAC TAB ──────────────────────────────────────────────────────── */}
      {activeTab === 'RBAC' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* RBAC Simulator Controls */}
            <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl space-y-4">
              <h3 className="text-lg font-bold text-white flex items-center gap-2">
                <Users className="w-5 h-5 text-cyan-400" />
                RBAC Access Control Simulator
              </h3>
              <p className="text-xs text-slate-400">
                Evaluates requested actions against assigned user roles and permission matrices.
              </p>

              <div className="space-y-3">
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">Select Subject Identity:</label>
                  <select
                    value={rbacUserId}
                    onChange={(e) => setRbacUserId(Number(e.target.value))}
                    className="bg-slate-950 border border-slate-700 text-white text-xs px-3.5 py-2 rounded-xl w-full focus:outline-none focus:border-cyan-500"
                  >
                    <option value={101}>Alice Johnson (CUSTOMER)</option>
                    <option value={201}>Sarah Jenkins (SUPPORT)</option>
                    <option value={301}>Marcus Vance (MANAGER)</option>
                    <option value={401}>Dr. Aris Thorne (ADMIN)</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">Requested Action & Permission:</label>
                  <select
                    value={rbacPerm}
                    onChange={(e) => {
                      setRbacPerm(e.target.value);
                      if (e.target.value === 'CUSTOMER_READ_ALL') setRbacAction('View All Customers');
                      if (e.target.value === 'CUSTOMER_DELETE') setRbacAction('Delete Customer Account');
                      if (e.target.value === 'PROFILE_READ_SELF') setRbacAction('View Own Profile');
                      if (e.target.value === 'AUDIT_READ') setRbacAction('View Security Audit Logs');
                    }}
                    className="bg-slate-950 border border-slate-700 text-white text-xs px-3.5 py-2 rounded-xl w-full focus:outline-none focus:border-cyan-500"
                  >
                    <option value="PROFILE_READ_SELF">View Own Profile (PROFILE_READ_SELF)</option>
                    <option value="CUSTOMER_READ_ALL">View All Customers (CUSTOMER_READ_ALL)</option>
                    <option value="CUSTOMER_DELETE">Delete Customer Account (CUSTOMER_DELETE)</option>
                    <option value="AUDIT_READ">View Security Audit Logs (AUDIT_READ)</option>
                  </select>
                </div>

                <button
                  onClick={runRbacSim}
                  disabled={rbacLoading}
                  className="w-full py-2.5 bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-bold rounded-xl transition flex items-center justify-center gap-2 shadow-lg shadow-cyan-900/30"
                >
                  {rbacLoading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Key className="w-4 h-4" />}
                  Evaluate RBAC Decision
                </button>
              </div>
            </div>

            {/* RBAC Result */}
            <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl flex flex-col justify-between space-y-4">
              <div>
                <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-3">RBAC Policy Evaluation Result</h4>
                {rbacResult ? (
                  <div className="space-y-3">
                    <div className={`p-4 rounded-xl border flex items-center justify-between ${
                      rbacResult.decision === 'ALLOW' ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300' : 'bg-rose-500/10 border-rose-500/30 text-rose-300'
                    }`}>
                      <div className="flex items-center gap-3">
                        {rbacResult.decision === 'ALLOW' ? <CheckCircle className="w-6 h-6 text-emerald-400" /> : <XCircle className="w-6 h-6 text-rose-400" />}
                        <div>
                          <h5 className="font-bold text-sm">{rbacResult.decision} (HTTP {rbacResult.http_status})</h5>
                          <p className="text-xs opacity-90">{rbacResult.reason}</p>
                        </div>
                      </div>
                    </div>

                    <pre className="bg-slate-950 p-4 rounded-xl border border-slate-800 text-xs font-mono text-slate-300 overflow-x-auto">
                      {JSON.stringify(rbacResult, null, 2)}
                    </pre>
                  </div>
                ) : (
                  <div className="bg-slate-950 p-8 rounded-xl border border-slate-800 text-center text-slate-500 text-xs">
                    Click "Evaluate RBAC Decision" to run simulator.
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── ABAC TAB ──────────────────────────────────────────────────────── */}
      {activeTab === 'ABAC' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl space-y-4">
            <h3 className="text-lg font-bold text-white flex items-center gap-2">
              <Layers className="w-5 h-5 text-indigo-400" />
              ABAC Attribute Policy Evaluator
            </h3>
            <p className="text-xs text-slate-400">
              Evaluates access using subject attributes (Role, Department, Region, Clearance) against resource attributes (Department, Region, Classification).
            </p>

            <div className="space-y-3">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Select Subject (User):</label>
                <select
                  value={abacUserId}
                  onChange={(e) => setAbacUserId(Number(e.target.value))}
                  className="bg-slate-950 border border-slate-700 text-white text-xs px-3.5 py-2 rounded-xl w-full focus:outline-none focus:border-indigo-500"
                >
                  <option value={301}>Marcus Vance (MANAGER | Retail Banking | South)</option>
                  <option value={101}>Alice Johnson (CUSTOMER | Retail Banking | South)</option>
                  <option value={102}>Bob Smith (CUSTOMER | Retail Banking | North)</option>
                  <option value={401}>Dr. Aris Thorne (ADMIN | IT Security | Global)</option>
                </select>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Select Resource (Document):</label>
                <select
                  value={abacDocId}
                  onChange={(e) => setAbacDocId(Number(e.target.value))}
                  className="bg-slate-950 border border-slate-700 text-white text-xs px-3.5 py-2 rounded-xl w-full focus:outline-none focus:border-indigo-500"
                >
                  <option value={503}>South Region Salary Report (Dept: Retail Banking | Region: South)</option>
                  <option value={502}>Bob Loan Agreement (Dept: Retail Banking | Region: North)</option>
                  <option value={504}>Bank Master HSM Key Rotation (Dept: IT Security | Clearance: SECRET)</option>
                </select>
              </div>

              <button
                onClick={runAbacSim}
                disabled={abacLoading}
                className="w-full py-2.5 bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-bold rounded-xl transition flex items-center justify-center gap-2 shadow-lg shadow-indigo-900/30"
              >
                {abacLoading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Layers className="w-4 h-4" />}
                Evaluate ABAC Attributes
              </button>
            </div>
          </div>

          <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl flex flex-col justify-between space-y-4">
            <div>
              <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-3">ABAC Attribute Matching Analysis</h4>
              {abacResult ? (
                <div className="space-y-3">
                  <div className={`p-4 rounded-xl border flex items-center justify-between ${
                    abacResult.decision === 'ALLOW' ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300' : 'bg-rose-500/10 border-rose-500/30 text-rose-300'
                  }`}>
                    <div className="flex items-center gap-3">
                      {abacResult.decision === 'ALLOW' ? <CheckCircle className="w-6 h-6 text-emerald-400" /> : <XCircle className="w-6 h-6 text-rose-400" />}
                      <div>
                        <h5 className="font-bold text-sm">{abacResult.decision}</h5>
                        <p className="text-xs opacity-90">{abacResult.reason}</p>
                      </div>
                    </div>
                  </div>

                  <div className="grid grid-cols-3 gap-2 text-center text-xs">
                    <div className={`p-2.5 rounded-lg border font-bold ${abacResult.evaluation.department_match ? 'bg-emerald-950/40 border-emerald-800 text-emerald-400' : 'bg-rose-950/40 border-rose-800 text-rose-400'}`}>
                      Department
                      <span className="block text-[10px] opacity-80">{abacResult.evaluation.department_match ? 'MATCH' : 'MISMATCH'}</span>
                    </div>
                    <div className={`p-2.5 rounded-lg border font-bold ${abacResult.evaluation.region_match ? 'bg-emerald-950/40 border-emerald-800 text-emerald-400' : 'bg-rose-950/40 border-rose-800 text-rose-400'}`}>
                      Region
                      <span className="block text-[10px] opacity-80">{abacResult.evaluation.region_match ? 'MATCH' : 'MISMATCH'}</span>
                    </div>
                    <div className={`p-2.5 rounded-lg border font-bold ${abacResult.evaluation.clearance_match ? 'bg-emerald-950/40 border-emerald-800 text-emerald-400' : 'bg-rose-950/40 border-rose-800 text-rose-400'}`}>
                      Clearance
                      <span className="block text-[10px] opacity-80">{abacResult.evaluation.clearance_match ? 'MATCH' : 'MISMATCH'}</span>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="bg-slate-950 p-8 rounded-xl border border-slate-800 text-center text-slate-500 text-xs">
                  Click "Evaluate ABAC Attributes" to run attribute matching.
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ── MAC TAB ──────────────────────────────────────────────────────── */}
      {activeTab === 'MAC' && (
        <div className="space-y-6">
          {/* Classification Lattice Diagram */}
          <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl space-y-4">
            <h3 className="text-sm font-bold text-white flex items-center gap-2 uppercase tracking-wider">
              <Lock className="w-4 h-4 text-emerald-400" />
              Mandatory Access Control (MAC) Sensitivity Classification Lattice
            </h3>

            <div className="grid grid-cols-4 gap-3 text-center">
              <div className="bg-slate-950 p-4 rounded-xl border border-slate-800">
                <span className="text-xs font-bold text-slate-400 block">LEVEL 1</span>
                <span className="text-sm font-bold text-slate-200">PUBLIC</span>
              </div>
              <div className="bg-slate-950 p-4 rounded-xl border border-slate-800">
                <span className="text-xs font-bold text-blue-400 block">LEVEL 2</span>
                <span className="text-sm font-bold text-blue-300">INTERNAL</span>
              </div>
              <div className="bg-slate-950 p-4 rounded-xl border border-slate-800">
                <span className="text-xs font-bold text-amber-400 block">LEVEL 3</span>
                <span className="text-sm font-bold text-amber-300">CONFIDENTIAL</span>
              </div>
              <div className="bg-slate-950 p-4 rounded-xl border border-rose-500/30 bg-rose-500/5">
                <span className="text-xs font-bold text-rose-400 block">LEVEL 4</span>
                <span className="text-sm font-bold text-rose-300">SECRET</span>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl space-y-4">
              <h4 className="text-sm font-bold text-white">MAC Lattice Evaluator</h4>

              <div className="space-y-3">
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">Select Subject (User Clearance):</label>
                  <select
                    value={macUserId}
                    onChange={(e) => setMacUserId(Number(e.target.value))}
                    className="bg-slate-950 border border-slate-700 text-white text-xs px-3.5 py-2 rounded-xl w-full focus:outline-none focus:border-emerald-500"
                  >
                    <option value={101}>Alice Johnson (Clearance: CONFIDENTIAL - Level 3)</option>
                    <option value={103}>Charlie Davis (Clearance: INTERNAL - Level 2)</option>
                    <option value={108}>Henry Wilson (Clearance: PUBLIC - Level 1)</option>
                    <option value={401}>Dr. Aris Thorne (Clearance: SECRET - Level 4)</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">Select Target Resource (Classification):</label>
                  <select
                    value={macDocId}
                    onChange={(e) => setMacDocId(Number(e.target.value))}
                    className="bg-slate-950 border border-slate-700 text-white text-xs px-3.5 py-2 rounded-xl w-full focus:outline-none focus:border-emerald-500"
                  >
                    <option value={504}>Master HSM Key Rotation Policy (SECRET - Level 4)</option>
                    <option value={501}>Alice Tax Return (CONFIDENTIAL - Level 3)</option>
                    <option value={505}>Public Branch Operating Hours (PUBLIC - Level 1)</option>
                  </select>
                </div>

                <button
                  onClick={runMacSim}
                  disabled={macLoading}
                  className="w-full py-2.5 bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold rounded-xl transition flex items-center justify-center gap-2 shadow-lg shadow-emerald-900/30"
                >
                  {macLoading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Lock className="w-4 h-4" />}
                  Evaluate MAC Lattice Rule
                </button>
              </div>
            </div>

            <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl flex flex-col justify-between space-y-4">
              <div>
                <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-3">MAC Evaluation Result</h4>
                {macResult ? (
                  <div className="space-y-3">
                    <div className={`p-4 rounded-xl border flex items-center justify-between ${
                      macResult.decision === 'ALLOW' ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300' : 'bg-rose-500/10 border-rose-500/30 text-rose-300'
                    }`}>
                      <div className="flex items-center gap-3">
                        {macResult.decision === 'ALLOW' ? <CheckCircle className="w-6 h-6 text-emerald-400" /> : <XCircle className="w-6 h-6 text-rose-400" />}
                        <div>
                          <h5 className="font-bold text-sm">{macResult.decision}</h5>
                          <p className="text-xs opacity-90">{macResult.reason}</p>
                        </div>
                      </div>
                    </div>

                    <pre className="bg-slate-950 p-4 rounded-xl border border-slate-800 text-xs font-mono text-slate-300 overflow-x-auto">
                      {JSON.stringify(macResult, null, 2)}
                    </pre>
                  </div>
                ) : (
                  <div className="bg-slate-950 p-8 rounded-xl border border-slate-800 text-center text-slate-500 text-xs">
                    Click "Evaluate MAC Lattice Rule" to test clearance levels.
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
