export interface Finding {
  id: string;
  title: string;
  vulnerability_class: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  cvss_score: number;
  cvss_vector: string;
  endpoint_path: string;
  http_method: string;
  owasp_category: string;
  cve_analog: string;
  description: string;
  curl_reproduction: string;
  remediation_snippets: Record<string, string>;
  original_payload?: unknown;
  bypass_payload?: unknown;
}

export interface User {
  id: number;
  name: string;
  role: string;
  email: string;
  department: string;
  region: string;
  clearance: string;
  accountBalance: number;
  internalRiskScore?: number;
  isVerified?: boolean;
  token?: string;
}


import { useState, useEffect } from 'react';
import {
  Shield,
  LayoutDashboard,
  Zap,
  Grid,
  Users,
  FileText,
  AlertTriangle,
  ChevronDown,
  Activity,
  Layers,
  Info,
  CheckCircle,
  Terminal,
} from 'lucide-react';

import { AttackLabView } from './components/AttackLabView';
import { AttackerConsoleView } from './components/AttackerConsoleView';
import { AccessControlView } from './components/AccessControlView';
import { ResearchBenchmarkView } from './components/ResearchBenchmarkView';

import { AuthzMatrixView } from './components/AuthzMatrixView';
import { UsersView } from './components/UsersView';
import { AuditLogsView } from './components/AuditLogsView';
import { SecurityReportsView } from './components/SecurityReportsView';
import { IncidentSimulatorView } from './components/IncidentSimulatorView';

const API_BASE = 'http://localhost:8000/api/v1';

export function App() {

  const [activeTab, setActiveTab] = useState<
    'DASHBOARD' | 'ATTACK_LAB' | 'ATTACKER_CONSOLE' | 'RESEARCH_LAB' | 'ACCESS_CONTROL' | 'MATRIX' | 'USERS' | 'LOGS' | 'REPORTS' | 'SIMULATOR'
  >('DASHBOARD');


  // Application security mode ('vulnerable' | 'secure')
  const [securityMode, setSecurityMode] = useState<'vulnerable' | 'secure'>('vulnerable');

  // Synthetic users list & current user identity
  const [usersList, setUsersList] = useState<any[]>([]);
  const [currentUser, setCurrentUser] = useState<any>({
    id: 101,
    name: 'Alice Johnson',
    role: 'CUSTOMER',
    department: 'Retail Banking',
    region: 'South',
    clearance: 'CONFIDENTIAL',
    accountBalance: 75000,
    token: 'token_alice',
  });

  const [engineHealthy, setEngineHealthy] = useState<boolean | null>(null);
  const [showUserDropdown, setShowUserDropdown] = useState(false);

  // Fetch security mode and users on mount
  useEffect(() => {
    const initApp = async () => {
      try {
        const modeRes = await fetch(`${API_BASE}/bank/mode`);
        if (modeRes.ok) {
          const modeData = await modeRes.json();
          setSecurityMode(modeData.mode || 'vulnerable');
          setEngineHealthy(true);
        }

        const usersRes = await fetch(`${API_BASE}/bank/users`);
        if (usersRes.ok) {
          const usersData = await usersRes.json();
          setUsersList(usersData.users || []);
          if (usersData.users && usersData.users.length > 0) {
            // Default to Alice (101)
            const alice = usersData.users.find((u: any) => u.id === 101) || usersData.users[0];
            setCurrentUser(alice);
          }
        }
      } catch {
        setEngineHealthy(false);
      }
    };
    initApp();
  }, []);

  // Toggle Security Mode on Server & Client
  const handleToggleMode = async (newMode: 'vulnerable' | 'secure') => {
    try {
      const res = await fetch(`${API_BASE}/bank/mode`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: newMode }),
      });
      if (res.ok) {
        const data = await res.json();
        setSecurityMode(data.mode);
      }
    } catch {
      // silent fallback
      setSecurityMode(newMode);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 font-sans selection:bg-rose-500 selection:text-white flex flex-col">
      {/* Top Header */}
      <header className="bg-slate-900/90 backdrop-blur-md border-b border-slate-800 sticky top-0 z-40 px-6 py-3.5 flex items-center justify-between">
        {/* Brand */}
        <div className="flex items-center gap-3">
          <div className="p-2 bg-gradient-to-tr from-rose-500 to-amber-500 text-white rounded-xl shadow-lg shadow-rose-900/20">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-base font-extrabold text-white tracking-tight">AuthzGraph</h1>
              <span className="px-2 py-0.5 text-[10px] font-bold bg-slate-800 text-cyan-400 border border-slate-700 rounded-md">
                SecureBank Demo
              </span>
            </div>
            <p className="text-[11px] text-slate-400">Automated API Authorization Tester & Security Platform</p>
          </div>
        </div>

        {/* Global Controls & User Switcher */}
        <div className="flex items-center gap-4">
          {/* Mode Toggle Switcher */}
          <button
            onClick={() => handleToggleMode(securityMode === 'vulnerable' ? 'secure' : 'vulnerable')}
            className={`px-3.5 py-1.5 rounded-xl text-xs font-bold transition flex items-center gap-2 border shadow-lg ${
              securityMode === 'vulnerable'
                ? 'bg-rose-500/20 text-rose-300 border-rose-500/40 hover:bg-rose-500/30 shadow-rose-950/40'
                : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40 hover:bg-emerald-500/30 shadow-emerald-950/40'
            }`}
          >
            {securityMode === 'vulnerable' ? (
              <>
                <AlertTriangle className="w-4 h-4 text-rose-400" />
                <span>⚠️ VULNERABLE MODE</span>
              </>
            ) : (
              <>
                <CheckCircle className="w-4 h-4 text-emerald-400" />
                <span>🛡️ SECURE MODE</span>
              </>
            )}
          </button>

          {/* Quick Identity Switcher Dropdown */}
          <div className="relative">
            <button
              onClick={() => setShowUserDropdown(!showUserDropdown)}
              className="flex items-center gap-2 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-white rounded-xl text-xs transition"
            >
              <div className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
              <div className="text-left">
                <span className="font-bold block text-[11px] leading-tight">{currentUser.name}</span>
                <span className="text-[9px] text-slate-400 font-mono">[{currentUser.role}]</span>
              </div>
              <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
            </button>

            {showUserDropdown && (
              <div className="absolute right-0 mt-2 w-64 bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl p-2 z-50 space-y-1">
                <div className="px-3 py-1.5 text-[10px] font-bold text-slate-400 uppercase tracking-wider">
                  Switch Demo Identity
                </div>
                {usersList.slice(0, 7).map((u) => (
                  <button
                    key={u.id}
                    onClick={() => {
                      setCurrentUser(u);
                      setShowUserDropdown(false);
                    }}
                    className={`w-full text-left px-3 py-2 rounded-xl text-xs flex items-center justify-between transition ${
                      currentUser.id === u.id ? 'bg-cyan-500/20 text-cyan-300 font-bold' : 'hover:bg-slate-800 text-slate-300'
                    }`}
                  >
                    <span>{u.name}</span>
                    <span className="text-[10px] font-mono px-1.5 py-0.5 bg-slate-800 rounded text-slate-400">{u.role}</span>
                  </button>
                ))}
              </div>
            )}
          </div>

          {/* Engine Health Badge */}
          <div className="hidden md:flex items-center gap-2 text-xs bg-slate-900 border border-slate-800 px-3 py-1.5 rounded-xl">
            <span className={`w-2 h-2 rounded-full ${engineHealthy ? 'bg-emerald-400' : 'bg-rose-400'}`} />
            <span className="text-slate-400">{engineHealthy ? 'Engine Online' : 'Engine Offline'}</span>
          </div>
        </div>
      </header>

      {/* Educational Banner */}
      <div className="bg-gradient-to-r from-slate-900 via-rose-950/20 to-slate-900 border-b border-slate-800/80 px-6 py-2.5 text-xs text-center text-slate-300 flex items-center justify-center gap-2">
        <Info className="w-4 h-4 text-cyan-400 shrink-0" />
        <span>
          <strong>Central Educational Concept:</strong> "Authentication tells the application <em>WHO</em> the user is. Authorization determines <em>WHAT</em> that user is allowed to do."
        </span>
      </div>

      {/* Main Content Layout */}
      <div className="flex-1 flex overflow-hidden">
        {/* Sidebar Navigation */}
        <aside className="w-64 bg-slate-900/60 border-r border-slate-800/80 p-4 space-y-6 shrink-0 hidden md:block">
          <div className="space-y-1">
            <div className="px-3 text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-2">Platform Core</div>

            <button
              onClick={() => setActiveTab('DASHBOARD')}
              className={`w-full flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-xs font-semibold transition ${
                activeTab === 'DASHBOARD' ? 'bg-cyan-500/10 text-cyan-300 border border-cyan-500/20' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <LayoutDashboard className="w-4 h-4" />
              Security Dashboard
            </button>

            <button
              onClick={() => setActiveTab('ATTACK_LAB')}
              className={`w-full flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-xs font-semibold transition ${
                activeTab === 'ATTACK_LAB' ? 'bg-rose-500/10 text-rose-300 border border-rose-500/20' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <Zap className="w-4 h-4 text-rose-400" />
              Attack Lab (OWASP)
            </button>

            <button
              onClick={() => setActiveTab('ATTACKER_CONSOLE')}
              className={`w-full flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-xs font-semibold transition ${
                activeTab === 'ATTACKER_CONSOLE' ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40 font-bold' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <Terminal className="w-4 h-4 text-rose-400" />
              🕵 Attacker Console
            </button>

            <button
              onClick={() => setActiveTab('RESEARCH_LAB')}
              className={`w-full flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-xs font-semibold transition ${
                activeTab === 'RESEARCH_LAB' ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <Activity className="w-4 h-4 text-cyan-400" />
              📊 Research Benchmark Suite
            </button>


            <button
              onClick={() => setActiveTab('ACCESS_CONTROL')}
              className={`w-full flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-xs font-semibold transition ${
                activeTab === 'ACCESS_CONTROL' ? 'bg-indigo-500/10 text-indigo-300 border border-indigo-500/20' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <Layers className="w-4 h-4 text-indigo-400" />
              RBAC / ABAC / MAC Engine
            </button>

            <button
              onClick={() => setActiveTab('MATRIX')}
              className={`w-full flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-xs font-semibold transition ${
                activeTab === 'MATRIX' ? 'bg-blue-500/10 text-blue-300 border border-blue-500/20' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <Grid className="w-4 h-4 text-blue-400" />
              Authorization Matrix
            </button>
          </div>

          <div className="space-y-1">
            <div className="px-3 text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-2">Auditing & Data</div>

            <button
              onClick={() => setActiveTab('USERS')}
              className={`w-full flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-xs font-semibold transition ${
                activeTab === 'USERS' ? 'bg-cyan-500/10 text-cyan-300 border border-cyan-500/20' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <Users className="w-4 h-4 text-cyan-400" />
              Synthetic User Identities
            </button>

            <button
              onClick={() => setActiveTab('LOGS')}
              className={`w-full flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-xs font-semibold transition ${
                activeTab === 'LOGS' ? 'bg-emerald-500/10 text-emerald-300 border border-emerald-500/20' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <Activity className="w-4 h-4 text-emerald-400" />
              Security Audit Logs
            </button>

            <button
              onClick={() => setActiveTab('REPORTS')}
              className={`w-full flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-xs font-semibold transition ${
                activeTab === 'REPORTS' ? 'bg-amber-500/10 text-amber-300 border border-amber-500/20' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <FileText className="w-4 h-4 text-amber-400" />
              Executive Security Report
            </button>

            <button
              onClick={() => setActiveTab('SIMULATOR')}
              className={`w-full flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-xs font-semibold transition ${
                activeTab === 'SIMULATOR' ? 'bg-purple-500/10 text-purple-300 border border-purple-500/20' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <AlertTriangle className="w-4 h-4 text-purple-400" />
              Incident Walkthrough
            </button>
          </div>
        </aside>

        {/* Main Body View */}
        <main className="flex-1 overflow-y-auto p-6 space-y-6">
          {activeTab === 'DASHBOARD' && (
            <div className="space-y-6">
              {/* Dashboard Banner Cards */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div className="bg-slate-900 border border-slate-800 p-5 rounded-2xl space-y-2">
                  <span className="text-xs font-bold text-slate-400 uppercase">System Security Score</span>
                  <div className="text-3xl font-extrabold text-cyan-400">
                    {securityMode === 'secure' ? '96' : '32'}{' '}
                    <span className="text-xs text-slate-500 font-normal">/ 100</span>
                  </div>
                  <span className={`text-[10px] font-bold block ${securityMode === 'secure' ? 'text-emerald-400' : 'text-rose-400'}`}>
                    {securityMode === 'secure' ? '🛡️ CONTROLS ACTIVE' : '⚠️ VULNERABLE STATE'}
                  </span>
                </div>

                <div className="bg-slate-900 border border-slate-800 p-5 rounded-2xl space-y-2">
                  <span className="text-xs font-bold text-rose-400 uppercase">BOLA Risk Status</span>
                  <div className="text-xl font-bold text-white">
                    {securityMode === 'vulnerable' ? 'CRITICAL' : 'MITIGATED'}
                  </div>
                  <span className="text-[10px] text-slate-400 block">OWASP API1:2023 Object Level</span>
                </div>

                <div className="bg-slate-900 border border-slate-800 p-5 rounded-2xl space-y-2">
                  <span className="text-xs font-bold text-amber-400 uppercase">BOPLA Risk Status</span>
                  <div className="text-xl font-bold text-white">
                    {securityMode === 'vulnerable' ? 'HIGH RISK' : 'MITIGATED'}
                  </div>
                  <span className="text-[10px] text-slate-400 block">OWASP API3:2023 Property Level</span>
                </div>

                <div className="bg-slate-900 border border-slate-800 p-5 rounded-2xl space-y-2">
                  <span className="text-xs font-bold text-purple-400 uppercase">BFLA Risk Status</span>
                  <div className="text-xl font-bold text-white">
                    {securityMode === 'vulnerable' ? 'CRITICAL' : 'MITIGATED'}
                  </div>
                  <span className="text-[10px] text-slate-400 block">OWASP API5:2023 Function Level</span>
                </div>
              </div>

              {/* Action Prompt Cards */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl space-y-3">
                  <h3 className="font-bold text-white text-sm flex items-center gap-2">
                    <Zap className="w-4 h-4 text-rose-400" />
                    Authorization Attack Lab
                  </h3>
                  <p className="text-xs text-slate-400">
                    Perform controlled attacks against synthetic user objects, inspect live HTTP status codes, and toggle side-by-side mitigation.
                  </p>
                  <button
                    onClick={() => setActiveTab('ATTACK_LAB')}
                    className="px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white font-bold text-xs rounded-xl transition"
                  >
                    Open Attack Lab →
                  </button>
                </div>

                <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl space-y-3">
                  <h3 className="font-bold text-white text-sm flex items-center gap-2">
                    <Layers className="w-4 h-4 text-indigo-400" />
                    Access Control Simulators
                  </h3>
                  <p className="text-xs text-slate-400">
                    Evaluate formal RBAC role matrices, ABAC attribute matchers (department, region), and MAC sensitivity clearance lattices.
                  </p>
                  <button
                    onClick={() => setActiveTab('ACCESS_CONTROL')}
                    className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white font-bold text-xs rounded-xl transition"
                  >
                    Open Access Control →
                  </button>
                </div>

                <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl space-y-3">
                  <h3 className="font-bold text-white text-sm flex items-center gap-2">
                    <FileText className="w-4 h-4 text-amber-400" />
                    Executive Report Generator
                  </h3>
                  <p className="text-xs text-slate-400">
                    Generate an executive security audit report with security scoring, decision logs, and defense-in-depth mitigations.
                  </p>
                  <button
                    onClick={() => setActiveTab('REPORTS')}
                    className="px-4 py-2 bg-amber-600 hover:bg-amber-500 text-white font-bold text-xs rounded-xl transition"
                  >
                    Generate Executive Report →
                  </button>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'ATTACK_LAB' && (
            <AttackLabView currentUser={currentUser} securityMode={securityMode} onToggleMode={handleToggleMode} />
          )}

          {activeTab === 'ATTACKER_CONSOLE' && (
            <AttackerConsoleView currentUser={currentUser} securityMode={securityMode} onToggleMode={handleToggleMode} />
          )}

          {activeTab === 'RESEARCH_LAB' && <ResearchBenchmarkView />}

          {activeTab === 'ACCESS_CONTROL' && <AccessControlView />}


          {activeTab === 'MATRIX' && <AuthzMatrixView />}

          {activeTab === 'USERS' && (
            <UsersView
              users={usersList}
              currentUser={currentUser}
              onSelectUser={(u) => setCurrentUser(u)}
            />
          )}

          {activeTab === 'LOGS' && <AuditLogsView />}

          {activeTab === 'REPORTS' && <SecurityReportsView />}

          {activeTab === 'SIMULATOR' && <IncidentSimulatorView />}
        </main>
      </div>
    </div>
  );
}

export default App;

