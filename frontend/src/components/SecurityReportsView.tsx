import { useState, useEffect } from 'react';
import { FileText, Download, ShieldCheck, RefreshCw } from 'lucide-react';


const API_BASE = 'http://localhost:8000/api/v1';

export function SecurityReportsView() {
  const [report, setReport] = useState<any | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchReport = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/bank/report/executive`);
      if (res.ok) {
        const data = await res.json();
        setReport(data);
      }
    } catch {
      // silent
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchReport();
  }, []);

  const handlePrint = () => {
    window.print();
  };

  return (
    <div className="space-y-6">
      <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-amber-500/10 border border-amber-500/20 text-amber-400 rounded-xl">
            <FileText className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-white">Executive Security & Compliance Reports</h2>
            <p className="text-xs text-slate-400">Automated Security Auditing & Defense Capability Assessment</p>
          </div>
        </div>

        <div className="flex gap-2">
          <button
            onClick={fetchReport}
            className="px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-xl transition flex items-center gap-2 border border-slate-700"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Re-evaluate Score
          </button>
          <button
            onClick={handlePrint}
            className="px-3.5 py-2 bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-bold rounded-xl transition flex items-center gap-2 shadow-lg shadow-cyan-900/30"
          >
            <Download className="w-3.5 h-3.5" />
            Export Executive Report (PDF)
          </button>
        </div>
      </div>

      {loading ? (
        <div className="p-12 text-center text-slate-500 text-xs">Generating Executive Security Assessment...</div>
      ) : report ? (
        <div className="bg-slate-900 border border-slate-800 p-8 rounded-2xl space-y-8 print:bg-white print:text-black">
          {/* Header Summary */}
          <div className="flex flex-col md:flex-row justify-between items-start md:items-center border-b border-slate-800 pb-6 gap-4">
            <div>
              <span className="text-xs font-bold text-cyan-400 uppercase tracking-widest">{report.target_application}</span>
              <h1 className="text-2xl font-extrabold text-white mt-1">{report.title}</h1>
              <p className="text-xs text-slate-400 mt-1">{report.testing_scope}</p>
            </div>

            {/* Score Badge */}
            <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 text-center min-w-[200px]">
              <span className="text-[10px] font-bold uppercase text-slate-400 block">Security Score</span>
              <div className="text-3xl font-extrabold text-cyan-400 mt-1">
                {report.security_score} <span className="text-sm font-normal text-slate-500">/ 100</span>
              </div>
              <span className={`text-[10px] font-bold block mt-1 ${report.mode === 'secure' ? 'text-emerald-400' : 'text-rose-400'}`}>
                {report.score_label}
              </span>
            </div>
          </div>

          {/* Key Metric Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="bg-slate-950 p-5 rounded-xl border border-slate-800">
              <span className="text-xs font-bold text-slate-400 block uppercase">Decisions Evaluated</span>
              <span className="text-2xl font-bold text-white mt-1 block">{report.decisions_evaluated}</span>
            </div>

            <div className="bg-slate-950 p-5 rounded-xl border border-slate-800">
              <span className="text-xs font-bold text-rose-400 block uppercase">Blocked Unauthorized Requests</span>
              <span className="text-2xl font-bold text-rose-300 mt-1 block">{report.blocked_attacks}</span>
            </div>

            <div className="bg-slate-950 p-5 rounded-xl border border-slate-800">
              <span className="text-xs font-bold text-emerald-400 block uppercase">Authorized Requests Passed</span>
              <span className="text-2xl font-bold text-emerald-300 mt-1 block">{report.authorized_requests}</span>
            </div>
          </div>

          {/* Detailed Findings Table */}
          <div className="space-y-4">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider">OWASP Authorization Findings Status</h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {Object.entries(report.findings_summary).map(([key, val]: [string, any]) => (
                <div key={key} className="bg-slate-950 p-5 rounded-xl border border-slate-800 space-y-2">
                  <div className="flex justify-between items-center">
                    <span className="text-xs font-bold text-slate-400 uppercase">{key.toUpperCase()}</span>
                    <span className={`px-2 py-0.5 text-[10px] font-bold rounded ${
                      val.status === 'FIXED' ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30' : 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                    }`}>
                      {val.status}
                    </span>
                  </div>
                  <h4 className="font-bold text-white text-sm">{val.title}</h4>
                  <p className="text-xs text-slate-400">Severity: <strong className="text-rose-400">{val.severity}</strong></p>
                </div>
              ))}
            </div>
          </div>

          {/* Attacker Console Reconnaissance Summary */}
          <div className="bg-slate-950 p-6 rounded-xl border border-slate-800 space-y-3 text-xs text-slate-300">
            <h3 className="font-bold text-white text-sm flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-cyan-400" />
              Attacker Console Findings & Reconnaissance Analysis (Phase 6)
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-slate-400">
              <div className="bg-slate-900 p-3 rounded-lg border border-slate-800 space-y-1">
                <span className="font-bold text-rose-400 block">Capture ➔ Tamper ➔ Replay Pipeline</span>
                <p className="text-[11px]">Interception proves that client-supplied IDs (`/users/102`) and body keys (`"role":"ADMIN"`) are easily tampered via proxy tools. Server-side ownership and property whitelisting are mandatory.</p>
              </div>
              <div className="bg-slate-900 p-3 rounded-lg border border-slate-800 space-y-1">
                <span className="font-bold text-amber-400 block">Secondary Finding: OWASP API2:2023</span>
                <p className="text-[11px]">Identified predictable session credentials ('token_&lt;user&gt;'). Recommended paper mitigation: Migrate to signed JWTs with expiration claims.</p>

              </div>
            </div>
          </div>

          {/* Mitigation Architecture */}
          <div className="bg-slate-950 p-6 rounded-xl border border-slate-800 space-y-3 text-xs text-slate-300">
            <h3 className="font-bold text-white text-sm flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              Mitigation Architecture & Defense-in-Depth Summary
            </h3>
            <ul className="list-disc list-inside space-y-1.5 text-slate-400">
              <li><strong>Complete Server Mediation:</strong> Authorization decisions are strictly computed on the backend server.</li>
              <li><strong>Object Ownership Validation:</strong> All resource accesses verify <code className="text-slate-200">user_id == owner_id</code>.</li>
              <li><strong>Property DTO Whitelisting:</strong> Privilege properties (<code className="text-slate-200">role</code>, <code className="text-slate-200">balance</code>) are filtered via strict input DTO schemas.</li>
              <li><strong>Hybrid Control Integration:</strong> RBAC, ABAC, and MAC policies are unified in a central authorization engine.</li>
            </ul>
          </div>


          <div className="text-center text-[10px] text-slate-500 border-t border-slate-800 pt-4">
            {report.disclaimer} • Generated at {new Date(report.generated_at).toLocaleString()}
          </div>
        </div>
      ) : null}
    </div>
  );
}
