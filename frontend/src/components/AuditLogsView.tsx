import { useState, useEffect } from 'react';
import { ShieldCheck, RefreshCw, Trash2, CheckCircle, XCircle } from 'lucide-react';


const API_BASE = 'http://localhost:8000/api/v1';

export function AuditLogsView() {
  const [logs, setLogs] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchLogs = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/bank/logs/decisions`);
      if (res.ok) {
        const data = await res.json();
        setLogs(data.logs || []);
      }
    } catch {
      // silent
    } finally {
      setLoading(false);
    }
  };

  const clearLogs = async () => {
    try {
      await fetch(`${API_BASE}/bank/logs/decisions`, { method: 'DELETE' });
      setLogs([]);
    } catch {
      // silent
    }
  };

  useEffect(() => {
    fetchLogs();
  }, []);

  return (
    <div className="space-y-6">
      <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 rounded-xl">
            <ShieldCheck className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-white">Security Authorization Audit Logs</h2>
            <p className="text-xs text-slate-400">Complete immutable record of all server-side authorization decisions</p>
          </div>
        </div>

        <div className="flex gap-2">
          <button
            onClick={fetchLogs}
            className="px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-xl transition flex items-center gap-2 border border-slate-700"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <button
            onClick={clearLogs}
            className="px-3.5 py-2 bg-rose-950/40 hover:bg-rose-900/60 text-rose-300 text-xs font-semibold rounded-xl transition flex items-center gap-2 border border-rose-800"
          >
            <Trash2 className="w-3.5 h-3.5" />
            Clear Audit Trail
          </button>
        </div>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden">
        {loading ? (
          <div className="p-12 text-center text-slate-500 text-xs">Loading decision logs...</div>
        ) : logs.length === 0 ? (
          <div className="p-12 text-center text-slate-500 text-xs">No decision logs recorded yet. Perform actions in the Attack Lab to trigger logs.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="bg-slate-950 border-b border-slate-800 text-slate-400 font-bold uppercase tracking-wider">
                  <th className="p-4">Timestamp</th>
                  <th className="p-4">User</th>
                  <th className="p-4">Role</th>
                  <th className="p-4">Endpoint</th>
                  <th className="p-4">Policy Layer</th>
                  <th className="p-4 text-center">Decision</th>
                  <th className="p-4">Policy Reason</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {logs.map((log, idx) => {
                  const isAllow = log.decision === 'ALLOW';

                  return (
                    <tr key={idx} className="hover:bg-slate-800/40 transition">
                      <td className="p-4 text-slate-400">{new Date(log.timestamp).toLocaleTimeString()}</td>
                      <td className="p-4 font-bold text-white">{log.username || `User #${log.user_id}`}</td>
                      <td className="p-4 text-cyan-400">{log.user_role}</td>
                      <td className="p-4 text-slate-200">{log.endpoint || 'N/A'}</td>
                      <td className="p-4"><span className="px-2 py-0.5 bg-slate-800 border border-slate-700 text-slate-300 rounded text-[10px]">{log.policy}</span></td>
                      <td className="p-4 text-center">
                        <span className={`px-2.5 py-1 rounded-full font-bold flex items-center justify-center gap-1 text-[11px] ${
                          isAllow ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30' : 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                        }`}>
                          {isAllow ? <CheckCircle className="w-3 h-3 text-emerald-400" /> : <XCircle className="w-3 h-3 text-rose-400" />}
                          {log.decision} ({log.status_code})
                        </span>
                      </td>
                      <td className="p-4 text-slate-300 text-[11px] font-sans max-w-xs truncate">{log.reason}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
