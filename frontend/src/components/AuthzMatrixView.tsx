import { useState, useEffect } from 'react';
import { Grid, Info } from 'lucide-react';


const API_BASE = 'http://localhost:8000/api/v1';

export function AuthzMatrixView() {
  const [matrix, setMatrix] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedCell, setSelectedCell] = useState<{ endpoint: string; role: string; decision: string } | null>(null);

  useEffect(() => {
    const fetchMatrix = async () => {
      try {
        const res = await fetch(`${API_BASE}/bank/matrix`);
        if (res.ok) {
          const data = await res.json();
          setMatrix(data.matrix || []);
        }
      } catch (err) {
        // silent
      } finally {
        setLoading(false);
      }
    };
    fetchMatrix();
  }, []);

  return (
    <div className="space-y-6">
      <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-blue-500/10 border border-blue-500/20 text-blue-400 rounded-xl">
            <Grid className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-white">Interactive Authorization Matrix</h2>
            <p className="text-xs text-slate-400">Complete permission grid mapping API Endpoints against User Roles (CUSTOMER, SUPPORT, MANAGER, ADMIN)</p>
          </div>
        </div>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden">
        {loading ? (
          <div className="p-12 text-center text-slate-500 text-xs">Loading authorization matrix...</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="bg-slate-950 border-b border-slate-800 text-slate-400 font-bold uppercase tracking-wider">
                  <th className="p-4">Method</th>
                  <th className="p-4">API Endpoint Path</th>
                  <th className="p-4 text-center">CUSTOMER</th>
                  <th className="p-4 text-center">SUPPORT</th>
                  <th className="p-4 text-center">MANAGER</th>
                  <th className="p-4 text-center">ADMIN</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {matrix.map((row, idx) => (
                  <tr key={idx} className="hover:bg-slate-800/40 transition">
                    <td className="p-4 font-bold text-cyan-400">{row.method}</td>
                    <td className="p-4 text-slate-200">{row.endpoint}</td>

                    {['CUSTOMER', 'SUPPORT', 'MANAGER', 'ADMIN'].map((role) => {
                      const dec = row[role] || 'DENY';
                      const isAllow = dec.includes('ALLOW');

                      return (
                        <td
                          key={role}
                          onClick={() => setSelectedCell({ endpoint: row.endpoint, role, decision: dec })}
                          className={`p-4 text-center cursor-pointer transition ${
                            isAllow ? 'bg-emerald-500/10 text-emerald-300 font-bold hover:bg-emerald-500/20' : 'bg-rose-500/10 text-rose-400 hover:bg-rose-500/20'
                          }`}
                        >
                          {dec}
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Selected Cell Modal / Details */}
      {selectedCell && (
        <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl space-y-2 text-xs">
          <div className="flex justify-between items-center">
            <h4 className="font-bold text-white text-sm flex items-center gap-2">
              <Info className="w-4 h-4 text-cyan-400" />
              Policy Detail: {selectedCell.endpoint} for Role [{selectedCell.role}]
            </h4>
            <button onClick={() => setSelectedCell(null)} className="text-slate-400 hover:text-white">✕</button>
          </div>
          <p className="text-slate-300">
            Decision: <strong className="text-cyan-300">{selectedCell.decision}</strong>. Access control policy enforces role permission matrix and ownership validation server-side.
          </p>
        </div>
      )}
    </div>
  );
}
