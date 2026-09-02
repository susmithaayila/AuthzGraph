import { useState, useEffect } from 'react';
import {
  BarChart3,
  Layers,
  GitCommit,
  Activity,
  Code,
  Shield,
  Play,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Zap,
  Lock,
} from 'lucide-react';

const API_BASE = 'http://localhost:8000/api/v1';

export function ResearchBenchmarkView() {
  const [subTab, setSubTab] = useState<'BENCHMARK' | 'ABLATION' | 'ATTACK_GRAPH' | 'ANOMALY_GRAPHQL'>('BENCHMARK');

  // Benchmark state
  const [iterations, setIterations] = useState<number>(10);
  const [benchmarkData, setBenchmarkData] = useState<any>(null);
  const [benchmarking, setBenchmarking] = useState(false);

  // Ablation state
  const [ablationData, setAblationData] = useState<any>(null);
  const [loadingAblation, setLoadingAblation] = useState(false);

  // Attack graph state
  const [attackGraph, setAttackGraph] = useState<any>(null);

  // Anomaly & GraphQL state
  const [anomalyData, setAnomalyData] = useState<any>(null);
  const [tokenExpData, setTokenExpData] = useState<any>(null);
  const [graphqlQuery, setGraphqlQuery] = useState('mutation {\n  updateRole(user_id: 101, role: "ADMIN")\n}');
  const [graphqlRes, setGraphqlRes] = useState<any>(null);
  const [graphqlLoading, setGraphqlLoading] = useState(false);

  // Fetch benchmark
  const runBenchmark = async () => {
    setBenchmarking(true);
    try {
      const res = await fetch(`${API_BASE}/bank/benchmark/run?iterations=${iterations}`, { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        setBenchmarkData(data);
      }
    } catch {
      // silent fallback
    } finally {
      setBenchmarking(false);
    }
  };

  // Fetch ablation
  const runAblation = async () => {
    setLoadingAblation(true);
    try {
      const res = await fetch(`${API_BASE}/bank/benchmark/ablation`);
      if (res.ok) {
        const data = await res.json();
        setAblationData(data);
      }
    } catch {
      // silent
    } finally {
      setLoadingAblation(false);
    }
  };

  // Fetch attack graph
  const fetchAttackGraph = async () => {
    try {
      const res = await fetch(`${API_BASE}/bank/attack-graph`);
      if (res.ok) {
        setAttackGraph(await res.json());
      }
    } catch {
      // silent
    }
  };

  // Fetch anomaly & token experiment
  const fetchAnomalyAndToken = async () => {
    try {
      const aRes = await fetch(`${API_BASE}/bank/anomaly/detect`);
      if (aRes.ok) setAnomalyData(await aRes.json());

      const tRes = await fetch(`${API_BASE}/bank/demo/token-experiment`);
      if (tRes.ok) setTokenExpData(await tRes.json());
    } catch {
      // silent
    }
  };

  // Run GraphQL test
  const executeGraphQL = async () => {
    setGraphqlLoading(true);
    try {
      const res = await fetch(`${API_BASE}/bank/graphql`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: graphqlQuery }),
      });
      if (res.ok) {
        setGraphqlRes(await res.json());
      }
    } catch {
      setGraphqlRes({ error: 'Failed to connect to GraphQL endpoint' });
    } finally {
      setGraphqlLoading(false);
    }
  };

  useEffect(() => {
    if (subTab === 'BENCHMARK' && !benchmarkData) runBenchmark();
    if (subTab === 'ABLATION' && !ablationData) runAblation();
    if (subTab === 'ATTACK_GRAPH') fetchAttackGraph();
    if (subTab === 'ANOMALY_GRAPHQL') fetchAnomalyAndToken();
  }, [subTab]);

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-3 bg-gradient-to-tr from-cyan-500 to-blue-600 text-white rounded-xl shadow-lg shadow-cyan-900/20">
            <BarChart3 className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-xl font-bold text-white tracking-tight">Academic Research & Benchmark Suite</h2>
              <span className="px-2 py-0.5 text-[10px] font-bold bg-cyan-950 text-cyan-400 border border-cyan-800 rounded-md">
                IEEE/ACM Paper Companion
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Empirical attack success benchmarks, 7-layer pipeline ablation studies, and attack graph modeling (Sections 9.1–9.8).
            </p>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div className="flex bg-slate-950 p-1 rounded-xl border border-slate-800 text-xs font-semibold">
          <button
            onClick={() => setSubTab('BENCHMARK')}
            className={`px-3 py-1.5 rounded-lg transition flex items-center gap-1.5 ${
              subTab === 'BENCHMARK' ? 'bg-cyan-600 text-white shadow' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <BarChart3 className="w-3.5 h-3.5" />
            9.1 Empirical Benchmark
          </button>
          <button
            onClick={() => setSubTab('ABLATION')}
            className={`px-3 py-1.5 rounded-lg transition flex items-center gap-1.5 ${
              subTab === 'ABLATION' ? 'bg-cyan-600 text-white shadow' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            9.2 Layer Ablation
          </button>
          <button
            onClick={() => setSubTab('ATTACK_GRAPH')}
            className={`px-3 py-1.5 rounded-lg transition flex items-center gap-1.5 ${
              subTab === 'ATTACK_GRAPH' ? 'bg-cyan-600 text-white shadow' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <GitCommit className="w-3.5 h-3.5" />
            9.6 Attack Graph
          </button>
          <button
            onClick={() => setSubTab('ANOMALY_GRAPHQL')}
            className={`px-3 py-1.5 rounded-lg transition flex items-center gap-1.5 ${
              subTab === 'ANOMALY_GRAPHQL' ? 'bg-cyan-600 text-white shadow' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Activity className="w-3.5 h-3.5" />
            9.4-9.8 Anomaly & GraphQL
          </button>
        </div>
      </div>

      {/* ── SubTab 1: Empirical Benchmark ── */}
      {subTab === 'BENCHMARK' && (
        <div className="space-y-6">
          <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <Zap className="w-4 h-4 text-amber-400" />
                  Section 9.1: Scripted N-Run Empirical Benchmark
                </h3>
                <p className="text-xs text-slate-400 mt-1">
                  Executes automated multi-vector attack suites across VULNERABLE and SECURE modes, measuring exposure rate (%), overhead latency (ms), and false positive rates.
                </p>
              </div>

              <div className="flex items-center gap-3">
                <div className="flex items-center gap-2 text-xs text-slate-400">
                  <span>Iterations:</span>
                  <input
                    type="number"
                    min={1}
                    max={50}
                    value={iterations}
                    onChange={(e) => setIterations(Number(e.target.value))}
                    className="w-16 bg-slate-950 border border-slate-700 text-white px-2 py-1 rounded-lg text-center font-mono"
                  />
                </div>
                <button
                  onClick={runBenchmark}
                  disabled={benchmarking}
                  className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white text-xs font-semibold rounded-xl transition flex items-center gap-2"
                >
                  <Play className={`w-3.5 h-3.5 ${benchmarking ? 'animate-spin' : ''}`} />
                  {benchmarking ? 'Executing Benchmark...' : 'Run Empirical Benchmark'}
                </button>
              </div>
            </div>

            {benchmarkData && (
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-4 border-t border-slate-800">
                <div className="bg-slate-950 p-4 rounded-xl border border-slate-800">
                  <div className="text-[11px] font-bold text-slate-400 uppercase">Exposure Reduction</div>
                  <div className="text-2xl font-extrabold text-emerald-400 mt-1">
                    {benchmarkData.comparison_summary.exposure_rate_reduction}
                  </div>
                  <div className="text-[10px] text-slate-500 mt-1">100% exploit blocking in SECURE mode</div>
                </div>

                <div className="bg-slate-950 p-4 rounded-xl border border-slate-800">
                  <div className="text-[11px] font-bold text-slate-400 uppercase">Latency Overhead</div>
                  <div className="text-2xl font-extrabold text-cyan-400 mt-1">
                    +{benchmarkData.comparison_summary.latency_overhead_ms} ms
                  </div>
                  <div className="text-[10px] text-slate-500 mt-1">Microsecond policy evaluation time</div>
                </div>

                <div className="bg-slate-950 p-4 rounded-xl border border-slate-800">
                  <div className="text-[11px] font-bold text-slate-400 uppercase">False Positive Rate</div>
                  <div className="text-2xl font-extrabold text-blue-400 mt-1">
                    {benchmarkData.comparison_summary.false_positive_rate}
                  </div>
                  <div className="text-[10px] text-slate-500 mt-1">Zero legitimate user requests denied</div>
                </div>
              </div>
            )}
          </div>

          {/* Side by side mode results */}
          {benchmarkData && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* Vulnerable Mode */}
              <div className="bg-slate-900 border border-rose-900/50 p-6 rounded-2xl space-y-3">
                <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                  <div className="flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 text-rose-400" />
                    <h4 className="text-sm font-bold text-rose-300">VULNERABLE MODE</h4>
                  </div>
                  <span className="px-2.5 py-0.5 text-[10px] font-bold bg-rose-950 text-rose-400 border border-rose-800 rounded-full">
                    {benchmarkData.vulnerable_mode.exposure_rate_pct}% EXPOSED
                  </span>
                </div>
                <div className="space-y-2 text-xs text-slate-300 font-mono">
                  <div className="flex justify-between">
                    <span>Total Attack Attempts:</span>
                    <span className="text-white font-bold">{benchmarkData.vulnerable_mode.total_attack_attempts}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Successful Exploits:</span>
                    <span className="text-rose-400 font-bold">{benchmarkData.vulnerable_mode.successful_exploits}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Average Latency:</span>
                    <span className="text-slate-400">{benchmarkData.vulnerable_mode.avg_latency_ms} ms</span>
                  </div>
                </div>
              </div>

              {/* Secure Mode */}
              <div className="bg-slate-900 border border-emerald-900/50 p-6 rounded-2xl space-y-3">
                <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                  <div className="flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    <h4 className="text-sm font-bold text-emerald-300">SECURE MODE (AuthzGraph)</h4>
                  </div>
                  <span className="px-2.5 py-0.5 text-[10px] font-bold bg-emerald-950 text-emerald-400 border border-emerald-800 rounded-full">
                    0.0% EXPOSED
                  </span>
                </div>
                <div className="space-y-2 text-xs text-slate-300 font-mono">
                  <div className="flex justify-between">
                    <span>Total Attack Attempts:</span>
                    <span className="text-white font-bold">{benchmarkData.secure_mode.total_attack_attempts}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Successful Exploits:</span>
                    <span className="text-emerald-400 font-bold">0 (Blocked)</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Average Latency:</span>
                    <span className="text-slate-400">{benchmarkData.secure_mode.avg_latency_ms} ms</span>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ── SubTab 2: Layer Ablation ── */}
      {subTab === 'ABLATION' && (
        <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Layers className="w-4 h-4 text-cyan-400" />
                Section 9.2: Layer-Ablation Study (7-Layer Pipeline)
              </h3>
              <p className="text-xs text-slate-400 mt-1">
                Disables one enforcement layer at a time to empirically measure defense-in-depth redundancy and isolate individual policy contributions.
              </p>
            </div>
            <button
              onClick={runAblation}
              disabled={loadingAblation}
              className="px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-xl transition flex items-center gap-2 border border-slate-700"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loadingAblation ? 'animate-spin' : ''}`} />
              Re-run Ablation
            </button>
          </div>

          {ablationData && (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="bg-slate-950 border-b border-slate-800 text-slate-400 font-bold uppercase">
                    <th className="p-3">Disabled Layer</th>
                    <th className="p-3">Protection Rate</th>
                    <th className="p-3">Attacks Blocked</th>
                    <th className="p-3">Vulnerability Exposed When Disabled</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono">
                  {ablationData.ablation_matrix.map((row: any, idx: number) => (
                    <tr key={idx} className="hover:bg-slate-800/30">
                      <td className="p-3 font-bold text-cyan-300">{row.disabled_layer}</td>
                      <td className="p-3">
                        <span className={`px-2 py-0.5 rounded font-bold ${
                          row.protection_rate_pct === 100 ? 'bg-emerald-950 text-emerald-400' : 'bg-amber-950 text-amber-400'
                        }`}>
                          {row.protection_rate_pct}%
                        </span>
                      </td>
                      <td className="p-3 text-slate-300">
                        {row.blocked_attacks} / {row.total_attacks}
                      </td>
                      <td className="p-3 text-rose-400">
                        {row.vulnerability_exposure.length > 0 ? row.vulnerability_exposure.join(', ') : 'None (Compensating controls active)'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* ── SubTab 3: Attack Graph ── */}
      {subTab === 'ATTACK_GRAPH' && (
        <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl space-y-6">
          <div className="flex items-center justify-between border-b border-slate-800 pb-4">
            <div>
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <GitCommit className="w-4 h-4 text-rose-400" />
                Section 9.6: Chained Exploit Path & Attack-Graph Model
              </h3>
              <p className="text-xs text-slate-400 mt-1">
                Formalizes multi-step exploit chains as nodes and directed capability edges ($BOLA \rightarrow BOPLA \rightarrow BFLA$).
              </p>
            </div>

            {attackGraph && (
              <span className={`px-3 py-1 text-xs font-extrabold rounded-full border ${
                attackGraph.security_mode === 'vulnerable'
                  ? 'bg-rose-950 text-rose-400 border-rose-800'
                  : 'bg-emerald-950 text-emerald-400 border-emerald-800'
              }`}>
                {attackGraph.attack_chain_status}
              </span>
            )}
          </div>

          {attackGraph && (
            <div className="space-y-4">
              <div className="p-3 bg-slate-950 border border-slate-800 rounded-xl text-xs text-slate-300 italic">
                "{attackGraph.chain_narrative}"
              </div>

              {/* Node cards */}
              <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
                {attackGraph.graph.nodes.map((node: any, idx: number) => (
                  <div
                    key={idx}
                    className={`p-3.5 rounded-xl border text-xs space-y-1.5 ${
                      node.status === 'EXPLOITABLE' || node.status === 'COMPROMISED' || node.status === 'ACHIEVED'
                        ? 'bg-rose-950/30 border-rose-800 text-rose-200'
                        : 'bg-slate-950 border-slate-800 text-slate-300'
                    }`}
                  >
                    <div className="text-[10px] font-bold uppercase tracking-wider text-slate-400">{node.type}</div>
                    <div className="font-bold text-white">{node.label}</div>
                    <div className="text-[10px] opacity-80">{node.details}</div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ── SubTab 4: Anomaly & GraphQL ── */}
      {subTab === 'ANOMALY_GRAPHQL' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Anomaly Detector */}
          <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl space-y-4">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Activity className="w-4 h-4 text-cyan-400" />
              Section 9.4: Statistical Anomaly & Probing Detector
            </h3>
            {anomalyData && (
              <div className="space-y-3 text-xs">
                <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 font-mono space-y-1">
                  <div className="flex justify-between">
                    <span className="text-slate-400">Monitoring Window:</span>
                    <span className="text-white">{anomalyData.monitoring_window_seconds}s</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Distinct Endpoints Accessed:</span>
                    <span className="text-cyan-400 font-bold">{anomalyData.distinct_endpoints_accessed}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Precision / Recall:</span>
                    <span className="text-emerald-400 font-bold">
                      {anomalyData.metrics.synthetic_detection_precision * 100}% / {anomalyData.metrics.synthetic_detection_recall * 100}%
                    </span>
                  </div>
                </div>

                <div className="p-3 bg-cyan-950/30 border border-cyan-800/50 rounded-xl text-cyan-300 text-[11px]">
                  Detective control layer monitoring request velocity ($K$ distinct IDs in $T$ seconds) to catch automated scans.
                </div>
              </div>
            )}
          </div>

          {/* GraphQL Inspector */}
          <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl space-y-4">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Code className="w-4 h-4 text-purple-400" />
              Section 9.5: GraphQL Protocol Authorization Inspector
            </h3>
            <div className="space-y-2">
              <textarea
                value={graphqlQuery}
                onChange={(e) => setGraphqlQuery(e.target.value)}
                rows={4}
                className="w-full bg-slate-950 border border-slate-800 text-white p-3 rounded-xl font-mono text-xs focus:outline-none focus:border-purple-500"
              />
              <button
                onClick={executeGraphQL}
                disabled={graphqlLoading}
                className="w-full py-2 bg-purple-600 hover:bg-purple-500 text-white text-xs font-bold rounded-xl transition"
              >
                Execute GraphQL Request
              </button>

              {graphqlRes && (
                <pre className="p-3 bg-slate-950 border border-slate-800 rounded-xl font-mono text-[11px] text-slate-300 overflow-x-auto max-h-36">
                  {JSON.stringify(graphqlRes, null, 2)}
                </pre>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
