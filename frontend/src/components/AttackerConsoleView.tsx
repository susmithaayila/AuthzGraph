import { useState, useEffect } from 'react';
import {
  Zap,
  Eye,
  Edit3,
  Play,
  AlertTriangle,
  RefreshCw,
  Code,
  ShieldAlert,
  Info,
  Terminal,
} from 'lucide-react';

const API_BASE = 'http://localhost:8000/api/v1';

interface Props {
  currentUser: any;
  securityMode: 'vulnerable' | 'secure';
  onToggleMode: (mode: 'vulnerable' | 'secure') => void;
}

export function AttackerConsoleView({ currentUser, securityMode }: Props) {

  const [attackType, setAttackType] = useState<'BOLA' | 'BOPLA' | 'BFLA'>('BOLA');
  const [currentStep, setCurrentStep] = useState<number>(1);

  // Step 1: Captured Packets
  const [capturedPackets, setCapturedPackets] = useState<any[]>([]);
  const [selectedPacket, setSelectedPacket] = useState<any | null>(null);
  const [loadingCapture, setLoadingCapture] = useState(false);

  // Step 3: Repeater Tamper Editor
  const [tamperedMethod, setTamperedMethod] = useState('GET');
  const [tamperedPath, setTamperedPath] = useState('/api/v1/bank/users/102');
  const [tamperedHeaders, setTamperedHeaders] = useState('{\n  "Authorization": "Bearer token_alice"\n}');
  const [tamperedBody, setTamperedBody] = useState('{\n  "role": "ADMIN",\n  "accountBalance": 999999\n}');

  // Step 4: Replay Result
  const [replayResult, setReplayResult] = useState<any | null>(null);
  const [loadingReplay, setLoadingReplay] = useState(false);

  // Step 5: Automation & Enumeration
  const [showScriptPreview, setShowScriptPreview] = useState(false);
  const [enumResults, setEnumResults] = useState<any | null>(null);
  const [loadingEnum, setLoadingEnum] = useState(false);

  // Token Inspector State
  const [tokenInfo, setTokenInfo] = useState<any | null>(null);

  // Fetch Captured Traffic on Mount or User/Mode change
  const fetchTraffic = async () => {
    setLoadingCapture(true);
    try {
      const res = await fetch(`${API_BASE}/bank/demo/traffic-capture?user_id=${currentUser.id}&limit=5`);
      if (res.ok) {
        const data = await res.json();
        setCapturedPackets(data.packets || []);
        if (data.packets && data.packets.length > 0) {
          setSelectedPacket(data.packets[0]);
        }
      }
    } catch {
      // silent fallback
    } finally {
      setLoadingCapture(false);
    }
  };

  useEffect(() => {
    fetchTraffic();
  }, [currentUser.id]);

  // Update Tamper Editor template whenever AttackType changes
  useEffect(() => {
    if (attackType === 'BOLA') {
      setTamperedMethod('GET');
      setTamperedPath('/api/v1/bank/users/102');
      setTamperedHeaders(`{\n  "Authorization": "Bearer ${currentUser.token || 'token_alice'}"\n}`);
      setTamperedBody('');
    } else if (attackType === 'BOPLA') {
      setTamperedMethod('PATCH');
      setTamperedPath(`/api/v1/bank/users/${currentUser.id}`);
      setTamperedHeaders(`{\n  "Authorization": "Bearer ${currentUser.token || 'token_alice'}"\n}`);
      setTamperedBody('{\n  "role": "ADMIN",\n  "accountBalance": 999999\n}');
    } else if (attackType === 'BFLA') {
      setTamperedMethod('GET');
      setTamperedPath('/api/v1/bank/admin/users');
      setTamperedHeaders(`{\n  "Authorization": "Bearer ${currentUser.token || 'token_alice'}"\n}`);
      setTamperedBody('');
    }
    setReplayResult(null);
  }, [attackType, currentUser]);

  // Inspect Token
  const inspectToken = async () => {
    try {
      const res = await fetch(`${API_BASE}/bank/demo/token-inspector?token=${currentUser.token || 'token_alice'}`);
      if (res.ok) {
        const data = await res.json();
        setTokenInfo(data);
      }
    } catch {
      // silent
    }
  };

  useEffect(() => {
    inspectToken();
  }, [currentUser]);

  // Execute Replay Request (Step 3/4)
  const handleRunReplay = async () => {
    setLoadingReplay(true);
    let parsedHeaders = { Authorization: `Bearer ${currentUser.token || 'token_alice'}` };
    let parsedBody = null;

    try {
      if (tamperedHeaders.trim()) parsedHeaders = JSON.parse(tamperedHeaders);
    } catch {
      // fallback
    }
    try {
      if (tamperedBody.trim()) parsedBody = JSON.parse(tamperedBody);
    } catch {
      // fallback
    }

    try {
      const res = await fetch(`${API_BASE}/bank/demo/replay`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          method: tamperedMethod,
          path: tamperedPath,
          headers: parsedHeaders,
          body: parsedBody,
          caller_id: currentUser.id,
        }),
      });
      const data = await res.json();
      setReplayResult(data);
      setCurrentStep(4);
    } catch (err: any) {
      setReplayResult({ error: err.message });
    } finally {
      setLoadingReplay(false);
    }
  };

  // Execute Enumeration (Step 5)
  const handleRunEnumeration = async () => {
    setLoadingEnum(true);
    try {
      const res = await fetch(`${API_BASE}/bank/demo/enumerate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          vulnerability_type: attackType,
          start_id: 101,
          end_id: 110,
          caller_id: currentUser.id,
        }),
      });
      const data = await res.json();
      setEnumResults(data);
    } catch (err: any) {
      setEnumResults({ error: err.message });
    } finally {
      setLoadingEnum(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-rose-500/10 border border-rose-500/20 text-rose-400 rounded-xl">
            <Terminal className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-xl font-bold text-white">Attacker Reconnaissance & Exploitation Console</h2>
              <span className="px-2 py-0.5 text-[10px] font-bold bg-rose-500/20 text-rose-300 border border-rose-500/30 rounded">
                PHASE 6 RESEARCH TOOL
              </span>
            </div>
            <p className="text-xs text-slate-400">
              5-Step Guided Walkthrough: Capture ➔ Annotate ➔ Tamper/Replay ➔ Classify ➔ Automate/Enumerate
            </p>
          </div>
        </div>

        {/* Vulnerability Mode Selector */}
        <div className="flex items-center gap-2 bg-slate-950 p-1.5 rounded-xl border border-slate-800">
          {(['BOLA', 'BOPLA', 'BFLA'] as const).map((type) => (
            <button
              key={type}
              onClick={() => setAttackType(type)}
              className={`px-3 py-1.5 rounded-lg text-xs font-bold transition ${
                attackType === type
                  ? type === 'BOLA'
                    ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                    : type === 'BOPLA'
                    ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                    : 'bg-purple-500/20 text-purple-300 border border-purple-500/40'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {type}
            </button>
          ))}
        </div>
      </div>

      {/* Stepper Navigation */}
      <div className="grid grid-cols-5 gap-2">
        {[
          { num: 1, title: '1. Capture', icon: Eye },
          { num: 2, title: '2. Annotate', icon: Info },
          { num: 3, title: '3. Tamper & Replay', icon: Edit3 },
          { num: 4, title: '4. Result & Classify', icon: ShieldAlert },
          { num: 5, title: '5. Automate & Scale', icon: Play },
        ].map((s) => {
          const isActive = currentStep === s.num;
          const isDone = currentStep > s.num;


          return (
            <button
              key={s.num}
              onClick={() => setCurrentStep(s.num)}
              className={`p-3 rounded-xl border text-left transition flex items-center gap-2.5 ${
                isActive
                  ? 'bg-rose-500/10 border-rose-500/50 text-rose-300 shadow-md'
                  : isDone
                  ? 'bg-slate-900 border-slate-800 text-slate-300 hover:bg-slate-800'
                  : 'bg-slate-950/60 border-slate-800/80 text-slate-500 hover:text-slate-400'
              }`}
            >
              <div
                className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold shrink-0 ${
                  isActive ? 'bg-rose-500 text-white' : isDone ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40' : 'bg-slate-800 text-slate-400'
                }`}
              >
                {isDone ? '✓' : s.num}
              </div>
              <span className="text-xs font-bold truncate">{s.title}</span>
            </button>
          );
        })}
      </div>

      {/* STEP 1: LEGITIMATE TRAFFIC CAPTURE */}
      {currentStep === 1 && (
        <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl space-y-5">
          <div className="flex justify-between items-start">
            <div>
              <span className="text-xs font-bold text-rose-400 uppercase tracking-widest">STEP 1: RECONNAISSANCE</span>
              <h3 className="text-lg font-bold text-white mt-1">Intercepted DevTools / Proxy Traffic Log</h3>
              <p className="text-xs text-slate-400 mt-1">
                Captures legitimate HTTP traffic sent by user <strong className="text-white">{currentUser.name}</strong>.
              </p>
            </div>
            <button
              onClick={fetchTraffic}
              disabled={loadingCapture}
              className="px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-xl transition flex items-center gap-2 border border-slate-700"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loadingCapture ? 'animate-spin' : ''}`} />
              Refresh Traffic
            </button>
          </div>

          <div className="bg-slate-950 p-4 rounded-xl border border-slate-800/80 text-xs text-slate-300">
            <span className="font-bold text-cyan-400 block mb-1">💡 Attacker Perspective:</span>
            "This packet represents what any user sees in browser DevTools Network tab or Burp Suite proxy history after initiating a normal authorized request."
          </div>

          {capturedPackets.length > 0 ? (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {/* Packets List */}
              <div className="space-y-2">
                <h4 className="text-xs font-bold text-slate-400 uppercase">Captured Request Stream</h4>
                {capturedPackets.map((pkt) => (
                  <div
                    key={pkt.request_id}
                    onClick={() => setSelectedPacket(pkt)}
                    className={`p-3.5 rounded-xl border cursor-pointer transition ${
                      selectedPacket?.request_id === pkt.request_id
                        ? 'bg-rose-500/10 border-rose-500/40 text-white'
                        : 'bg-slate-950 border-slate-800 text-slate-300 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex justify-between items-center text-xs">
                      <span className="font-mono font-bold text-cyan-400">{pkt.method} {pkt.path}</span>
                      <span className="px-2 py-0.5 bg-emerald-500/20 text-emerald-400 rounded text-[10px] font-bold">
                        {pkt.response_status} OK
                      </span>
                    </div>
                    <div className="text-[10px] text-slate-500 mt-1 font-mono">{pkt.timestamp}</div>
                  </div>
                ))}
              </div>

              {/* Packet Details Inspector */}
              {selectedPacket && (
                <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-3">
                  <h4 className="text-xs font-bold text-slate-300 uppercase">Raw HTTP Packet Inspector</h4>
                  <pre className="text-xs font-mono text-slate-300 bg-slate-900 p-3 rounded-lg overflow-x-auto">
{`${selectedPacket.method} ${selectedPacket.path} HTTP/1.1
Host: 127.0.0.1:8000
Authorization: ${selectedPacket.request_headers?.Authorization || 'Bearer token_alice'}
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)

${selectedPacket.request_body ? JSON.stringify(selectedPacket.request_body, null, 2) : '// No request body'}`}
                  </pre>
                </div>
              )}
            </div>
          ) : (
            <div className="p-8 text-center text-slate-500 text-xs bg-slate-950 rounded-xl border border-slate-800">
              No traffic captured yet. Intercepting background traffic...
            </div>
          )}

          {/* Secondary Vulnerability: Predictable Token Warning */}
          {tokenInfo && tokenInfo.security_findings && tokenInfo.security_findings.length > 0 && (
            <div className="bg-amber-950/20 border border-amber-500/30 p-4 rounded-xl space-y-2 text-xs text-amber-300">
              <div className="flex items-center gap-2 font-bold text-amber-400">
                <AlertTriangle className="w-4 h-4" />
                Secondary Vulnerability Identified: {tokenInfo.security_findings[0].vulnerability_class}
              </div>
              <p>{tokenInfo.security_findings[0].observation}</p>
              <div className="text-[11px] text-amber-400/80 font-mono">
                Recommendation for Research Paper: {tokenInfo.security_findings[0].paper_recommendation}
              </div>
            </div>
          )}

          <div className="flex justify-end pt-2">
            <button
              onClick={() => setCurrentStep(2)}
              className="px-5 py-2.5 bg-rose-600 hover:bg-rose-500 text-white text-xs font-bold rounded-xl transition flex items-center gap-2 shadow-lg shadow-rose-900/30"
            >
              Proceed to Step 2: Pattern Recognition ➔
            </button>
          </div>
        </div>
      )}

      {/* STEP 2: PATTERN RECOGNITION & ANNOTATION */}
      {currentStep === 2 && (
        <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl space-y-5">
          <div>
            <span className="text-xs font-bold text-amber-400 uppercase tracking-widest">STEP 2: ANALYSIS</span>
            <h3 className="text-lg font-bold text-white mt-1">Exploitable Target Field Identification</h3>
            <p className="text-xs text-slate-400 mt-1">
              Automatic identification of attacker-controllable parameter fields for <strong className="text-rose-400">{attackType}</strong>.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className={`p-4 rounded-xl border space-y-2 ${attackType === 'BOLA' ? 'bg-rose-500/10 border-rose-500/40' : 'bg-slate-950 border-slate-800'}`}>
              <span className="text-xs font-bold text-rose-400 block">BOLA Target Field</span>
              <code className="text-xs font-mono text-white block bg-slate-900 p-2 rounded">/api/v1/bank/users/<span className="text-rose-400 font-bold underline">101</span></code>
              <p className="text-[11px] text-slate-400">
                <strong>Vulnerability Note:</strong> Sequential integer identifier in URL path. Trivially guessable and enumerable.
              </p>
            </div>

            <div className={`p-4 rounded-xl border space-y-2 ${attackType === 'BOPLA' ? 'bg-amber-500/10 border-amber-500/40' : 'bg-slate-950 border-slate-800'}`}>
              <span className="text-xs font-bold text-amber-400 block">BOPLA Target Field</span>
              <code className="text-xs font-mono text-white block bg-slate-900 p-2 rounded">JSON Body: <span className="text-amber-400 font-bold">"role": "ADMIN"</span></code>
              <p className="text-[11px] text-slate-400">
                <strong>Vulnerability Note:</strong> Client-supplied privileged fields injected into profile update JSON payloads.
              </p>
            </div>

            <div className={`p-4 rounded-xl border space-y-2 ${attackType === 'BFLA' ? 'bg-purple-500/10 border-purple-500/40' : 'bg-slate-950 border-slate-800'}`}>
              <span className="text-xs font-bold text-purple-400 block">BFLA Target Field</span>
              <code className="text-xs font-mono text-white block bg-slate-900 p-2 rounded">Path Segment: <span className="text-purple-400 font-bold">/admin/users</span></code>
              <p className="text-[11px] text-slate-400">
                <strong>Vulnerability Note:</strong> Administrative route path invoked by low-privilege customer account identity.
              </p>
            </div>
          </div>

          <div className="flex justify-between items-center pt-2">
            <button onClick={() => setCurrentStep(1)} className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-bold rounded-xl">
              ← Back to Step 1
            </button>
            <button
              onClick={() => setCurrentStep(3)}
              className="px-5 py-2.5 bg-rose-600 hover:bg-rose-500 text-white text-xs font-bold rounded-xl transition flex items-center gap-2 shadow-lg shadow-rose-900/30"
            >
              Proceed to Step 3: Tamper & Replay ➔
            </button>
          </div>
        </div>
      )}

      {/* STEP 3: TAMPER & REPLAY (REPEATER EDITOR) */}
      {currentStep === 3 && (
        <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl space-y-5">
          <div>
            <span className="text-xs font-bold text-rose-400 uppercase tracking-widest">STEP 3: EXPLOITATION</span>
            <h3 className="text-lg font-bold text-white mt-1">Repeater Raw Request Tamper Editor</h3>
            <p className="text-xs text-slate-400 mt-1">
              Modify captured request parameters and replay directly against the live backend authorization pipeline.
            </p>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div className="space-y-3">
              <div className="flex gap-2">
                <select
                  value={tamperedMethod}
                  onChange={(e) => setTamperedMethod(e.target.value)}
                  className="bg-slate-950 border border-slate-700 text-white font-mono text-xs px-3 py-2 rounded-xl focus:outline-none focus:border-rose-500"
                >
                  <option value="GET">GET</option>
                  <option value="POST">POST</option>
                  <option value="PATCH">PATCH</option>
                  <option value="DELETE">DELETE</option>
                </select>
                <input
                  type="text"
                  value={tamperedPath}
                  onChange={(e) => setTamperedPath(e.target.value)}
                  className="bg-slate-950 border border-slate-700 text-white font-mono text-xs px-3.5 py-2 rounded-xl flex-1 focus:outline-none focus:border-rose-500"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Request Headers (JSON):</label>
                <textarea
                  value={tamperedHeaders}
                  onChange={(e) => setTamperedHeaders(e.target.value)}
                  rows={3}
                  className="bg-slate-950 border border-slate-700 text-slate-300 font-mono text-xs p-3 rounded-xl w-full focus:outline-none focus:border-rose-500"
                />
              </div>

              {tamperedMethod !== 'GET' && (
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">Request Body (JSON):</label>
                  <textarea
                    value={tamperedBody}
                    onChange={(e) => setTamperedBody(e.target.value)}
                    rows={4}
                    className="bg-slate-950 border border-slate-700 text-amber-300 font-mono text-xs p-3 rounded-xl w-full focus:outline-none focus:border-rose-500"
                  />
                </div>
              )}

              <button
                onClick={handleRunReplay}
                disabled={loadingReplay}
                className="w-full py-2.5 bg-rose-600 hover:bg-rose-500 text-white text-xs font-bold rounded-xl transition flex items-center justify-center gap-2 shadow-lg shadow-rose-900/30"
              >
                {loadingReplay ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />}
                Send Tampered Replay Request ➔
              </button>
            </div>

            <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-3 text-xs">
              <h4 className="font-bold text-slate-300">Targeting Strategy ({attackType})</h4>
              <p className="text-slate-400 text-[11px]">
                Modifying the request parameters allows testing whether the server enforces authorization on mutated requests.
              </p>
              <div className="bg-slate-900 p-3 rounded-lg border border-slate-800 text-[11px] font-mono text-slate-300">
                Current Security Mode: <strong className={securityMode === 'secure' ? 'text-emerald-400' : 'text-rose-400'}>{securityMode.toUpperCase()}</strong>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* STEP 4: RESULT & CLASSIFICATION */}
      {currentStep === 4 && (
        <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl space-y-5">
          <div className="flex justify-between items-start">
            <div>
              <span className="text-xs font-bold text-emerald-400 uppercase tracking-widest">STEP 4: EVALUATION</span>
              <h3 className="text-lg font-bold text-white mt-1">Live Engine Response & Vulnerability Tagging</h3>
              <p className="text-xs text-slate-400 mt-1">
                Real status code and body returned by <code className="text-slate-200">CentralAuthorizationEngine</code>.
              </p>
            </div>

            {replayResult && (
              <span className={`px-3 py-1 text-xs font-mono font-bold rounded-xl border ${
                replayResult.status_code === 200
                  ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                  : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
              }`}>
                HTTP {replayResult.status_code}
              </span>
            )}
          </div>

          {replayResult ? (
            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
                <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800">
                  <span className="text-slate-400 block text-[10px]">CVSS SEVERITY BADGE</span>
                  <span className={`text-sm font-bold block mt-0.5 ${
                    replayResult.status_code === 200 ? 'text-rose-400 font-extrabold' : 'text-emerald-400'
                  }`}>
                    {replayResult.status_code === 200 ? 'CRITICAL (CVSS 9.1)' : 'MITIGATED (0.0)'}
                  </span>
                </div>

                <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800">
                  <span className="text-slate-400 block text-[10px]">VULNERABILITY TAG</span>
                  <span className={`text-sm font-bold block mt-0.5 ${
                    replayResult.status_code === 200 ? 'text-rose-400' : 'text-emerald-400'
                  }`}>
                    {replayResult.status_code === 200 ? `EXPOSED (${attackType})` : 'BLOCKED (403)'}
                  </span>
                </div>

                <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800">
                  <span className="text-slate-400 block text-[10px]">ENGINE POLICY LAYER</span>
                  <span className="text-sm font-bold text-cyan-300 block mt-0.5">{replayResult.policy || 'AUTHORIZATION_ENGINE'}</span>
                </div>
              </div>

              <pre className="bg-slate-950 p-4 rounded-xl border border-slate-800 text-xs font-mono text-slate-300 overflow-x-auto max-h-64">
                {JSON.stringify(replayResult.response_body, null, 2)}
              </pre>

              <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800 text-xs text-slate-400 flex items-center justify-between">
                <span>Matching security decision recorded in Audit Logs.</span>
                <span className="text-cyan-400 font-bold font-mono">Timestamp: {new Date().toLocaleTimeString()}</span>
              </div>
            </div>
          ) : (
            <div className="p-8 text-center text-slate-500 text-xs bg-slate-950 rounded-xl border border-slate-800">
              No replay request executed yet. Return to Step 3 and click "Send Tampered Replay Request".
            </div>
          )}

          <div className="flex justify-between items-center pt-2">
            <button onClick={() => setCurrentStep(3)} className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-bold rounded-xl">
              ← Back to Step 3
            </button>
            <button
              onClick={() => setCurrentStep(5)}
              className="px-5 py-2.5 bg-rose-600 hover:bg-rose-500 text-white text-xs font-bold rounded-xl transition flex items-center gap-2 shadow-lg shadow-rose-900/30"
            >
              Proceed to Step 5: Automate & Scale ➔
            </button>
          </div>
        </div>
      )}

      {/* STEP 5: AUTOMATE & SCALE */}
      {currentStep === 5 && (
        <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl space-y-5">
          <div className="flex justify-between items-start">
            <div>
              <span className="text-xs font-bold text-purple-400 uppercase tracking-widest">STEP 5: AUTOMATION & ENUMERATION</span>
              <h3 className="text-lg font-bold text-white mt-1">Automated Scripting & Batch Enumeration Primitive</h3>
              <p className="text-xs text-slate-400 mt-1">
                Demonstrates how attackers scale single vulnerability findings into automated data scraping pipelines.
              </p>
            </div>

            <button
              onClick={() => setShowScriptPreview(!showScriptPreview)}
              className="px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-xl transition flex items-center gap-2 border border-slate-700"
            >
              <Code className="w-3.5 h-3.5 text-cyan-400" />
              {showScriptPreview ? 'Hide Script Preview' : 'Show Python Script Preview'}
            </button>
          </div>

          {/* Python Script Preview */}
          {showScriptPreview && (
            <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 text-xs space-y-2">
              <span className="font-bold text-cyan-400 block font-mono">// Illustrative Attacker Python Script (requests)</span>
              <pre className="text-slate-300 font-mono text-[11px] overflow-x-auto bg-slate-900 p-3 rounded-lg">
{`import requests

headers = {"Authorization": "Bearer token_alice"}

for user_id in range(101, 111):
    url = f"http://127.0.0.1:8000/api/v1/bank/users/{user_id}"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        print(f"[+] EXPOSED: User {user_id} -> {response.json()['data']['name']}")
    else:
        print(f"[-] BLOCKED: User {user_id} -> HTTP {response.status_code}")`}
              </pre>
            </div>
          )}

          {/* Enumeration Execution */}
          <div className="space-y-4">
            <button
              onClick={handleRunEnumeration}
              disabled={loadingEnum}
              className="w-full py-3 bg-purple-600 hover:bg-purple-500 text-white text-xs font-bold rounded-xl transition flex items-center justify-center gap-2 shadow-lg shadow-purple-900/30"
            >
              {loadingEnum ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
              Run Automated 10-ID Enumeration Loop (IDs 101–110)
            </button>

            {enumResults && (
              <div className="space-y-3">
                <div className="flex items-center justify-between text-xs bg-slate-950 p-3 rounded-xl border border-slate-800">
                  <span className="text-slate-400">Total Tested: <strong className="text-white">{enumResults.total_tested}</strong></span>
                  <span className="text-slate-400">Total Exposed: <strong className={enumResults.total_exposed > 0 ? "text-rose-400" : "text-emerald-400"}>{enumResults.total_exposed}</strong></span>
                  <span className="text-slate-400">Mode: <strong className="text-cyan-400">{enumResults.mode.toUpperCase()}</strong></span>
                </div>

                <div className="bg-slate-950 rounded-xl border border-slate-800 overflow-hidden">
                  <table className="w-full text-left text-xs">
                    <thead>
                      <tr className="bg-slate-900 border-b border-slate-800 text-slate-400 font-bold uppercase">
                        <th className="p-3">ID</th>
                        <th className="p-3">Target Name</th>
                        <th className="p-3 text-center">Status Code</th>
                        <th className="p-3 text-center">Exposure</th>
                        <th className="p-3">Reason</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60 font-mono">
                      {enumResults.results?.map((r: any) => (
                        <tr key={r.target_id} className="hover:bg-slate-900/50">
                          <td className="p-3 text-cyan-400">#{r.target_id}</td>
                          <td className="p-3 font-bold text-white">{r.target_name}</td>
                          <td className="p-3 text-center">{r.status_code}</td>
                          <td className="p-3 text-center">
                            <span className={`px-2 py-0.5 rounded font-bold text-[10px] ${
                              r.exposed ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30' : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                            }`}>
                              {r.exposed ? '⚠️ EXPOSED' : '🛡️ BLOCKED'}
                            </span>
                          </td>
                          <td className="p-3 text-slate-400 text-[11px] font-sans truncate max-w-xs">{r.reason}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>

          {/* Sandbox Disclaimer Note */}
          <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 text-[11px] text-slate-400 text-center">
            🔒 <strong>Research Disclaimer:</strong> This automation only targets this application's own local, synthetic sandbox API and cannot be pointed at external hosts — included strictly to illustrate attacker tooling patterns for research purposes.
          </div>
        </div>
      )}
    </div>
  );
}
