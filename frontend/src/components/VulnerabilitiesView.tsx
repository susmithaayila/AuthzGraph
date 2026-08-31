import { useState } from 'react';
import { ShieldAlert, Copy, Check, Code, FileText, AlertCircle, Loader2 } from 'lucide-react';
import type { Finding } from '../App';

interface VulnerabilitiesViewProps {
  findings: Finding[];
  isScanning: boolean;
}

const SEVERITY_COLOR: Record<string, string> = {
  CRITICAL: 'text-red-400 bg-red-950/60 border-red-800',
  HIGH: 'text-orange-400 bg-orange-950/60 border-orange-800',
  MEDIUM: 'text-amber-400 bg-amber-950/60 border-amber-800',
  LOW: 'text-emerald-400 bg-emerald-950/60 border-emerald-800',
};

export const VulnerabilitiesView = ({ findings, isScanning }: VulnerabilitiesViewProps) => {
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(
    findings.length > 0 ? findings[0] : null
  );
  const [copied, setCopied] = useState(false);
  const [activeLang, setActiveLang] = useState<string>('Python (FastAPI)');

  // Update selectedFinding when findings change (after scan completes)
  const effectiveFinding = selectedFinding ?? findings[0] ?? null;

  const copyCurl = () => {
    if (!effectiveFinding) return;
    navigator.clipboard.writeText(effectiveFinding.curl_reproduction);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // ── Loading skeleton ─────────────────────────────────────────────────────
  if (isScanning) {
    return (
      <div className="space-y-6">
        <div className="flex justify-between items-center bg-[#151D2A] border border-[#26334D] p-4 rounded-xl">
          <div>
            <h2 className="text-xl font-bold text-white flex items-center gap-2">
              <ShieldAlert className="text-red-400 w-5 h-5" />
              Vulnerabilities & Remediation Hub
            </h2>
            <p className="text-xs text-gray-400">Scanning for BOLA, BFLA, and BOPLA vulnerabilities…</p>
          </div>
          <div className="flex items-center gap-2 text-blue-400 text-xs">
            <Loader2 className="w-4 h-4 animate-spin" />
            Live scan in progress
          </div>
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="space-y-3">
            {[1, 2, 3].map((i) => (
              <div key={i} className="p-4 rounded-xl border border-[#26334D] bg-[#0B0F17] animate-pulse">
                <div className="h-4 bg-[#26334D] rounded w-2/3 mb-3" />
                <div className="h-3 bg-[#26334D] rounded w-full mb-2" />
                <div className="h-3 bg-[#26334D] rounded w-1/2" />
              </div>
            ))}
          </div>
          <div className="lg:col-span-2 bg-[#151D2A] border border-[#26334D] p-6 rounded-xl animate-pulse">
            <div className="h-5 bg-[#26334D] rounded w-1/2 mb-4" />
            <div className="h-3 bg-[#26334D] rounded w-full mb-3" />
            <div className="h-3 bg-[#26334D] rounded w-3/4 mb-3" />
            <div className="h-24 bg-[#26334D] rounded w-full mt-6" />
          </div>
        </div>
      </div>
    );
  }

  // ── Empty state ──────────────────────────────────────────────────────────
  if (findings.length === 0) {
    return (
      <div className="space-y-6">
        <div className="flex justify-between items-center bg-[#151D2A] border border-[#26334D] p-4 rounded-xl">
          <div>
            <h2 className="text-xl font-bold text-white flex items-center gap-2">
              <ShieldAlert className="text-red-400 w-5 h-5" />
              Vulnerabilities & Remediation Hub
            </h2>
            <p className="text-xs text-gray-400">
              Actionable BOLA, BFLA, and BOPLA finding advisories with CVSS v3.1 scoring, cURL repros, and framework fixes.
            </p>
          </div>
        </div>
        <div className="flex flex-col items-center justify-center py-24 text-center bg-[#151D2A] border border-[#26334D] rounded-xl">
          <AlertCircle className="w-12 h-12 text-gray-600 mb-4" />
          <p className="text-white font-semibold text-lg mb-1">No Findings Yet</p>
          <p className="text-gray-400 text-sm max-w-sm">
            Click <span className="text-blue-400 font-mono">Start Live Scan</span> in the header to run the BOLA/BFLA/BOPLA scanner and populate this panel with real findings.
          </p>
        </div>
      </div>
    );
  }

  // ── Real findings view ───────────────────────────────────────────────────
  const selected = effectiveFinding!;
  const remediationLangs = Object.keys(selected.remediation_snippets);
  const currentLang = remediationLangs.includes(activeLang) ? activeLang : remediationLangs[0];

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center bg-[#151D2A] border border-[#26334D] p-4 rounded-xl">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <ShieldAlert className="text-red-400 w-5 h-5" />
            Vulnerabilities & Remediation Hub
          </h2>
          <p className="text-xs text-gray-400">
            {findings.length} live finding{findings.length !== 1 ? 's' : ''} — CVSS v3.1 scoring, cURL repros, and framework fixes.
          </p>
        </div>
        <div className="flex gap-2">
          {(['BOLA', 'BFLA', 'BOPLA'] as const).map((cls) => {
            const count = findings.filter((f) => f.vulnerability_class === cls).length;
            return count > 0 ? (
              <span key={cls} className="text-[10px] font-mono font-bold px-2 py-0.5 rounded border border-red-800 bg-red-950/40 text-red-400">
                {cls}: {count}
              </span>
            ) : null;
          })}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Findings List */}
        <div className="space-y-3">
          {findings.map((finding) => (
            <div
              key={finding.id}
              onClick={() => { setSelectedFinding(finding); setActiveLang('Python (FastAPI)'); }}
              className={`p-4 rounded-xl border cursor-pointer transition-all ${
                selected.id === finding.id
                  ? 'bg-[#151D2A] border-blue-500 shadow-lg shadow-blue-900/30'
                  : 'bg-[#0B0F17] border-[#26334D] hover:border-gray-600'
              }`}
            >
              <div className="flex justify-between items-start mb-2">
                <span className={`text-xs font-mono font-bold px-2 py-0.5 rounded border ${SEVERITY_COLOR[finding.severity] ?? 'text-gray-400 bg-gray-900 border-gray-700'}`}>
                  {finding.severity} ({finding.cvss_score})
                </span>
                <span className="text-xs font-mono text-gray-400">{finding.http_method}</span>
              </div>
              <h3 className="text-sm font-semibold text-white line-clamp-2">{finding.title}</h3>
              <p className="text-xs text-gray-400 font-mono mt-2 truncate">{finding.endpoint_path}</p>
            </div>
          ))}
        </div>

        {/* Detail Panel */}
        <div className="lg:col-span-2 space-y-6 bg-[#151D2A] border border-[#26334D] p-6 rounded-xl">
          {/* Header */}
          <div>
            <div className="flex items-center gap-3 flex-wrap">
              <span className={`px-2.5 py-1 text-xs font-bold font-mono rounded border ${SEVERITY_COLOR[selected.severity] ?? ''}`}>
                {selected.severity} ({selected.cvss_score})
              </span>
              <span className="text-xs font-mono text-blue-400 bg-blue-950 px-2 py-1 rounded border border-blue-800">
                {selected.owasp_category}
              </span>
            </div>
            <h3 className="text-lg font-bold text-white mt-3">{selected.title}</h3>
            <p className="text-xs text-gray-400 mt-1 font-mono break-all">{selected.endpoint_path}</p>
            <p className="text-xs text-gray-300 mt-3 leading-relaxed">{selected.description}</p>
          </div>

          {/* Faculty Proof Card */}
          <div className="bg-[#0B0F17] border border-red-500/40 p-4 rounded-xl space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-red-400 uppercase tracking-wider flex items-center gap-1.5">
                <ShieldAlert className="w-4 h-4 text-red-400" /> Faculty Verification: Proof of Unauthorized Access
              </span>
              <span className="text-[10px] font-mono bg-red-950 text-red-300 border border-red-800 px-2 py-0.5 rounded">
                BOLA Violation Verified
              </span>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-2 text-xs font-mono pt-1">
              <div className="bg-[#151D2A] p-2.5 rounded border border-[#26334D]">
                <p className="text-[10px] text-gray-500">VICTIM (Resource Owner)</p>
                <p className="text-emerald-400 font-bold mt-0.5">Arjun Kapoor (rider_arjun)</p>
                <p className="text-[10px] text-gray-400 truncate">Token: token_arjun</p>
              </div>
              <div className="bg-[#151D2A] p-2.5 rounded border border-[#26334D]">
                <p className="text-[10px] text-gray-500">ATTACKER (Unauthorized User)</p>
                <p className="text-red-400 font-bold mt-0.5">Priya Sharma (rider_priya)</p>
                <p className="text-[10px] text-gray-400 truncate">Token: token_priya</p>
              </div>
              <div className="bg-[#151D2A] p-2.5 rounded border border-[#26334D]">
                <p className="text-[10px] text-gray-500">RESOURCE COMPROMISED</p>
                <p className="text-amber-400 font-bold mt-0.5 truncate">{selected.endpoint_path}</p>
                <p className="text-[10px] text-emerald-400">Response: HTTP 200 OK (Data Stolen)</p>
              </div>
            </div>
          </div>

          {/* CVSS / CVE row */}
          <div className="bg-[#0B0F17] border border-[#26334D] p-3 rounded-lg flex flex-wrap justify-between gap-2 text-xs font-mono">
            <div>
              <span className="text-gray-400">CVSS v3.1 Vector: </span>
              <span className="text-gray-200">{selected.cvss_vector}</span>
            </div>
            <div>
              <span className="text-gray-400">CVE Analog: </span>
              <span className="text-red-400 font-bold">{selected.cve_analog}</span>
            </div>
          </div>

          {/* cURL Reproduction */}
          <div>
            <div className="flex justify-between items-center mb-2">
              <h4 className="text-xs font-semibold text-gray-300 uppercase tracking-wider flex items-center gap-1.5">
                <FileText className="w-3.5 h-3.5 text-blue-400" /> 1-Click cURL Reproduction
              </h4>
              <button
                onClick={copyCurl}
                className="flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300 transition-colors"
              >
                {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                {copied ? 'Copied' : 'Copy cURL'}
              </button>
            </div>
            <pre className="bg-[#0B0F17] border border-[#26334D] p-3 rounded-lg font-mono text-xs text-emerald-400 overflow-x-auto whitespace-pre-wrap">
              {selected.curl_reproduction}
            </pre>
          </div>

          {/* Remediation Snippet */}
          <div>
            <div className="flex justify-between items-center mb-2">
              <h4 className="text-xs font-semibold text-gray-300 uppercase tracking-wider flex items-center gap-1.5">
                <Code className="w-3.5 h-3.5 text-emerald-400" /> Framework Remediation Snippet
              </h4>
              <div className="flex gap-1 flex-wrap">
                {remediationLangs.map((lang) => (
                  <button
                    key={lang}
                    onClick={() => setActiveLang(lang)}
                    className={`px-2 py-1 text-[11px] rounded ${
                      currentLang === lang ? 'bg-blue-600 text-white' : 'bg-[#0B0F17] text-gray-400 border border-[#26334D]'
                    }`}
                  >
                    {lang}
                  </button>
                ))}
              </div>
            </div>
            <pre className="bg-[#0B0F17] border border-[#26334D] p-3 rounded-lg font-mono text-xs text-blue-300 overflow-x-auto whitespace-pre-wrap">
              {selected.remediation_snippets[currentLang] ?? '// Remediation snippet not available for this finding'}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
};
