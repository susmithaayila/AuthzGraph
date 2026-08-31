import { useState } from 'react';
import { AlertTriangle, CheckCircle, XCircle, ShieldCheck } from 'lucide-react';


interface CaseStudy {
  id: string;
  company: string;
  year: string;
  owasp_category: string;
  vulnerability_type: string;
  summary: string;
  how_authzgraph_mitigates: string;
  mitigation_layer: string;
  is_contrast_case?: boolean;
}

const CASE_STUDIES: CaseStudy[] = [
  {
    id: 'optus',
    company: 'Optus (Australia)',
    year: '2022',
    owasp_category: 'OWASP API1:2023 — Broken Object Level Authorization',
    vulnerability_type: 'BOLA (Sequential Customer ID Enumeration)',
    summary: 'An unauthenticated internal API endpoint allowed sequential customer ID enumeration without ownership validation, exposing personal data of ~9.8 million customers.',
    how_authzgraph_mitigates: 'AuthzGraph enforces server-side ownership checks (`current_user.id == resource_owner_id`). Replaying requests across mismatched IDs yields 403 Forbidden.',
    mitigation_layer: 'BOLA Ownership Validation Layer',
  },
  {
    id: 'peloton',
    company: 'Peloton',
    year: '2021',
    owasp_category: 'OWASP API1:2023 — Broken Object Level Authorization',
    vulnerability_type: 'BOLA (Profile IDOR Vulnerability)',
    summary: 'API endpoints returned private user profile attributes and workout statistics for any user ID supplied in the request, bypassing user privacy preferences.',
    how_authzgraph_mitigates: 'Evaluates object ownership and user privacy clearance level before returning profile payloads.',
    mitigation_layer: 'BOLA Ownership + ABAC Privacy Policy',
  },
  {
    id: 'usps_informed',
    company: 'USPS Informed Delivery',
    year: '2018',
    owasp_category: 'OWASP API1:2023 — Broken Object Level Authorization',
    vulnerability_type: 'BOLA / IDOR Account Exposure',
    summary: 'An account management API allowed authenticated users to modify search parameters and view private account details of ~60 million accounts.',
    how_authzgraph_mitigates: 'Verifies requesting identity token against target account ID in complete mediation check.',
    mitigation_layer: 'BOLA Ownership Check',
  },
  {
    id: 'panera',
    company: 'Panera Bread',
    year: '2018',
    owasp_category: 'OWASP API1:2023 — Broken Object Level Authorization',
    vulnerability_type: 'BOLA (Plaintext Customer Record Leaks)',
    summary: 'Unauthenticated API endpoint with predictable sequential customer identifiers exposed millions of customer records including names, emails, and address history.',
    how_authzgraph_mitigates: 'Enforces mandatory authentication check followed by object-level permission check.',
    mitigation_layer: 'AuthN + BOLA Ownership Check',
  },
  {
    id: 'tmobile',
    company: 'T-Mobile API Abuse',
    year: '2022–2023',
    owasp_category: 'OWASP API1:2023 + API4:2023 Unrestricted Resource Consumption',
    vulnerability_type: 'BOLA + Missing Rate Limiting',
    summary: 'API lacking authorization boundaries and rate limiting was scraped via automated script loops, leaking customer record attributes across millions of accounts.',
    how_authzgraph_mitigates: 'Combines BOLA object authorization with decision audit logging to block mass enumeration.',
    mitigation_layer: 'BOLA Ownership + Audit Decision Engine',
  },
  {
    id: 'mass_assignment',
    company: 'USPS / Mass-Assignment Breaches',
    year: 'Various',
    owasp_category: 'OWASP API3:2023 — Broken Object Property Level Authorization',
    vulnerability_type: 'BOPLA / Mass-Assignment Privilege Escalation',
    summary: 'APIs accepted client-supplied JSON body fields (such as `role`, `discount_rate`, `is_admin`) directly into backend data models without DTO whitelisting.',
    how_authzgraph_mitigates: 'Strict input schema validation strips or rejects privileged properties (`role`, `accountBalance`) when submitted by non-admin users.',
    mitigation_layer: 'BOPLA Property Whitelist DTO Layer',
  },
  {
    id: 'uber',
    company: 'Uber Incident',
    year: '2022',
    owasp_category: 'OWASP API2:2023 Broken Authentication / Excessive Privilege',
    vulnerability_type: 'Contrast Case: AuthN Failure & MFA Fatigue',
    summary: 'Attacker compromised contractor credentials via MFA fatigue and discovered hardcoded admin scripts. This was a credential/standing privilege compromise rather than an API object authorization flaw.',
    how_authzgraph_mitigates: 'Demonstrates contrast between Broken Authentication (who you are) and Broken Authorization (what you can do). AuthzGraph focuses on API access control logic.',
    mitigation_layer: 'Research Contrast Case (AuthN vs AuthZ)',
    is_contrast_case: true,
  },
];

export function IncidentSimulatorView() {
  const [selectedCaseId, setSelectedCaseId] = useState('optus');
  const activeCase = CASE_STUDIES.find((c) => c.id === selectedCaseId) || CASE_STUDIES[0];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-rose-500/10 border border-rose-500/20 text-rose-400 rounded-xl">
            <AlertTriangle className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-white">Real-World Incident Simulator & Case Studies</h2>
            <p className="text-xs text-slate-400">Research-Accurate Real-World API Breach Case Studies Citable in Academic Research Papers</p>
          </div>
        </div>
      </div>

      {/* Case Study Switcher */}
      <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl space-y-6">
        <div className="space-y-3">
          <h3 className="text-sm font-bold text-white uppercase tracking-wider">Select Real-World Incident Case Study</h3>
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-2">
            {CASE_STUDIES.map((c) => (
              <button
                key={c.id}
                onClick={() => setSelectedCaseId(c.id)}
                className={`p-3 rounded-xl border text-left transition ${
                  selectedCaseId === c.id
                    ? c.is_contrast_case
                      ? 'bg-purple-500/20 border-purple-500/50 text-purple-300 font-bold'
                      : 'bg-rose-500/20 border-rose-500/50 text-rose-300 font-bold'
                    : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200'
                }`}
              >
                <div className="text-xs font-bold truncate">{c.company}</div>
                <div className="text-[10px] text-slate-500 font-mono mt-0.5">{c.year}</div>
              </button>
            ))}
          </div>
        </div>

        {/* Selected Case Study Detail */}
        <div className={`p-6 rounded-2xl border space-y-4 ${
          activeCase.is_contrast_case ? 'bg-purple-950/20 border-purple-500/30' : 'bg-rose-950/20 border-rose-500/30'
        }`}>
          <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-2 border-b border-slate-800 pb-3">
            <div>
              <span className={`text-xs font-bold uppercase tracking-wider ${activeCase.is_contrast_case ? 'text-purple-400' : 'text-rose-400'}`}>
                {activeCase.owasp_category}
              </span>
              <h3 className="text-lg font-bold text-white mt-0.5">{activeCase.company} ({activeCase.year})</h3>
            </div>
            <span className={`px-3 py-1 text-xs font-bold rounded-lg border ${
              activeCase.is_contrast_case ? 'bg-purple-500/20 text-purple-300 border-purple-500/40' : 'bg-rose-500/20 text-rose-300 border-rose-500/40'
            }`}>
              {activeCase.vulnerability_type}
            </span>
          </div>

          <div className="space-y-3 text-xs">
            <div>
              <h4 className="font-bold text-slate-300 mb-1">What Happened (Fact Summary):</h4>
              <p className="text-slate-400 text-[11px] leading-relaxed">{activeCase.summary}</p>
            </div>

            <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-1">
              <h4 className="font-bold text-emerald-400 flex items-center gap-2 text-xs">
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
                How AuthzGraph's SECURE Mode Would Have Blocked This:
              </h4>
              <p className="text-slate-300 text-[11px] leading-relaxed">{activeCase.how_authzgraph_mitigates}</p>
              <div className="text-[10px] text-cyan-400 font-mono mt-1">
                Mapped Engine Defensive Layer: <strong>{activeCase.mitigation_layer}</strong>
              </div>
            </div>
          </div>
        </div>

        {/* Standard Attack Chain Step Visualizer */}
        <div className="space-y-4 pt-2">
          <h3 className="text-sm font-bold text-white uppercase tracking-wider">The Standard API Authorization Attack Chain</h3>

          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2 text-xs">
              <span className="px-2 py-0.5 bg-rose-500/20 text-rose-400 rounded font-bold text-[10px]">STEP 1</span>
              <h4 className="font-bold text-white">Normal User Login</h4>
              <p className="text-slate-400">Attacker authenticates legitimately as Alice (User ID 101).</p>
            </div>

            <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2 text-xs">
              <span className="px-2 py-0.5 bg-rose-500/20 text-rose-400 rounded font-bold text-[10px]">STEP 2</span>
              <h4 className="font-bold text-white">Endpoint Discovery</h4>
              <p className="text-slate-400">Attacker captures <code className="text-rose-300">GET /api/users/101</code> containing predictable integer ID.</p>
            </div>

            <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2 text-xs">
              <span className="px-2 py-0.5 bg-rose-500/20 text-rose-400 rounded font-bold text-[10px]">STEP 3</span>
              <h4 className="font-bold text-white">Identifier Substitution</h4>
              <p className="text-slate-400">Attacker alters request identifier to <code className="text-rose-300">GET /api/users/102</code> (Bob's ID).</p>
            </div>

            <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2 text-xs">
              <span className="px-2 py-0.5 bg-rose-500/20 text-rose-400 rounded font-bold text-[10px]">STEP 4</span>
              <h4 className="font-bold text-white">Mass Data Exposure</h4>
              <p className="text-slate-400">Missing server-side ownership checks expose data across synthetic objects 101..110.</p>
            </div>
          </div>
        </div>

        {/* Before vs After Code Comparison */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 pt-2">
          <div className="bg-rose-950/20 border border-rose-500/30 p-5 rounded-xl space-y-3">
            <h4 className="font-bold text-rose-400 text-sm flex items-center gap-2">
              <XCircle className="w-5 h-5 text-rose-400" />
              Vulnerable Implementation (Before Fix)
            </h4>
            <pre className="bg-slate-950 p-4 rounded-xl border border-slate-800 text-xs font-mono text-rose-300 overflow-x-auto">
{`# ❌ BAD: Missing server-side ownership check
@app.get("/api/users/{user_id}")
def get_user(user_id):
    # Backend trusts client object ID directly!
    return database.get_user(user_id)`}
            </pre>
            <p className="text-xs text-rose-300/80">Result: 200 OK returning Bob's private data to Alice.</p>
          </div>

          <div className="bg-emerald-950/20 border border-emerald-500/30 p-5 rounded-xl space-y-3">
            <h4 className="font-bold text-emerald-400 text-sm flex items-center gap-2">
              <CheckCircle className="w-5 h-5 text-emerald-400" />
              Secure Implementation (After Fix)
            </h4>
            <pre className="bg-slate-950 p-4 rounded-xl border border-slate-800 text-xs font-mono text-emerald-300 overflow-x-auto">
{`# 🛡️ SECURE: Complete Mediation & Ownership Check
@app.get("/api/users/{user_id}")
def get_user(user_id, current_user):
    if current_user.id != user_id and current_user.role != "ADMIN":
        raise HTTPException(status_code=403, detail="Access Denied")
    return database.get_user(user_id)`}
            </pre>
            <p className="text-xs text-emerald-300/80">Result: 403 Forbidden blocking unauthorized access.</p>
          </div>
        </div>
      </div>
    </div>
  );
}
