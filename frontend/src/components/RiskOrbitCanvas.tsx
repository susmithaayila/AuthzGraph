import { useEffect, useRef, useState } from 'react';
import type { Finding } from '../App';



interface EndpointRiskNode {
  id: string;
  path: string;
  method: string;
  risk_score: number;
  owasp_category: string;
  cve_analog?: string;
  sensitivity: string;
}

// Static fallback displayed when no findings are available yet
const FALLBACK_ENDPOINTS: EndpointRiskNode[] = [
  { id: '1', path: '/identity/api/v2/vehicle/{id}/location', method: 'GET', risk_score: 0.92, owasp_category: 'API1:2023 BOLA', cve_analog: 'CVE-2022-24706', sensitivity: 'RESTRICTED' },
  { id: '2', path: '/identity/api/v2/admin/users', method: 'GET', risk_score: 0.88, owasp_category: 'API5:2023 BFLA', cve_analog: 'CVE-2023-28432', sensitivity: 'RESTRICTED' },
  { id: '3', path: '/identity/api/v2/user/profile', method: 'GET', risk_score: 0.65, owasp_category: 'API3:2023 BOPLA', cve_analog: 'CVE-2021-43798', sensitivity: 'CONFIDENTIAL' },
  { id: '4', path: '/community/api/v1/posts', method: 'POST', risk_score: 0.15, owasp_category: 'API6:2023 Mass Assignment', sensitivity: 'INTERNAL' },
  { id: '5', path: '/mechanic/api/v1/services', method: 'GET', risk_score: 0.05, owasp_category: 'Clean', sensitivity: 'PUBLIC' },
  { id: '6', path: '/health', method: 'GET', risk_score: 0.0, owasp_category: 'Clean', sensitivity: 'PUBLIC' },
  { id: '7', path: '/identity/api/v2/user/login', method: 'POST', risk_score: 0.08, owasp_category: 'Clean', sensitivity: 'INTERNAL' },
  { id: '8', path: '/workshop/api/v1/orders', method: 'PUT', risk_score: 0.78, owasp_category: 'API1:2023 BOLA', cve_analog: 'CVE-2022-26134', sensitivity: 'CONFIDENTIAL' },
];

// Convert real findings → risk nodes (one node per unique endpoint)
function findingsToRiskNodes(findings: Finding[]): EndpointRiskNode[] {
  const seen = new Set<string>();
  const nodes: EndpointRiskNode[] = [];

  findings.forEach((f, i) => {
    const key = `${f.http_method}:${f.endpoint_path}`;
    if (!seen.has(key)) {
      seen.add(key);
      nodes.push({
        id: String(i + 1),
        path: f.endpoint_path,
        method: f.http_method,
        risk_score: Math.min(1.0, f.cvss_score / 10),
        owasp_category: f.owasp_category,
        cve_analog: f.cve_analog || undefined,
        sensitivity: f.cvss_score >= 8 ? 'RESTRICTED' : f.cvss_score >= 5 ? 'CONFIDENTIAL' : 'INTERNAL',
      });
    }
  });

  // Pad with some clean endpoints to populate the orbit visually
  if (nodes.length < 6) {
    nodes.push(
      { id: 'f-health', path: '/health', method: 'GET', risk_score: 0.0, owasp_category: 'Clean', sensitivity: 'PUBLIC' },
      { id: 'f-login', path: '/identity/api/v2/user/login', method: 'POST', risk_score: 0.08, owasp_category: 'Clean', sensitivity: 'INTERNAL' },
      { id: 'f-posts', path: '/community/api/v1/posts', method: 'GET', risk_score: 0.05, owasp_category: 'Clean', sensitivity: 'PUBLIC' },
    );
  }

  return nodes;
}

interface RiskOrbitCanvasProps {
  findings: Finding[];
}

export const RiskOrbitCanvas: React.FC<RiskOrbitCanvasProps> = ({ findings }) => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const [selectedNode, setSelectedNode] = useState<EndpointRiskNode | null>(null);
  const nodesRef = useRef<EndpointRiskNode[]>([]);
  const nodePositionsRef = useRef<Array<{ x: number; y: number; node: EndpointRiskNode }>>([]);

  // Derive nodes from real findings or fallback
  const endpoints = findings.length > 0 ? findingsToRiskNodes(findings) : FALLBACK_ENDPOINTS;
  nodesRef.current = endpoints;

  // Auto-select first node when endpoints change
  useEffect(() => {
    setSelectedNode(endpoints[0] ?? null);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [findings.length]);

  // Canvas click handler
  const handleCanvasClick = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const scaleX = canvas.width / rect.width;
    const scaleY = canvas.height / rect.height;
    const mx = (e.clientX - rect.left) * scaleX;
    const my = (e.clientY - rect.top) * scaleY;

    for (const pos of nodePositionsRef.current) {
      const dist = Math.hypot(pos.x - mx, pos.y - my);
      if (dist <= 14) {
        setSelectedNode(pos.node);
        return;
      }
    }
  };

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationFrameId: number;
    let angleOffset = 0;

    const render = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      const centerX = canvas.width / 2;
      const centerY = canvas.height / 2;
      const maxRadius = Math.min(centerX, centerY) - 40;

      // Draw concentric rings
      const rings = [0.2, 0.4, 0.6, 0.8, 1.0];
      rings.forEach((level) => {
        const r = maxRadius * level;
        ctx.beginPath();
        ctx.arc(centerX, centerY, r, 0, Math.PI * 2);
        ctx.setLineDash([4, 4]);
        ctx.strokeStyle = level === 0.2 ? '#EF4444' : level === 0.4 ? '#F97316' : '#26334D';
        ctx.lineWidth = level === 0.2 || level === 0.4 ? 1.5 : 1;
        ctx.stroke();
      });
      ctx.setLineDash([]);

      // Critical zone fill
      ctx.beginPath();
      ctx.arc(centerX, centerY, maxRadius * 0.2, 0, Math.PI * 2);
      ctx.fillStyle = 'rgba(239, 68, 68, 0.08)';
      ctx.fill();

      // Labels
      ctx.fillStyle = '#94A3B8';
      ctx.font = '10px Inter';
      ctx.fillText('CRITICAL RISK (CENTER)', centerX - 55, centerY - maxRadius * 0.15);
      ctx.fillText('CLEAN / SAFE (OUTER)', centerX - 55, centerY - maxRadius * 0.95);

      // Nodes
      angleOffset += 0.002;
      const currentEndpoints = nodesRef.current;
      const newPositions: Array<{ x: number; y: number; node: EndpointRiskNode }> = [];

      currentEndpoints.forEach((ep, index) => {
        const radius = maxRadius * Math.max(0.15, 1.0 - ep.risk_score);
        const baseAngle = (index / currentEndpoints.length) * Math.PI * 2;
        const currentAngle = baseAngle + angleOffset;

        const x = centerX + radius * Math.cos(currentAngle);
        const y = centerY + radius * Math.sin(currentAngle);
        newPositions.push({ x, y, node: ep });

        const nodeRadius = ep.risk_score > 0.7 ? 10 : 7;
        ctx.beginPath();
        ctx.arc(x, y, nodeRadius, 0, Math.PI * 2);
        const nodeColor = ep.risk_score > 0.7 ? '#EF4444' : ep.risk_score > 0.4 ? '#F59E0B' : '#10B981';
        ctx.fillStyle = nodeColor;
        ctx.shadowColor = nodeColor;
        ctx.shadowBlur = ep.risk_score > 0.7 ? 12 : 4;
        ctx.fill();
        ctx.shadowBlur = 0;

        // Selected ring
        if (selectedNode?.id === ep.id) {
          ctx.beginPath();
          ctx.arc(x, y, 14, 0, Math.PI * 2);
          ctx.strokeStyle = '#2563EB';
          ctx.lineWidth = 2;
          ctx.stroke();
        }

        ctx.fillStyle = '#F8FAFC';
        ctx.font = '10px JetBrains Mono, monospace';
        ctx.fillText(ep.method, x + 12, y + 4);
      });

      nodePositionsRef.current = newPositions;
      animationFrameId = requestAnimationFrame(render);
    };

    render();
    return () => cancelAnimationFrame(animationFrameId);
  }, [selectedNode, findings]);

  return (
    <div className="bg-[#151D2A] border border-[#26334D] rounded-xl p-5 shadow-lg">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="text-lg font-semibold text-white flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-red-500 animate-pulse" />
            Real-Time API Risk Orbit
            {findings.length > 0 && (
              <span className="text-[10px] font-mono text-blue-400 bg-blue-950 px-1.5 py-0.5 rounded border border-blue-800 ml-1">
                LIVE — {findings.length} finding{findings.length !== 1 ? 's' : ''}
              </span>
            )}
          </h3>
          <p className="text-xs text-gray-400 mt-1">
            {findings.length > 0
              ? 'Orbit populated from live scan results. Critical APIs pull toward the center.'
              : 'Radial Threat Surface: Critical risk APIs pull toward center. Safe APIs sit on outer ring.'}
          </p>
        </div>
        <div className="flex gap-2 text-xs">
          <span className="px-2 py-1 bg-red-950/50 border border-red-800 text-red-400 rounded">Critical ({'>'}0.7)</span>
          <span className="px-2 py-1 bg-amber-950/50 border border-amber-800 text-amber-400 rounded">Medium (0.4–0.7)</span>
          <span className="px-2 py-1 bg-emerald-950/50 border border-emerald-800 text-emerald-400 rounded">Safe ({'<'}0.4)</span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-center">
        <div className="lg:col-span-2 flex justify-center relative">
          <canvas
            ref={canvasRef}
            width={460}
            height={360}
            className="max-w-full cursor-pointer"
            onClick={handleCanvasClick}
          />
        </div>

        <div className="bg-[#0B0F17] border border-[#26334D] rounded-lg p-4 text-sm">
          <h4 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">Endpoint Inspector</h4>
          {selectedNode ? (
            <div className="space-y-3">
              <div>
                <span className="text-xs px-2 py-0.5 rounded font-mono bg-blue-950 text-blue-400 border border-blue-800">
                  {selectedNode.method}
                </span>
                <p className="text-xs font-mono text-white mt-1.5 break-all">{selectedNode.path}</p>
              </div>
              <div className="flex justify-between items-center border-t border-[#26334D] pt-2">
                <span className="text-xs text-gray-400">Risk Score:</span>
                <span className={`font-bold ${selectedNode.risk_score > 0.7 ? 'text-red-400' : selectedNode.risk_score > 0.4 ? 'text-amber-400' : 'text-emerald-400'}`}>
                  {(selectedNode.risk_score * 100).toFixed(0)}% ({selectedNode.risk_score.toFixed(2)})
                </span>
              </div>
              <div className="flex justify-between items-center border-t border-[#26334D] pt-2">
                <span className="text-xs text-gray-400">OWASP Risk:</span>
                <span className="text-xs text-blue-300 font-medium text-right max-w-[140px]">{selectedNode.owasp_category}</span>
              </div>
              {selectedNode.cve_analog && (
                <div className="flex justify-between items-center border-t border-[#26334D] pt-2">
                  <span className="text-xs text-gray-400">CVE Analog:</span>
                  <span className="text-xs text-red-400 font-mono">{selectedNode.cve_analog}</span>
                </div>
              )}
              <div className="flex justify-between items-center border-t border-[#26334D] pt-2">
                <span className="text-xs text-gray-400">Classification:</span>
                <span className="text-xs text-gray-300 font-mono">{selectedNode.sensitivity}</span>
              </div>
            </div>
          ) : (
            <p className="text-xs text-gray-500">Click a node on the orbit canvas to inspect endpoint risk payload.</p>
          )}
        </div>
      </div>
    </div>
  );
};
