import { useState } from 'react';


interface GraphNode {
  id: string;
  type: string;
  data: { label: string; details: Record<string, unknown> };
  position: { x: number; y: number };
}

interface GraphEdge {
  id: string;
  source: string;
  target: string;
  label: string;
  animated: boolean;
}

interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

interface GraphExplorerViewProps {
  graphData: GraphData;
}

type Filter = 'ALL' | 'BOLA' | 'BFLA' | 'BOPLA';

export const NODE_STYLE: Record<string, { border: string; label: string; dot: string }> = {

  user:     { border: 'border-emerald-500/80', label: 'text-emerald-400', dot: 'bg-emerald-400' },
  resource: { border: 'border-blue-500/60',    label: 'text-blue-400',    dot: 'bg-blue-400' },
  unknown:  { border: 'border-gray-600',        label: 'text-gray-400',    dot: 'bg-gray-400' },
};

// Attack vectors derived from edge relationships for each filter view
const ATTACK_PATHS: Record<Filter, string> = {
  ALL:   'Showing all graph edges — ownership and attack vectors',
  BOLA:  'Highlighting BOLA attack paths: cross-user object substitution edges',
  BFLA:  'Highlighting BFLA escalation paths: low-privilege → admin endpoint edges',
  BOPLA: 'Highlighting BOPLA exposure paths: sensitive property leakage edges',
};

export const GraphExplorerView: React.FC<GraphExplorerViewProps> = ({ graphData }) => {
  const [filter, setFilter] = useState<Filter>('ALL');

  const { nodes, edges } = graphData;
  const userNodes     = nodes.filter((n) => n.type === 'user');
  const resourceNodes = nodes.filter((n) => n.type === 'resource');
  const otherNodes    = nodes.filter((n) => n.type !== 'user' && n.type !== 'resource');

  const hasData = nodes.length > 0;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center bg-[#151D2A] border border-[#26334D] p-4 rounded-xl">
        <div>
          <h2 className="text-xl font-bold text-white">Multi-User Object Ownership Graph Explorer</h2>
          <p className="text-xs text-gray-400">
            {hasData
              ? `NetworkX-powered live topology — ${userNodes.length} identities, ${resourceNodes.length} resources, ${edges.length} edges`
              : 'NetworkX-powered stateful topology showing Users, Tokens, Resources, and Attack Vectors.'}
          </p>
        </div>
        <div className="flex gap-2">
          {(['ALL', 'BOLA', 'BFLA', 'BOPLA'] as const).map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`px-3 py-1.5 text-xs font-semibold rounded-lg transition-all ${
                filter === f
                  ? 'bg-blue-600 text-white shadow-lg'
                  : 'bg-[#0B0F17] text-gray-400 border border-[#26334D] hover:text-white'
              }`}
            >
              {f === 'ALL' ? 'All Graph Edges' : `${f} Vectors`}
            </button>
          ))}
        </div>
      </div>

      {/* Graph Panel */}
      <div className="bg-[#151D2A] border border-[#26334D] rounded-xl p-6 relative min-h-[480px] flex flex-col justify-between">
        {hasData ? (
          <>
            <p className="text-[11px] text-blue-400/70 font-mono mb-4">{ATTACK_PATHS[filter]}</p>

            <div className="grid grid-cols-1 md:grid-cols-4 gap-6 my-auto">
              {/* Identity Tier */}
              <div className="space-y-4">
                <h4 className="text-xs font-semibold text-gray-400 uppercase tracking-wider">
                  Identities ({userNodes.length})
                </h4>
                {userNodes.length === 0 ? (
                  <p className="text-xs text-gray-600">No user nodes</p>
                ) : (
                  userNodes.map((node) => {
                    const d = node.data.details as Record<string, string>;
                    const isAdmin = (d.role ?? '').includes('ADMIN');
                    const isAttacker = node.id.includes('priya') || node.id.includes('attacker') || node.id === 'user_b';

                    const borderClass = isAdmin
                      ? 'border-purple-500/80 bg-purple-950/20'
                      : isAttacker
                      ? 'border-red-500/80 bg-red-950/20'
                      : 'border-emerald-500/80 bg-emerald-950/20';

                    const labelClass = isAdmin
                      ? 'text-purple-400'
                      : isAttacker
                      ? 'text-red-400 font-bold'
                      : 'text-emerald-400 font-bold';
                    
                    const roleBadge = isAdmin 
                      ? '🔒 Admin' 
                      : isAttacker 
                      ? '🥷 Attacker Node' 
                      : '👤 Victim / Owner';

                    return (
                      <div key={node.id} className={`bg-[#0B0F17] border-2 ${borderClass} rounded-lg p-3 shadow-md space-y-1`}>
                        <div className="flex justify-between items-center">
                          <span className={`text-[10px] font-mono font-bold uppercase ${labelClass}`}>
                            {node.id}
                          </span>
                          <span className={`text-[9px] font-semibold px-1.5 py-0.5 rounded ${labelClass}`}>
                            {roleBadge}
                          </span>
                        </div>
                        <p className="text-sm font-semibold text-white">{d.username || node.id}</p>
                        <p className="text-xs text-gray-400 font-mono">Role: {d.role || 'USER'} (L{d.role_level || '1'})</p>
                      </div>
                    );
                  })
                )}
              </div>

              {/* Session Tokens */}
              <div className="space-y-4">
                <h4 className="text-xs font-semibold text-gray-400 uppercase tracking-wider">Session Tokens</h4>
                {userNodes.map((node) => {
                  const d = node.data.details as Record<string, string>;
                  return (
                    <div key={node.id} className="bg-[#0B0F17] border border-[#26334D] rounded-lg p-3 font-mono text-xs text-gray-300 truncate">
                      {d.token || 'N/A'}
                    </div>
                  );
                })}
              </div>

              {/* Resources */}
              <div className="space-y-4">
                <h4 className="text-xs font-semibold text-gray-400 uppercase tracking-wider">
                  Objects / Resources ({resourceNodes.length})
                </h4>
                {resourceNodes.length === 0 ? (
                  <p className="text-xs text-gray-600">No resource nodes</p>
                ) : (
                  resourceNodes.map((node) => {
                    const d = node.data.details as Record<string, string>;
                    return (
                      <div key={node.id} className="bg-[#0B0F17] border border-blue-500/60 rounded-lg p-3">
                        <span className="text-[10px] font-bold text-blue-400">{d.resource_type || 'Resource'}</span>
                        <p className="text-xs font-mono text-white">{node.id}</p>
                        <p className="text-[10px] text-gray-400">Owner: {d.owner_user_id || 'unknown'}</p>
                        <p className="text-[10px] text-gray-500 font-mono">{d.classification || 'INTERNAL'}</p>
                      </div>
                    );
                  })
                )}
                {otherNodes.map((node) => (
                  <div key={node.id} className="bg-[#0B0F17] border border-gray-600 rounded-lg p-3">
                    <span className="text-[10px] font-bold text-gray-400">{node.type.toUpperCase()}</span>
                    <p className="text-xs font-mono text-white">{node.id}</p>
                  </div>
                ))}
              </div>

              {/* Edges / Attack Vectors */}
              <div className="space-y-4">
                <h4 className="text-xs font-semibold text-gray-400 uppercase tracking-wider">Graph Edges ({edges.length})</h4>
                {edges.map((edge) => (
                  <div key={edge.id} className={`bg-[#0B0F17] rounded-lg p-3 border ${
                    edge.label === 'OWNS' ? 'border-emerald-500/50' : 'border-red-500/50'
                  }`}>
                    <span className={`text-[10px] font-bold ${edge.label === 'OWNS' ? 'text-emerald-400' : 'text-red-400'}`}>
                      {edge.label}
                    </span>
                    <p className="text-[10px] text-gray-300 font-mono mt-0.5 truncate">
                      {edge.source} → {edge.target}
                    </p>
                  </div>
                ))}
              </div>
            </div>
          </>
        ) : (
          /* Fallback static layout when no backend data yet */
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6 my-auto">
            <div className="space-y-4">
              <h4 className="text-xs font-semibold text-gray-400 uppercase tracking-wider">Identities (Users)</h4>
              <div className="bg-[#0B0F17] border-2 border-emerald-500/80 rounded-lg p-3 shadow-md">
                <span className="text-[10px] font-bold text-emerald-400 uppercase">User_A (Owner)</span>
                <p className="text-sm font-semibold text-white">alice</p>
                <p className="text-xs text-gray-400 font-mono">Role: USER_REGULAR (L1)</p>
              </div>
              <div className="bg-[#0B0F17] border-2 border-red-500/80 rounded-lg p-3 shadow-md">
                <span className="text-[10px] font-bold text-red-400 uppercase">User_B (Attacker)</span>
                <p className="text-sm font-semibold text-white">bob_attacker</p>
                <p className="text-xs text-gray-400 font-mono">Role: USER_REGULAR (L1)</p>
              </div>
              <div className="bg-[#0B0F17] border-2 border-purple-500/80 rounded-lg p-3 shadow-md">
                <span className="text-[10px] font-bold text-purple-400 uppercase">User_C (Admin)</span>
                <p className="text-sm font-semibold text-white">charlie_admin</p>
                <p className="text-xs text-gray-400 font-mono">Role: ADMIN (L3)</p>
              </div>
            </div>
            <div className="space-y-4">
              <h4 className="text-xs font-semibold text-gray-400 uppercase tracking-wider">Session Tokens</h4>
              {['token_alice_secret', 'token_bob_attacker', 'token_charlie_admin'].map((t) => (
                <div key={t} className="bg-[#0B0F17] border border-[#26334D] rounded-lg p-3 font-mono text-xs text-gray-300">{t}</div>
              ))}
            </div>
            <div className="space-y-4">
              <h4 className="text-xs font-semibold text-gray-400 uppercase tracking-wider">Objects (NetworkX)</h4>
              <div className="bg-[#0B0F17] border border-blue-500/60 rounded-lg p-3">
                <span className="text-[10px] font-bold text-blue-400">VehicleLocation</span>
                <p className="text-xs font-mono text-white">veh_101</p>
                <p className="text-[10px] text-gray-400">Owner: User_A</p>
              </div>
              <div className="bg-[#0B0F17] border border-blue-500/60 rounded-lg p-3">
                <span className="text-[10px] font-bold text-blue-400">UserProfile</span>
                <p className="text-xs font-mono text-white">profile_alice</p>
                <p className="text-[10px] text-gray-400">Owner: User_A</p>
              </div>
            </div>
            <div className="space-y-4">
              <h4 className="text-xs font-semibold text-gray-400 uppercase tracking-wider">API Endpoints</h4>
              <div className="bg-[#0B0F17] border border-red-500/70 rounded-lg p-3">
                <span className="text-[10px] font-bold text-red-400">GET /vehicle/{'{id}'}/location</span>
                <p className="text-[10px] text-red-300 mt-1">BOLA Substitution Path</p>
              </div>
              <div className="bg-[#0B0F17] border border-amber-500/70 rounded-lg p-3">
                <span className="text-[10px] font-bold text-amber-400">GET /admin/users</span>
                <p className="text-[10px] text-amber-300 mt-1">BFLA Escalation Path</p>
              </div>
            </div>
          </div>
        )}

        {/* Legend */}
        <div className="flex gap-4 text-xs text-gray-400 border-t border-[#26334D] pt-4 mt-6 flex-wrap">
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-0.5 bg-emerald-500 inline-block" /> Valid Ownership Edge (User A → resource)
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-0.5 bg-red-500 inline-block" /> Unauthorized BOLA Attack Path
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-0.5 bg-amber-500 inline-block" /> BFLA Privilege Escalation
          </div>
        </div>
      </div>
    </div>
  );
};
