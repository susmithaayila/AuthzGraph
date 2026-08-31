import { Users, Key, CheckCircle } from 'lucide-react';


interface User {
  id: number;
  name: string;
  role: string;
  email: string;
  department: string;
  region: string;
  clearance: string;
  accountBalance: number;
  internalRiskScore: number;
  isVerified: boolean;
  token: string;
}

interface Props {
  users: User[];
  currentUser: User;
  onSelectUser: (user: User) => void;
}

export function UsersView({ users, currentUser, onSelectUser }: Props) {
  return (
    <div className="space-y-6">
      <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 rounded-xl">
            <Users className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-white">Synthetic User Identity Gallery</h2>
            <p className="text-xs text-slate-400">15 Seeded Fake Users with Roles, Department, Region, and Security Clearance Levels</p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {users.map((user) => {
          const isCurrent = currentUser.id === user.id;

          return (
            <div
              key={user.id}
              className={`p-5 rounded-2xl border transition flex flex-col justify-between space-y-4 ${
                isCurrent ? 'bg-cyan-950/30 border-cyan-500/50 shadow-lg shadow-cyan-950/50' : 'bg-slate-900 border-slate-800 hover:border-slate-700'
              }`}
            >
              <div>
                <div className="flex items-start justify-between">
                  <div>
                    <h3 className="font-bold text-white text-sm">{user.name}</h3>
                    <p className="text-xs text-slate-400 font-mono">ID #{user.id}</p>
                  </div>
                  <span className={`px-2.5 py-0.5 rounded text-[10px] font-bold ${
                    user.role === 'ADMIN' ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30' :
                    user.role === 'MANAGER' ? 'bg-purple-500/20 text-purple-300 border border-purple-500/30' :
                    user.role === 'SUPPORT' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30' :
                    'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                  }`}>
                    {user.role}
                  </span>
                </div>

                <div className="mt-3 space-y-1.5 text-xs">
                  <div className="flex justify-between">
                    <span className="text-slate-400">Department:</span>
                    <span className="text-slate-200 font-medium">{user.department}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Region:</span>
                    <span className="text-slate-200 font-medium">{user.region}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Clearance:</span>
                    <span className="text-emerald-400 font-bold">{user.clearance}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Account Balance:</span>
                    <span className="font-mono text-slate-200">${user.accountBalance?.toLocaleString()}</span>
                  </div>
                </div>
              </div>

              <button
                onClick={() => onSelectUser(user)}
                disabled={isCurrent}
                className={`w-full py-2 text-xs font-bold rounded-xl transition flex items-center justify-center gap-2 ${
                  isCurrent
                    ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 cursor-default'
                    : 'bg-slate-800 hover:bg-slate-700 text-white border border-slate-700'
                }`}
              >
                {isCurrent ? <CheckCircle className="w-4 h-4 text-emerald-400" /> : <Key className="w-4 h-4 text-cyan-400" />}
                {isCurrent ? 'ACTIVE IDENTITY' : 'LOGIN AS THIS USER'}
              </button>
            </div>
          );
        })}
      </div>
    </div>
  );
}
