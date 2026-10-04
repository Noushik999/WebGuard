import { Link, useNavigate } from 'react-router-dom';
import { isAuthed, setToken, type Severity } from '../api';

export const SEV_ORDER: Severity[] = ['Critical', 'High', 'Medium', 'Low', 'Informational'];
export const SEV_COLORS: Record<Severity, string> = {
  Critical: '#f04452', High: '#f5853c', Medium: '#f5c542', Low: '#4aa8ff', Informational: '#8b93a7',
};

export function SeverityBadge({ severity }: { severity: string }) {
  return <span className={`badge sev-${severity}`}>{severity}</span>;
}

export function ScoreRing({ score, size = 120 }: { score: number | null; size?: number }) {
  if (score === null || score === undefined)
    return <div className="text-slate-500">—</div>;
  const color = score >= 90 ? '#4ade80' : score >= 75 ? '#a3e635' : score >= 60 ? '#f5c542' : score >= 40 ? '#f5853c' : '#f04452';
  const r = 54, circ = 2 * Math.PI * r;
  return (
    <svg width={size} height={size} viewBox="0 0 120 120">
      <circle cx="60" cy="60" r={r} fill="none" stroke="#232f4d" strokeWidth="10" />
      <circle cx="60" cy="60" r={r} fill="none" stroke={color} strokeWidth="10"
        strokeDasharray={circ} strokeDashoffset={circ - (circ * score) / 100}
        strokeLinecap="round" transform="rotate(-90 60 60)" />
      <text x="60" y="58" textAnchor="middle" fill="#e8edf5" fontSize="28" fontWeight="800">{score}</text>
      <text x="60" y="78" textAnchor="middle" fill="#93a0b8" fontSize="11">/ 100</text>
    </svg>
  );
}

export function StatCard({ label, value, accent }: { label: string; value: React.ReactNode; accent?: string }) {
  return (
    <div className="card p-5">
      <div className="text-3xl font-bold" style={accent ? { color: accent } : undefined}>{value}</div>
      <div className="text-sm text-slate-400 mt-1">{label}</div>
    </div>
  );
}

export function Empty({ title, hint, action }: { title: string; hint?: string; action?: React.ReactNode }) {
  return (
    <div className="card p-10 text-center">
      <div className="text-lg font-semibold">{title}</div>
      {hint && <div className="text-slate-400 text-sm mt-2 max-w-md mx-auto">{hint}</div>}
      {action && <div className="mt-5">{action}</div>}
    </div>
  );
}

export function DemoBanner() {
  return (
    <div className="rounded-xl border border-amber-400/60 bg-amber-950/40 text-amber-300 px-4 py-3 text-sm font-semibold mb-5">
      DEMO / SAMPLE — findings shown here are simulated for demonstration purposes.
    </div>
  );
}

const NAV = [
  { to: '/', label: 'Dashboard', icon: '📊' },
  { to: '/targets', label: 'Targets', icon: '🎯' },
  { to: '/assessments', label: 'History', icon: '🕘' },
  { to: '/demo', label: 'Demo', icon: '🧪' },
];

export function Layout({ children }: { children: React.ReactNode }) {
  const nav = useNavigate();
  if (!isAuthed()) { window.location.href = '/login'; return null; }
  return (
    <div className="min-h-screen flex">
      <aside className="w-60 shrink-0 border-r border-[#232f4d] p-5 hidden md:flex flex-col gap-1">
        <Link to="/" className="flex items-center gap-3 mb-8 px-2">
          <div className="w-10 h-10 rounded-xl flex items-center justify-center text-2xl"
            style={{ background: 'linear-gradient(135deg,#3b82f6,#8b5cf6)' }}>🛡️</div>
          <div><div className="font-bold text-lg leading-none">WebGuard</div>
            <div className="text-xs text-slate-500">Security Assessment</div></div>
        </Link>
        {NAV.map(n => (
          <Link key={n.to} to={n.to}
            className="px-3 py-2.5 rounded-lg text-slate-300 hover:bg-[#1a2338] flex gap-3 items-center">
            <span>{n.icon}</span>{n.label}
          </Link>
        ))}
        <div className="mt-auto">
          <button className="btn-ghost w-full text-sm" onClick={() => { setToken(null); nav('/login'); }}>
            Sign out
          </button>
        </div>
      </aside>
      <main className="flex-1 p-6 md:p-8 max-w-6xl w-full mx-auto">{children}</main>
    </div>
  );
}

export function StatusPill({ status }: { status: string }) {
  const colors: Record<string, string> = {
    COMPLETED: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/40',
    FAILED: 'bg-red-500/15 text-red-300 border-red-500/40',
    CANCELLED: 'bg-slate-500/15 text-slate-300 border-slate-500/40',
  };
  const c = colors[status] || 'bg-blue-500/15 text-blue-300 border-blue-500/40 scan-pulse';
  return <span className={`text-xs font-semibold px-2.5 py-1 rounded-full border ${c}`}>{status.replace(/_/g, ' ')}</span>;
}

export function ResponsibleUseNotice() {
  return (
    <div className="rounded-xl border border-blue-500/30 bg-blue-950/30 text-blue-200/90 px-4 py-3 text-sm mb-5">
      ⚠️ <strong>Responsible use:</strong> only assess systems you own or have explicit authorization to test.
      WebGuard performs passive, non-destructive checks and blocks internal-network targets by default.
    </div>
  );
}
