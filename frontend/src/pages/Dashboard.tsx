import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { api, type Dashboard as Dash } from '../api';
import { Layout, StatCard, ScoreRing, SeverityBadge, StatusPill, SEV_ORDER, SEV_COLORS, Empty, ResponsibleUseNotice } from '../components/ui';
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';

export default function DashboardPage() {
  const [d, setD] = useState<Dash | null>(null);
  const [error, setError] = useState('');

  useEffect(() => { api.dashboard().then(setD).catch(e => setError(e.message)); }, []);

  return (
    <Layout>
      <h1 className="text-2xl font-bold mb-1">Security Dashboard</h1>
      <p className="text-slate-400 text-sm mb-6">Your authorized targets at a glance.</p>
      <ResponsibleUseNotice />
      {error && <div className="text-red-400 mb-4">{error}</div>}
      {!d && !error && <div className="text-slate-400">Loading…</div>}
      {d && (
        <>
          {d.target_count === 0 ? (
            <Empty title="No targets yet"
              hint="Add a website you own (or are authorized to test) and run your first passive security assessment."
              action={<Link to="/targets" className="btn-primary inline-block">Add your first target</Link>} />
          ) : (
            <>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                <StatCard label="Targets" value={d.target_count} />
                <StatCard label="Assessments" value={d.assessment_count} />
                <StatCard label="Running now" value={d.running_count} />
                <StatCard label="Open critical findings" value={d.severity_totals['Critical'] || 0} accent="#f04452" />
              </div>

              <div className="grid md:grid-cols-3 gap-4 mb-6">
                <div className="card p-6 flex flex-col items-center justify-center">
                  <div className="text-sm text-slate-400 mb-2">Latest security score</div>
                  <ScoreRing score={d.latest_score} size={140} />
                  <div className="text-xs text-slate-500 mt-3 text-center max-w-[220px]">
                    Measures only the checks WebGuard performs — not a guarantee of security.
                  </div>
                </div>
                <div className="card p-6">
                  <div className="text-sm text-slate-400 mb-2">Findings by severity</div>
                  {SEV_ORDER.map(s => (
                    <div key={s} className="flex items-center gap-3 py-1.5">
                      <SeverityBadge severity={s} />
                      <div className="flex-1 h-2 rounded bg-[#232f4d] overflow-hidden">
                        <div className="h-full rounded" style={{
                          width: `${Math.min(100, ((d.severity_totals[s] || 0) / Math.max(1, ...Object.values(d.severity_totals))) * 100)}%`,
                          background: SEV_COLORS[s],
                        }} />
                      </div>
                      <div className="w-8 text-right font-semibold">{d.severity_totals[s] || 0}</div>
                    </div>
                  ))}
                </div>
                <div className="card p-6">
                  <div className="text-sm text-slate-400 mb-2">Score history</div>
                  {d.score_history.length > 1 ? (
                    <ResponsiveContainer width="100%" height={180}>
                      <LineChart data={d.score_history.map(h => ({ ...h, label: `#${h.assessment_id}` }))}>
                        <XAxis dataKey="label" tick={{ fill: '#93a0b8', fontSize: 11 }} />
                        <YAxis domain={[0, 100]} tick={{ fill: '#93a0b8', fontSize: 11 }} />
                        <Tooltip contentStyle={{ background: '#141b2e', border: '1px solid #232f4d' }} />
                        <Line type="monotone" dataKey="score" stroke="#3b82f6" strokeWidth={2} dot={false} />
                      </LineChart>
                    </ResponsiveContainer>
                  ) : (
                    <div className="text-slate-500 text-sm py-8 text-center">Run more assessments to see trends.</div>
                  )}
                </div>
              </div>

              <div className="grid md:grid-cols-2 gap-4">
                <div className="card p-6">
                  <div className="font-semibold mb-3">Top findings <span className="text-slate-500 font-normal text-sm">(latest scan per target)</span></div>
                  {d.top_findings.length === 0 && <div className="text-slate-500 text-sm">No findings — nice.</div>}
                  {d.top_findings.map(f => (
                    <Link key={f.id} to={`/findings/${f.id}`} className="flex items-center gap-3 py-2 border-b border-[#232f4d] last:border-0 hover:bg-[#1a2338] rounded px-2">
                      <SeverityBadge severity={f.severity} />
                      <div className="flex-1 min-w-0">
                        <div className="truncate text-sm">{f.title}</div>
                        <div className="text-xs text-slate-500">{f.target_name} · {f.category}</div>
                      </div>
                    </Link>
                  ))}
                </div>
                <div className="card p-6">
                  <div className="font-semibold mb-3">Recent assessments</div>
                  {d.recent_assessments.map(a => (
                    <Link key={a.id} to={`/assessments/${a.id}`} className="flex items-center gap-3 py-2 border-b border-[#232f4d] last:border-0 hover:bg-[#1a2338] rounded px-2">
                      <StatusPill status={a.status} />
                      <div className="flex-1 min-w-0">
                        <div className="truncate text-sm">#{a.id} — {a.target_name}</div>
                        <div className="text-xs text-slate-500">{new Date(a.created_at).toLocaleString()}</div>
                      </div>
                      {a.score !== null && <div className="font-bold">{a.score}</div>}
                    </Link>
                  ))}
                </div>
              </div>
            </>
          )}
        </>
      )}
    </Layout>
  );
}
