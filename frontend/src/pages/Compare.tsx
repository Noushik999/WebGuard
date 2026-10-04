import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { api, type Comparison } from '../api';
import { Layout, SeverityBadge, Empty } from '../components/ui';

export default function ComparePage() {
  const { aId, bId } = useParams();
  const [c, setC] = useState<Comparison | null>(null);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!aId || !bId) return;
    api.compare(+aId, +bId).then(setC).catch(e => setError(e.message));
  }, [aId, bId]);

  return (
    <Layout>
      <h1 className="text-2xl font-bold mb-1">Scan comparison</h1>
      <p className="text-slate-400 text-sm mb-6">Assessment #{aId} → #{bId}</p>
      {error && <div className="text-red-400 mb-4">{error}</div>}
      {!c && !error && <div className="text-slate-400">Loading…</div>}
      {c && (
        <>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-6">
            <div className="card p-5 text-center">
              <div className="text-3xl font-bold">{c.score_a ?? '—'}</div>
              <div className="text-xs text-slate-400 mt-1">Previous score</div>
            </div>
            <div className="card p-5 text-center">
              <div className="text-3xl font-bold">{c.score_b ?? '—'}</div>
              <div className="text-xs text-slate-400 mt-1">Current score</div>
            </div>
            <div className="card p-5 text-center">
              <div className={`text-3xl font-bold ${(c.score_delta ?? 0) >= 0 ? 'text-emerald-400' : 'text-red-400'}`}>
                {(c.score_delta ?? 0) >= 0 ? '+' : ''}{c.score_delta ?? '—'}
              </div>
              <div className="text-xs text-slate-400 mt-1">Score change</div>
            </div>
            <div className="card p-5 text-center">
              <div className="text-3xl font-bold text-emerald-400">{c.resolved_count}</div>
              <div className="text-xs text-slate-400 mt-1">Resolved</div>
            </div>
            <div className="card p-5 text-center">
              <div className="text-3xl font-bold text-amber-400">{c.new_count}</div>
              <div className="text-xs text-slate-400 mt-1">New</div>
            </div>
          </div>

          {c.new_count === 0 && c.resolved_count === 0 ? (
            <Empty title="No changes" hint="The same findings persist across both scans. Nothing new, nothing resolved." />
          ) : (
            <div className="grid md:grid-cols-2 gap-4">
              <div className="card p-6">
                <div className="font-semibold mb-3 text-emerald-300">✅ Resolved ({c.resolved_count})</div>
                {c.resolved.map(f => (
                  <div key={f.fingerprint} className="flex items-center gap-3 py-2 border-b border-[#232f4d] last:border-0">
                    <SeverityBadge severity={f.severity} />
                    <div className="text-sm">{f.title}</div>
                  </div>
                ))}
              </div>
              <div className="card p-6">
                <div className="font-semibold mb-3 text-amber-300">🆕 New ({c.new_count})</div>
                {c.new.map(f => (
                  <Link key={f.fingerprint} to={`/findings/${f.finding_id}`} className="flex items-center gap-3 py-2 border-b border-[#232f4d] last:border-0 hover:bg-[#1a2338] rounded px-1">
                    <SeverityBadge severity={f.severity} />
                    <div className="text-sm">{f.title}</div>
                  </Link>
                ))}
              </div>
            </div>
          )}

          {c.severity_changes.length > 0 && (
            <div className="card p-6 mt-4">
              <div className="font-semibold mb-3">Severity changes ({c.severity_changes.length})</div>
              {c.severity_changes.map(f => (
                <div key={f.fingerprint} className="flex items-center gap-3 py-2 border-b border-[#232f4d] last:border-0 text-sm">
                  <span className="flex-1">{f.title}</span>
                  <SeverityBadge severity={f.old_severity} />
                  <span>→</span>
                  <SeverityBadge severity={f.new_severity} />
                </div>
              ))}
            </div>
          )}

          <div className="card p-6 mt-4">
            <div className="font-semibold mb-3 text-slate-300">Persistent ({c.persistent_count})</div>
            <div className="text-sm text-slate-500">Still present in both scans — these need attention.</div>
            {c.persistent.slice(0, 12).map(f => (
              <div key={f.fingerprint} className="flex items-center gap-3 py-1.5 text-sm">
                <SeverityBadge severity={f.new_severity} />
                <span className="truncate">{f.title}</span>
              </div>
            ))}
          </div>
        </>
      )}
    </Layout>
  );
}
