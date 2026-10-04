import { useEffect, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { api, type AssessmentDetail, type Finding } from '../api';
import { Layout, ScoreRing, SeverityBadge, StatusPill, SEV_ORDER, DemoBanner, Empty } from '../components/ui';

const STAGE_LABELS: Record<string, string> = {
  VALIDATING: 'Validating target', COLLECTING: 'Collecting responses', RUNNING: 'Running security checks',
  ANALYZING: 'Analyzing findings', GENERATING_RESULTS: 'Generating results', COMPLETED: 'Completed',
};

export function AssessmentPage() {
  const { id } = useParams();
  const [a, setA] = useState<AssessmentDetail | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [sevFilter, setSevFilter] = useState<string>('');
  const [error, setError] = useState('');
  const [reportBusy, setReportBusy] = useState(false);
  const [compareWith, setCompareWith] = useState('');
  const [history, setHistory] = useState<{ id: number }[]>([]);
  const nav = useNavigate();

  useEffect(() => {
    if (!id) return;
    let timer: ReturnType<typeof setInterval>;
    const load = async () => {
      try {
        const det = await api.assessment(+id);
        setA(det);
        if (det.status === 'COMPLETED') {
          const f = await api.findings(+id, sevFilter || undefined);
          setFindings(f);
          clearInterval(timer);
        }
      } catch (e: unknown) { setError(e instanceof Error ? e.message : 'Failed'); clearInterval(timer); }
    };
    load();
    timer = setInterval(load, 2000);
    return () => clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id, sevFilter]);

  useEffect(() => {
    if (!id || !a) return;
    api.assessments()
      .then(all => setHistory(all
        .filter(x => x.target_id === a.target_id && x.status === 'COMPLETED' && x.id !== +id)
        .map(x => ({ id: x.id }))))
      .catch(() => {});
  }, [id, a]);

  async function genReport() {
    if (!id) return;
    setReportBusy(true);
    try {
      await api.generateReport(+id);
      window.open(api.reportUrl(+id), '_blank');
    } catch (e: unknown) { setError(e instanceof Error ? e.message : 'Failed'); }
    finally { setReportBusy(false); }
  }

  return (
    <Layout>
      {error && <div className="text-red-400 mb-4">{error}</div>}
      {!a ? <div className="text-slate-400">Loading…</div> : (
        <>
          {a.is_demo && <DemoBanner />}
          <div className="flex items-start justify-between gap-4 mb-6 flex-wrap">
            <div>
              <div className="flex items-center gap-3">
                <h1 className="text-2xl font-bold">Assessment #{a.id}</h1>
                <StatusPill status={a.status} />
              </div>
              <Link to={`/targets/${a.target_id}`} className="text-blue-400 text-sm hover:underline">{a.target_name}</Link>
              <div className="text-xs text-slate-500 mt-1">
                {new Date(a.created_at).toLocaleString()} · Scanner v{a.scanner_version}
                {a.duration_s ? ` · ${a.duration_s.toFixed(1)}s` : ''}
              </div>
            </div>
            <div className="flex gap-2">
              {a.status === 'COMPLETED' && (
                <>
                  <button className="btn-ghost" onClick={genReport} disabled={reportBusy}>{reportBusy ? 'Generating…' : '📄 Generate report'}</button>
                  <button className="btn-ghost" onClick={async () => { const n = await api.rescan(a.id); nav(`/assessments/${n.id}`); }}>🔁 Rescan</button>
                </>
              )}
              {!['COMPLETED', 'FAILED', 'CANCELLED'].includes(a.status) && (
                <button className="btn-ghost" onClick={() => api.cancelAssessment(a.id)}>Cancel</button>
              )}
            </div>
          </div>

          {!['COMPLETED', 'FAILED', 'CANCELLED'].includes(a.status) && (
            <div className="card p-6 mb-6">
              <div className="flex items-center justify-between mb-2">
                <div className="font-semibold scan-pulse">{STAGE_LABELS[a.current_stage] || a.current_stage || 'Working…'}</div>
                <div className="font-bold">{a.progress}%</div>
              </div>
              <div className="h-3 rounded-full bg-[#232f4d] overflow-hidden">
                <div className="h-full rounded-full transition-all duration-500" style={{ width: `${a.progress}%`, background: 'linear-gradient(90deg,#3b82f6,#8b5cf6)' }} />
              </div>
              <div className="text-xs text-slate-500 mt-2">Passive checks only — nothing is exploited or modified on the target.</div>
            </div>
          )}

          {a.status === 'FAILED' && (
            <div className="card p-6 mb-6 border-red-500/40">
              <div className="font-semibold text-red-300">Assessment failed</div>
              <div className="text-sm text-slate-400 mt-1">{a.error || 'Unknown error'}</div>
            </div>
          )}

          {a.status === 'COMPLETED' && (
            <>
              <div className="grid md:grid-cols-3 gap-4 mb-6">
                <div className="card p-6 flex items-center gap-5">
                  <ScoreRing score={a.score} size={110} />
                  <div>
                    <div className="font-semibold">Security score</div>
                    <div className="text-sm text-slate-400">{a.grade}</div>
                    <div className="text-xs text-slate-500 mt-1">{a.findings_count} findings</div>
                  </div>
                </div>
                <div className="card p-6">
                  <div className="font-semibold mb-2">Severity breakdown</div>
                  {SEV_ORDER.map(s => (
                    <div key={s} className="flex items-center gap-2 py-1 text-sm">
                      <SeverityBadge severity={s} />
                      <span className="ml-auto font-semibold">{a.severity_counts[s] || 0}</span>
                    </div>
                  ))}
                </div>
                <div className="card p-6">
                  <div className="font-semibold mb-2">Compare with previous</div>
                  <select className="input" value={compareWith} onChange={e => setCompareWith(e.target.value)}>
                    <option value="">Select assessment…</option>
                    {history.map(h => <option key={h.id} value={h.id}>Assessment #{h.id}</option>)}
                  </select>
                  <button className="btn-primary mt-3 w-full" disabled={!compareWith}
                    onClick={() => nav(`/compare/${compareWith}/${a.id}`)}>Compare scans</button>
                  {Object.keys(a.module_errors).length > 0 && (
                    <div className="text-xs text-amber-300 mt-3">Some modules reported issues: {Object.keys(a.module_errors).join(', ')}</div>
                  )}
                </div>
              </div>

              <div className="flex gap-2 mb-4 flex-wrap">
                <button onClick={() => setSevFilter('')} className={`px-3 py-1.5 rounded-full text-sm border ${!sevFilter ? 'bg-blue-600 border-blue-600 text-white' : 'border-[#2a3757] text-slate-300'}`}>All</button>
                {SEV_ORDER.map(s => (
                  <button key={s} onClick={() => setSevFilter(s)}
                    className={`px-3 py-1.5 rounded-full text-sm border ${sevFilter === s ? 'bg-blue-600 border-blue-600 text-white' : 'border-[#2a3757] text-slate-300'}`}>
                    {s} ({a.severity_counts[s] || 0})
                  </button>
                ))}
              </div>

              {findings.length === 0 ? (
                <Empty title="No findings" hint="The target passed all of WebGuard's checks. Nice work." />
              ) : (
                <div className="card divide-y divide-[#232f4d]">
                  {findings.map(f => (
                    <Link key={f.id} to={`/findings/${f.id}`} className="flex items-center gap-4 p-4 hover:bg-[#1a2338]">
                      <SeverityBadge severity={f.severity} />
                      <div className="flex-1 min-w-0">
                        <div className="font-medium truncate">{f.title}</div>
                        <div className="text-xs text-slate-500">{f.category} · {f.owasp_mapping} · {Math.round(f.confidence * 100)}% confidence</div>
                      </div>
                      {f.status !== 'Open' && <span className="text-xs text-slate-400 border border-[#2a3757] rounded-full px-2 py-0.5">{f.status}</span>}
                    </Link>
                  ))}
                </div>
              )}

              {a.score_breakdown.length > 0 && (
                <div className="card p-6 mt-6">
                  <div className="font-semibold mb-2">How the score was calculated</div>
                  <p className="text-xs text-slate-500 mb-3">Each finding deducts <em>severity weight × confidence</em> (Critical 25 · High 15 · Medium 8 · Low 3 · Informational 0). The score measures only the checks WebGuard performs.</p>
                  <div className="text-sm">
                    {a.score_breakdown.slice(0, 10).map((d, i) => (
                      <div key={i} className="flex justify-between py-1 border-b border-[#232f4d] last:border-0">
                        <span className="truncate mr-4">{d.title}</span>
                        <span className="text-red-300 shrink-0">−{d.deduction}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </>
          )}
        </>
      )}
    </Layout>
  );
}

export function HistoryPage() {
  const [list, setList] = useState<import('../api').AssessmentSummary[]>([]);
  useEffect(() => { api.assessments().then(setList).catch(() => {}); }, []);
  return (
    <Layout>
      <h1 className="text-2xl font-bold mb-6">Assessment history</h1>
      {list.length === 0 ? <Empty title="No assessments yet" hint="Assessments you run will appear here." /> : (
        <div className="card divide-y divide-[#232f4d]">
          {list.map(a => (
            <Link key={a.id} to={`/assessments/${a.id}`} className="flex items-center gap-4 p-4 hover:bg-[#1a2338]">
              <StatusPill status={a.status} />
              <div className="flex-1">
                <div className="font-medium">#{a.id} — {a.target_name} {a.is_demo && <span className="badge sev-Medium ml-1">DEMO</span>}</div>
                <div className="text-xs text-slate-500">{new Date(a.created_at).toLocaleString()} · {a.findings_count} findings</div>
              </div>
              {a.score !== null && <div className="text-xl font-bold">{a.score}<span className="text-sm text-slate-500">/100</span></div>}
            </Link>
          ))}
        </div>
      )}
    </Layout>
  );
}
