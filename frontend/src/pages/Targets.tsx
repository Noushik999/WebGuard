import { useEffect, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { api, type Target, type AssessmentSummary } from '../api';
import { Layout, ScoreRing, StatusPill, Empty, ResponsibleUseNotice } from '../components/ui';

export function TargetsPage() {
  const [targets, setTargets] = useState<Target[]>([]);
  const [error, setError] = useState('');
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({ name: '', url: '', description: '', scope: '', auth: false });
  const [busy, setBusy] = useState(false);
  const nav = useNavigate();

  const load = () => api.targets().then(setTargets).catch(e => setError(e.message));
  useEffect(() => { load(); }, []);

  async function create(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true); setError('');
    try {
      const t = await api.createTarget({ name: form.name, url: form.url, description: form.description, scope: form.scope, auth_confirmed: form.auth });
      nav(`/targets/${t.id}`);
    } catch (err: unknown) { setError(err instanceof Error ? err.message : 'Failed'); }
    finally { setBusy(false); }
  }

  return (
    <Layout>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold">Targets</h1>
          <p className="text-slate-400 text-sm">Websites you are authorized to assess.</p>
        </div>
        <button className="btn-primary" onClick={() => setShowForm(!showForm)}>+ Add target</button>
      </div>
      <ResponsibleUseNotice />
      {error && <div className="text-red-400 mb-4">{error}</div>}

      {showForm && (
        <form onSubmit={create} className="card p-6 mb-6 flex flex-col gap-4">
          <div className="grid md:grid-cols-2 gap-4">
            <div>
              <label className="text-sm text-slate-400">Target name</label>
              <input className="input mt-1" placeholder="e.g. My College Website" value={form.name}
                onChange={e => setForm({ ...form, name: e.target.value })} required />
            </div>
            <div>
              <label className="text-sm text-slate-400">Website URL</label>
              <input className="input mt-1" placeholder="https://example.edu" value={form.url}
                onChange={e => setForm({ ...form, url: e.target.value })} required />
            </div>
          </div>
          <div>
            <label className="text-sm text-slate-400">Description</label>
            <input className="input mt-1" placeholder="What is this site?" value={form.description}
              onChange={e => setForm({ ...form, description: e.target.value })} />
          </div>
          <div>
            <label className="text-sm text-slate-400">Scope (optional)</label>
            <input className="input mt-1" placeholder="e.g. Public pages only; exclude /admin" value={form.scope}
              onChange={e => setForm({ ...form, scope: e.target.value })} />
          </div>
          <label className="flex items-start gap-3 p-4 rounded-xl border border-amber-500/40 bg-amber-950/20 text-sm cursor-pointer">
            <input type="checkbox" className="mt-1 w-4 h-4" checked={form.auth}
              onChange={e => setForm({ ...form, auth: e.target.checked })} required />
            <span><strong>Authorization confirmation (required).</strong> I confirm that I own this target
              or have explicit permission to assess it. I understand WebGuard performs only passive,
              non-destructive checks.</span>
          </label>
          <div><button className="btn-primary" disabled={busy}>{busy ? 'Adding…' : 'Add target'}</button></div>
        </form>
      )}

      {targets.length === 0 && !showForm ? (
        <Empty title="No targets yet" hint="Add a website you own or are authorized to test." />
      ) : (
        <div className="grid md:grid-cols-2 gap-4">
          {targets.map(t => (
            <Link key={t.id} to={`/targets/${t.id}`} className="card p-5 hover:border-blue-500 transition-colors">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="font-semibold truncate">{t.name} {t.is_demo && <span className="badge sev-Medium ml-1">DEMO</span>}</div>
                  <div className="text-sm text-slate-400 truncate">{t.url}</div>
                  <div className="text-xs text-slate-500 mt-1">{t.assessment_count} assessment{t.assessment_count === 1 ? '' : 's'}</div>
                </div>
                <ScoreRing score={t.latest_score} size={64} />
              </div>
            </Link>
          ))}
        </div>
      )}
    </Layout>
  );
}

export function TargetDetailPage() {
  const { id } = useParams();
  const [t, setT] = useState<Target | null>(null);
  const [assessments, setAssessments] = useState<AssessmentSummary[]>([]);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const nav = useNavigate();

  const load = () => {
    if (!id) return;
    api.target(+id).then(setT).catch(e => setError(e.message));
    api.assessments().then(all => setAssessments(all.filter(a => a.target_id === +id))).catch(() => {});
  };
  useEffect(load, [id]);

  async function start() {
    if (!id) return;
    setBusy(true); setError('');
    try {
      const a = await api.startAssessment(+id);
      nav(`/assessments/${a.id}`);
    } catch (err: unknown) { setError(err instanceof Error ? err.message : 'Failed'); }
    finally { setBusy(false); }
  }

  async function remove() {
    if (!id || !confirm('Delete this target and all its assessments?')) return;
    await api.deleteTarget(+id);
    nav('/targets');
  }

  return (
    <Layout>
      {error && <div className="text-red-400 mb-4">{error}</div>}
      {!t ? <div className="text-slate-400">Loading…</div> : (
        <>
          <div className="flex items-start justify-between mb-6 gap-4">
            <div>
              <h1 className="text-2xl font-bold">{t.name} {t.is_demo && <span className="badge sev-Medium">DEMO</span>}</h1>
              <div className="text-slate-400 text-sm break-all">{t.url}</div>
              {t.description && <p className="text-slate-400 text-sm mt-2">{t.description}</p>}
              {t.scope && <p className="text-xs text-slate-500 mt-1">Scope: {t.scope}</p>}
            </div>
            <div className="flex gap-2 shrink-0">
              <button className="btn-primary" onClick={start} disabled={busy}>{busy ? 'Starting…' : '▶ Start assessment'}</button>
              <button className="btn-ghost" onClick={remove}>Delete</button>
            </div>
          </div>

          <h2 className="font-semibold mb-3">Assessments</h2>
          {assessments.length === 0 ? (
            <Empty title="No assessments yet" hint="Start your first passive assessment of this target." />
          ) : (
            <div className="card divide-y divide-[#232f4d]">
              {assessments.map(a => (
                <Link key={a.id} to={`/assessments/${a.id}`} className="flex items-center gap-4 p-4 hover:bg-[#1a2338]">
                  <StatusPill status={a.status} />
                  <div className="flex-1">
                    <div className="font-medium">Assessment #{a.id}</div>
                    <div className="text-xs text-slate-500">{new Date(a.created_at).toLocaleString()}
                      {a.duration_s ? ` · ${a.duration_s.toFixed(1)}s` : ''}</div>
                  </div>
                  {a.score !== null && <div className="text-xl font-bold">{a.score}<span className="text-sm text-slate-500">/100</span></div>}
                </Link>
              ))}
            </div>
          )}
        </>
      )}
    </Layout>
  );
}
