import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { api, type Finding, type AIAnalysis } from '../api';
import { Layout, SeverityBadge, DemoBanner } from '../components/ui';

const TRIAGE = ['Open', 'Fixed', 'Accepted Risk', 'False Positive'];

export default function FindingPage() {
  const { id } = useParams();
  const [f, setF] = useState<Finding | null>(null);
  const [analysis, setAnalysis] = useState<AIAnalysis | null>(null);
  const [analysisBusy, setAnalysisBusy] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!id) return;
    api.finding(+id).then(setF).catch(e => setError(e.message));
  }, [id]);

  async function loadAnalysis() {
    if (!id) return;
    setAnalysisBusy(true);
    try { setAnalysis(await api.analyzeFinding(+id)); }
    catch (e: unknown) { setError(e instanceof Error ? e.message : 'Failed'); }
    finally { setAnalysisBusy(false); }
  }

  async function triage(status: string) {
    if (!id) return;
    try { setF(await api.triageFinding(+id, status)); }
    catch (e: unknown) { setError(e instanceof Error ? e.message : 'Failed'); }
  }

  return (
    <Layout>
      {error && <div className="text-red-400 mb-4">{error}</div>}
      {!f ? <div className="text-slate-400">Loading…</div> : (
        <>
          <Link to={`/assessments/${f.assessment_id}`} className="text-blue-400 text-sm hover:underline">← Back to assessment #{f.assessment_id}</Link>
          <div className="flex items-start justify-between gap-4 mt-3 mb-5 flex-wrap">
            <div>
              <h1 className="text-2xl font-bold">{f.title}</h1>
              <div className="flex items-center gap-2 mt-2 flex-wrap">
                <SeverityBadge severity={f.severity} />
                <span className="text-sm text-slate-400">{Math.round(f.confidence * 100)}% confidence</span>
                <span className="text-sm text-slate-500">·</span>
                <span className="text-sm text-slate-400">{f.category}</span>
                <span className="text-sm text-slate-500">·</span>
                <span className="text-sm text-slate-400">{f.owasp_mapping}</span>
              </div>
            </div>
            <div className="flex gap-2 items-center">
              <span className="text-xs text-slate-500">Status:</span>
              <select className="input !w-auto" value={f.status} onChange={e => triage(e.target.value)}>
                {TRIAGE.map(s => <option key={s}>{s}</option>)}
              </select>
            </div>
          </div>

          <div className="grid gap-4">
            <Section title="What was observed" body={f.description} />
            <Section title="Why it matters" body={f.why_it_matters} />
            <div className="card p-6">
              <div className="font-semibold mb-2">Evidence</div>
              <pre className="bg-[#0b0f1a] border border-[#232f4d] rounded-lg p-4 text-sm whitespace-pre-wrap break-words">{f.evidence}</pre>
            </div>
            <Section title="Recommended fix" body={f.recommendation} accent />
            <Section title="How to verify the fix" body={f.verification} />
            <div className="card p-6">
              <div className="font-semibold mb-2">Details</div>
              <dl className="text-sm grid md:grid-cols-2 gap-x-8 gap-y-2">
                <Detail k="Affected URL" v={f.affected_url} mono />
                <Detail k="Scanner module" v={f.scanner} mono />
                <Detail k="First detected" v={new Date(f.detected_at).toLocaleString()} />
                <Detail k="Status" v={f.status} />
              </dl>
              {f.references.length > 0 && (
                <div className="mt-3 text-sm">
                  <span className="text-slate-400">References: </span>
                  {f.references.map((r, i) => (
                    <span key={i}><a href={r} target="_blank" rel="noreferrer" className="text-blue-400 hover:underline break-all">{r}</a>{i < f.references.length - 1 ? ', ' : ''}</span>
                  ))}
                </div>
              )}
            </div>

            <div className="card p-6">
              <div className="flex items-center justify-between mb-2">
                <div className="font-semibold">🤖 AI security analyst</div>
                {!analysis && !f.ai_analysis && (
                  <button className="btn-primary !py-2 text-sm" onClick={loadAnalysis} disabled={analysisBusy}>
                    {analysisBusy ? 'Analyzing…' : 'Explain this finding'}
                  </button>
                )}
              </div>
              {(analysis || f.ai_analysis) ? (
                <AnalysisView a={(analysis || f.ai_analysis)!} />
              ) : (
                <p className="text-sm text-slate-500">Get a plain-English explanation, impact assessment, and developer-oriented remediation steps — grounded strictly in the scanner evidence above.</p>
              )}
            </div>
          </div>
        </>
      )}
    </Layout>
  );
}

function Section({ title, body, accent }: { title: string; body: string; accent?: boolean }) {
  return (
    <div className={`card p-6 ${accent ? 'border-blue-500/40' : ''}`}>
      <div className="font-semibold mb-2">{title}</div>
      <p className="text-slate-300 text-[15px] whitespace-pre-wrap">{body}</p>
    </div>
  );
}

function Detail({ k, v, mono }: { k: string; v: string; mono?: boolean }) {
  return (
    <div>
      <dt className="text-slate-500 text-xs">{k}</dt>
      <dd className={`break-all ${mono ? 'font-mono text-[13px]' : ''}`}>{v}</dd>
    </div>
  );
}

function AnalysisView({ a }: { a: AIAnalysis }) {
  return (
    <div className="flex flex-col gap-4 text-[15px]">
      <div><div className="text-slate-400 text-sm font-semibold mb-1">In plain English</div><p>{a.plain_english}</p></div>
      <div><div className="text-slate-400 text-sm font-semibold mb-1">Potential impact</div><p>{a.impact}</p></div>
      <div><div className="text-slate-400 text-sm font-semibold mb-1">Priority</div><p className="text-amber-300 font-medium">{a.priority}</p></div>
      <div>
        <div className="text-slate-400 text-sm font-semibold mb-1">Remediation steps</div>
        <ol className="list-decimal ml-5 flex flex-col gap-1">{a.remediation_steps.map((s, i) => <li key={i}>{s}</li>)}</ol>
      </div>
      <div><div className="text-slate-400 text-sm font-semibold mb-1">Verification</div><p>{a.verification}</p></div>
      <div className="text-xs text-slate-500 border-t border-[#232f4d] pt-3">
        {a.confidence_note} <span className="ml-2 px-2 py-0.5 rounded bg-[#232f4d]">source: {a.source === 'llm' ? 'LLM (evidence-grounded)' : 'deterministic rules'}</span>
      </div>
    </div>
  );
}
