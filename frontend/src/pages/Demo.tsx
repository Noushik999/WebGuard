import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../api';
import { Layout, Empty, DemoBanner } from '../components/ui';

export default function DemoPage() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [existing, setExisting] = useState<{ target_id: number; assessment_id: number } | null>(null);
  const nav = useNavigate();

  useEffect(() => {
    api.targets().then(ts => {
      const d = ts.find(t => t.is_demo);
      if (d) {
        api.assessments().then(all => {
          const a = all.find(x => x.target_id === d.id && x.status === 'COMPLETED');
          if (a) setExisting({ target_id: d.id, assessment_id: a.id });
        }).catch(() => {});
      }
    }).catch(() => {});
  }, []);

  async function seed() {
    setBusy(true); setError('');
    try {
      const r = await api.seedDemo();
      nav(`/assessments/${r.assessment_id}`);
    } catch (e: unknown) { setError(e instanceof Error ? e.message : 'Failed'); }
    finally { setBusy(false); }
  }

  return (
    <Layout>
      <h1 className="text-2xl font-bold mb-1">Demo mode</h1>
      <p className="text-slate-400 text-sm mb-6">Explore WebGuard without scanning a real website.</p>
      <DemoBanner />
      {error && <div className="text-red-400 mb-4">{error}</div>}
      {existing ? (
        <Empty title="Demo target is ready"
          hint="The simulated 'WebGuard Demo Target' assessment is available. Open it to explore findings, the AI analyst, comparison and the sample report."
          action={<button className="btn-primary" onClick={() => nav(`/assessments/${existing.assessment_id}`)}>Open demo assessment</button>} />
      ) : (
        <div className="card p-8 max-w-2xl">
          <h2 className="font-semibold text-lg mb-2">🧪 WebGuard Demo Target</h2>
          <p className="text-slate-400 text-sm mb-4">
            Creates a simulated assessment of "Demo University Website" with realistic findings —
            missing security headers, insecure cookies, an expiring certificate and more.
            Perfect for presentations: no real target is scanned.
          </p>
          <ul className="text-sm text-slate-400 list-disc ml-5 mb-6 flex flex-col gap-1">
            <li>10 realistic findings across all severities</li>
            <li>Score, charts and severity breakdown</li>
            <li>AI analyst explanations</li>
            <li>Professional sample report (marked DEMO)</li>
          </ul>
          <button className="btn-primary" onClick={seed} disabled={busy}>
            {busy ? 'Creating…' : 'Create demo assessment'}
          </button>
        </div>
      )}
      <div className="card p-6 mt-6 max-w-2xl">
        <h2 className="font-semibold mb-2">🔬 Local vulnerable lab</h2>
        <p className="text-slate-400 text-sm mb-3">
          Prefer a <em>real</em> scan? Run the intentionally vulnerable lab app locally, then add it as a target
          with <code className="bg-[#0b0f1a] px-1 rounded">ALLOW_PRIVATE_NETWORKS=true</code> in the backend <code className="bg-[#0b0f1a] px-1 rounded">.env</code>.
        </p>
        <pre className="bg-[#0b0f1a] border border-[#232f4d] rounded-lg p-4 text-sm overflow-x-auto">{`cd demo/vuln-target
uvicorn vuln_app:app --port 8901
# then add target: http://127.0.0.1:8901/`}</pre>
      </div>
    </Layout>
  );
}
