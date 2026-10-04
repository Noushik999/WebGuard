import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api, setToken } from '../api';

export default function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const nav = useNavigate();

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(''); setBusy(true);
    try {
      const r = mode === 'login' ? await api.login(email, password) : await api.register(email, password);
      setToken(r.access_token);
      nav('/');
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Something went wrong');
    } finally { setBusy(false); }
  }

  return (
    <div className="min-h-screen flex items-center justify-center p-6">
      <div className="card p-8 w-full max-w-md">
        <div className="flex items-center gap-3 mb-6">
          <div className="w-12 h-12 rounded-xl flex items-center justify-center text-3xl"
            style={{ background: 'linear-gradient(135deg,#3b82f6,#8b5cf6)' }}>🛡️</div>
          <div>
            <div className="font-bold text-2xl">WebGuard</div>
            <div className="text-sm text-slate-400">Automated Web Security Assessment</div>
          </div>
        </div>
        <div className="flex gap-2 mb-6">
          {(['login', 'register'] as const).map(m => (
            <button key={m} onClick={() => setMode(m)}
              className={`px-4 py-2 rounded-lg text-sm font-semibold ${mode === m ? 'bg-blue-600 text-white' : 'text-slate-400 hover:text-white'}`}>
              {m === 'login' ? 'Sign in' : 'Create account'}
            </button>
          ))}
        </div>
        <form onSubmit={submit} className="flex flex-col gap-4">
          <input className="input" type="email" placeholder="Email" value={email}
            onChange={e => setEmail(e.target.value)} required autoComplete="email" />
          <input className="input" type="password" placeholder="Password (min 8 chars)" value={password}
            onChange={e => setPassword(e.target.value)} required autoComplete={mode === 'login' ? 'current-password' : 'new-password'} />
          {error && <div className="text-red-400 text-sm">{error}</div>}
          <button className="btn-primary" disabled={busy}>
            {busy ? 'Please wait…' : mode === 'login' ? 'Sign in' : 'Create account'}
          </button>
        </form>
        <p className="text-xs text-slate-500 mt-6 leading-relaxed">
          ⚠️ Only assess systems you own or have explicit authorization to test.
          WebGuard performs passive, non-destructive security checks.
        </p>
      </div>
    </div>
  );
}
