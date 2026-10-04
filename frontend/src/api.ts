/* Typed WebGuard API client. Token lives in localStorage (see SECURITY.md). */

const BASE = '';

export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational';

export interface User { id: number; email: string; is_admin: boolean; created_at: string }
export interface Target {
  id: number; name: string; url: string; description: string; scope: string;
  auth_confirmed: boolean; auth_confirmed_at: string | null; is_demo: boolean;
  created_at: string; assessment_count: number; latest_score: number | null;
}
export interface AssessmentSummary {
  id: number; target_id: number; target_name: string; status: string; progress: number;
  current_stage: string; score: number | null; findings_count: number;
  severity_counts: Record<string, number>; is_demo: boolean; error: string | null;
  duration_s: number | null; created_at: string; finished_at: string | null;
}
export interface AssessmentDetail extends AssessmentSummary {
  scanner_version: string; module_errors: Record<string, string>;
  score_breakdown: Array<{ title: string; severity: string; confidence: number; weight: number; deduction: number }>;
  grade: string;
}
export interface Finding {
  id: number; assessment_id: number; fingerprint: string; title: string; category: string;
  owasp_mapping: string; severity: Severity; confidence: number; description: string;
  why_it_matters: string; evidence: string; recommendation: string; verification: string;
  references: string[]; affected_url: string; scanner: string; detected_at: string;
  status: string; ai_analysis: AIAnalysis | null;
}
export interface AIAnalysis {
  plain_english: string; technical: string; impact: string; priority: string;
  remediation_steps: string[]; verification: string; confidence_note: string; source: string;
}
export interface Comparison {
  assessment_a_id: number; assessment_b_id: number; score_a: number | null; score_b: number | null;
  score_delta: number | null;
  new: Array<{ fingerprint: string; severity: string; title: string; category: string; finding_id: number }>;
  resolved: Array<{ fingerprint: string; severity: string; title: string; category: string; finding_id: number }>;
  persistent: Array<{ fingerprint: string; title: string; old_severity: string; new_severity: string }>;
  severity_changes: Array<{ fingerprint: string; title: string; old_severity: string; new_severity: string }>;
  new_count: number; resolved_count: number; persistent_count: number;
}
export interface Dashboard {
  target_count: number; assessment_count: number; completed_count: number; running_count: number;
  latest_score: number | null;
  score_history: Array<{ assessment_id: number; target_id: number; score: number; created_at: string }>;
  severity_totals: Record<string, number>;
  top_findings: Array<{ id: number; assessment_id: number; title: string; severity: string; category: string; target_name: string }>;
  recent_assessments: AssessmentSummary[];
}

function token(): string | null { return localStorage.getItem('wg_token'); }
export function setToken(t: string | null) { t ? localStorage.setItem('wg_token', t) : localStorage.removeItem('wg_token'); }
export function isAuthed() { return !!token(); }

async function req<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json', ...(init.headers as Record<string, string> || {}) };
  const t = token();
  if (t) headers['Authorization'] = `Bearer ${t}`;
  const res = await fetch(BASE + path, { ...init, headers });
  if (res.status === 401) { setToken(null); window.location.href = '/login'; throw new Error('Session expired'); }
  if (!res.ok) {
    let detail = res.statusText;
    try { const j = await res.json(); detail = typeof j.detail === 'string' ? j.detail : JSON.stringify(j.detail); } catch { /* ignore */ }
    throw new Error(detail);
  }
  const ct = res.headers.get('content-type') || '';
  if (ct.includes('application/json')) return res.json() as Promise<T>;
  return (await res.text()) as unknown as T;
}

export const api = {
  register: (email: string, password: string) => req<{ access_token: string; user: User }>('/api/auth/register', { method: 'POST', body: JSON.stringify({ email, password }) }),
  login: (email: string, password: string) => req<{ access_token: string; user: User }>('/api/auth/login', { method: 'POST', body: JSON.stringify({ email, password }) }),
  me: () => req<User>('/api/auth/me'),

  targets: () => req<Target[]>('/api/targets'),
  target: (id: number) => req<Target>(`/api/targets/${id}`),
  createTarget: (b: { name: string; url: string; description: string; scope: string; auth_confirmed: boolean }) =>
    req<Target>('/api/targets', { method: 'POST', body: JSON.stringify(b) }),
  deleteTarget: (id: number) => req<{ ok: boolean }>(`/api/targets/${id}`, { method: 'DELETE' }),

  startAssessment: (targetId: number) => req<AssessmentSummary>(`/api/assessments/targets/${targetId}`, { method: 'POST' }),
  assessments: () => req<AssessmentSummary[]>('/api/assessments'),
  assessment: (id: number) => req<AssessmentDetail>(`/api/assessments/${id}`),
  findings: (id: number, severity?: string) => req<Finding[]>(`/api/assessments/${id}/findings${severity ? `?severity=${severity}` : ''}`),
  cancelAssessment: (id: number) => req<{ ok: boolean }>(`/api/assessments/${id}/cancel`, { method: 'POST' }),
  rescan: (id: number) => req<AssessmentSummary>(`/api/assessments/${id}/rescan`, { method: 'POST' }),
  compare: (a: number, b: number) => req<Comparison>(`/api/assessments/${a}/compare/${b}`),

  finding: (id: number) => req<Finding>(`/api/findings/${id}`),
  triageFinding: (id: number, status: string) => req<Finding>(`/api/findings/${id}`, { method: 'PATCH', body: JSON.stringify({ status }) }),
  analyzeFinding: (id: number) => req<AIAnalysis>(`/api/findings/${id}/analysis`),

  generateReport: (id: number) => req<{ report_id: number }>(`/api/assessments/${id}/report`, { method: 'POST' }),
  reportUrl: (assessmentId: number) => `/api/assessments/${assessmentId}/report-view`,

  dashboard: () => req<Dashboard>('/api/dashboard'),
  seedDemo: () => req<{ target_id: number; assessment_id: number; score: number }>('/api/demo/seed', { method: 'POST' }),
};
