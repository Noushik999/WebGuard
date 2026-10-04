# WebGuard Architecture

## System overview

```
┌─────────────┐      ┌──────────────┐      ┌───────────────────┐
│  Frontend   │─────▶│   REST API   │─────▶│ Assessment Service │
│ React + TS  │◀─────│  FastAPI     │      │  (DB job queue +   │
│ Vite        │ JSON │  JWT auth    │      │   in-process worker)│
└─────────────┘      └──────────────┘      └────────┬──────────┘
                                                    │
                              ┌─────────────────────┼─────────────────────┐
                              ▼                     ▼                     ▼
                       ┌──────────────┐      ┌──────────────┐      ┌──────────────┐
                       │ Scanner      │      │ Risk Engine  │      │ AI Analyst   │
                       │ Engine       │─────▶│ (determin-   │─────▶│ (rules +     │
                       │ 7 modules    │      │  istic score)│      │  optional LLM)│
                       └──────────────┘      └──────────────┘      └──────────────┘
                              │                     │
                              ▼                     ▼
                       ┌──────────────────────────────────┐
                       │  Database (SQLite dev / PG prod)  │
                       │  users · targets · assessments    │
                       │  findings · reports · audit_logs  │
                       └──────────────────────────────────┘
```

The scanner engine is a standalone Python package (`backend/scanner/`) with no
FastAPI dependency — it can be used as a library or CLI independently of the web app.

## Components

### Frontend (`frontend/`)
React 18 + TypeScript + Vite + Tailwind CSS v4 + Recharts. SPA with react-router.
Pages: Login, Dashboard, Targets, TargetDetail, Assessment (live progress),
Finding (detail + AI analysis + triage), History, Compare, Demo.
The dev server proxies `/api` to the backend; production builds are static files.

### API (`backend/app/`)
FastAPI with JWT (HS256) bearer auth. Routers: `auth`, `targets`, `assessments`,
`findings`, `reports`, `dashboard`, `demo`. Global exception handler never leaks
stack traces. Security-headers middleware on every response. Per-IP sliding-window
rate limiting (stricter on auth endpoints).

### Assessment service (`backend/app/worker.py`)
DB-backed job queue + in-process asyncio worker (started in FastAPI lifespan):
- `QUEUED → VALIDATING → RUNNING → ANALYZING → GENERATING_RESULTS → COMPLETED`
- Terminal: `COMPLETED | FAILED | CANCELLED`.
- Jobs are rows in `assessments`; the worker polls every 2s and runs the scanner
  in a thread. A restart re-queues `QUEUED` jobs and fails stale mid-run jobs —
  no work is silently lost.
- Overall timeout (`SCAN_TIMEOUT_SECONDS` + 60s) fails runaway jobs.
- Cancellation via `cancel_events` map + engine `stop_check` hook.

### Scanner engine (`backend/scanner/`)
| File | Responsibility |
|---|---|
| `target_validator.py` | URL parsing, scheme/userinfo rules, DNS resolution, private-IP blocking (SSRF) |
| `http_client.py` | Safe client: manual redirect following (re-validated per hop), request budget, timeouts, body cap, identifiable UA, `trust_env=False`, retry-once on stale pooled connections |
| `engine.py` | Orchestration: validate → collect (page, robots.txt, security.txt, TLS info) → run modules isolated → normalize → score |
| `normalizer.py` | Stable fingerprints (`sha256(module‖title‖url-path)`), dedupe, severity ordering |
| `risk.py` | Deterministic scoring: `100 − Σ(severity_weight × confidence)`; weights Critical 25 / High 15 / Medium 8 / Low 3 / Informational 0; grade bands; `compare_fingerprints` diff |
| `modules/*.py` | 7 passive modules (below) |

**Modules** (each returns `Finding` list; an exception in one never aborts the run):
1. `security_headers` — CSP presence *and quality* (unsafe-inline/eval, wildcards), HSTS (max-age, includeSubDomains), X-Frame-Options / frame-ancestors, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.
2. `tls` — http vs https, http→https redirect, cert validity/expiry (via direct `ssl` handshake), negotiated protocol version, mixed-content signals.
3. `cookies` — Secure / HttpOnly / SameSite on observed `Set-Cookie`s; session-like names escalate severity. Never touches sessions.
4. `cors` — one probe with bogus `Origin`; detects reflection (± credentials) and `*`.
5. `disclosure` — Server/framework banners, robots.txt, security.txt (RFC 9116), one non-existent-path probe for verbose errors, generator meta tags.
6. `http_config` — observed `Allow` header on OPTIONS (never sends PUT/DELETE/TRACE), redirect-chain sanity.
7. `tech` — visible JS library versions vs bundled advisory notes; **honesty rule**: reports "outdated version detected — vulnerability NOT confirmed".

**Safety properties:** passive GET/HEAD/OPTIONS only; ≤40 requests/scan (default); 10s per-request timeout; 512KB body cap; no proxy env honored; private networks blocked by default; bounded, identifiable UA.

### AI analyst (`backend/app/ai_analyst.py`)
Rule-based analyst is always on (offline). If `OPENAI_API_KEY` is set, an LLM may
*rephrase* the explanation from the finding's evidence under a strict grounding
prompt; it cannot change severity/priority, and any failure falls back to rules.
Every output carries a confidence note. The deterministic scanner is the source of
truth — the analyst never creates findings.

### Reporting (`backend/reports/`)
Jinja2 → polished dark-theme HTML report with print CSS (save-as-PDF from any
browser). 14 sections per spec, including score-breakdown, comparison, limitations,
and the authorization notice.

## Data model

`users` → `targets` → `assessments` → `findings` (+ `reports`, `audit_logs`).
Every assessment stores: user, target, auth confirmation timestamp, scanner
version, config (score breakdown, grade, module errors, stats), timestamps.
`audit_logs` records user actions (register/login, target CRUD, assessment
lifecycle, triage, report generation) — never secrets.

## Key decisions (with reasons)

| Decision | Reason |
|---|---|
| SQLite default, PostgreSQL via `DATABASE_URL` | No Postgres available in dev; SQLAlchemy keeps it portable; zero-config local run |
| In-process worker instead of Celery/Redis | No broker available; single deployable unit; DB-backed jobs survive restarts; documented upgrade path |
| stdlib PBKDF2 + hand-rolled HS256 JWT | Zero native-dependency risk, fully auditable; adequate for the threat model (see SECURITY.md) |
| HTML report (print CSS) instead of WeasyPrint PDF | Avoids heavy native deps; equally professional; browser "Save as PDF" |
| Rule-based AI analyst + optional LLM | Works fully offline; LLM can never invent evidence (prompt + post-validation + fallback) |
| Manual redirect following with per-hop validation | Prevents redirect-based SSRF bypass; standard `follow_redirects` would skip checks |
| `trust_env=False` on scanner HTTP client | Env proxies would bypass SSRF protections (found during testing) |
| Retry-once on stale pooled connections | uvicorn-class servers reset idle keep-alive connections; prevents flaky false negatives (found during testing) |

## API design
REST, `/api` prefix, JSON. See `API.md`. Notable: assessments are created with
`POST /api/assessments/targets/{id}` (returns immediately, `QUEUED`); clients poll
`GET /api/assessments/{id}` for progress. Comparison is a pure function of two
completed assessments of the same target.

## Testing strategy
`pytest`: validators, risk math, normalizer, scanner vs fixture HTTP server
(incl. determinism + module-isolation), full API journey (auth → target → scan →
findings → AI → report → rescan → compare → demo). `vitest`: frontend components.
See `TESTING.md`.

## Deployment
`docker/` holds Dockerfiles + compose for docker-capable hosts. Frontend is a
static build (any static host). Backend is a single uvicorn process; production
uses PostgreSQL via `DATABASE_URL` and a real `SECRET_KEY`. See README run
instructions and `SECURITY.md` for the production checklist.

## Limitations (by design)
Passive only: no authenticated scans, no deep crawling, no exploitation.
Score measures only WebGuard's checks. Version-based dependency notes are risk
signals, not confirmed vulnerabilities.
