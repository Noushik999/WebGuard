# WebGuard — Automated Web Security Assessment & Remediation Platform

**Tagline:** *Automated Web Security Assessment & Remediation Platform*

WebGuard performs **authorized, passive, non-destructive** security assessments of websites
and produces understandable security reports with remediation guidance.

> ⚠️ **Responsible use:** Only assess systems you own or have explicit authorization to test.
> WebGuard blocks private/internal network targets by default and performs no exploitation.

## Quick start (local)

```bash
# 1. Backend
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp ../.env.example ../.env   # then edit secrets
uvicorn app.main:app --reload --port 8000

# 2. Frontend (new terminal)
cd frontend
npm install
npm run dev        # → http://localhost:5173

# 3. Demo (no real target needed)
# Log in, open "Demo", and run the pre-seeded WebGuard Demo Target assessment,
# or point a scan at the intentionally vulnerable local lab:
#   cd demo/vuln-target && uvicorn vuln_app:app --port 8901
```

Default login after first run: `admin@webguard.local` / `webguard-admin`
(change immediately; see `SECURITY.md`).

## What it does

1. Add an **authorized target** (authorization checkbox required)
2. Start an **assessment** → async job: `QUEUED → VALIDATING → RUNNING → ANALYZING → GENERATING_RESULTS → COMPLETED`
3. Passive scanner modules inspect: security headers, TLS/HTTPS, cookies, CORS,
   information disclosure, HTTP configuration, frontend technology signals
4. Findings normalized → deterministic **severity** + **0–100 security score**
5. AI analyst layer explains each finding (rule-based, evidence-grounded; optional LLM via `OPENAI_API_KEY`)
6. Dashboard, finding details, assessment history, **scan comparison**, HTML report

## Repository layout

```
webguard/
├── backend/            # FastAPI API + assessment service
│   ├── app/            # API, auth, jobs, DB models
│   ├── scanner/        # Passive scanning engine + modules
│   └── reports/        # HTML report generator
├── frontend/           # React + TypeScript + Vite dashboard
├── demo/
│   ├── vuln-target/    # Intentionally vulnerable LOCAL lab app (for safe demos)
│   └── sample-report/  # Polished example report (simulated data, marked DEMO)
├── tests/              # backend + scanner tests
├── docker/             # Dockerfiles + compose for docker-capable hosts
├── docs/               # Detailed documentation
├── .github/workflows/  # CI
├── ARCHITECTURE.md
├── SECURITY.md
├── API.md
├── TESTING.md
└── CONTRIBUTING.md
```

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) — system design, decisions, data model
- [SECURITY.md](SECURITY.md) — security model, responsible use, self-review
- [API.md](API.md) — REST API reference
- [TESTING.md](TESTING.md) — test strategy and how to run
- [CONTRIBUTING.md](CONTRIBUTING.md) — contribution guide

## Limitations (honest)

- Passive assessment only: WebGuard observes what a normal client can see. It does
  not perform authenticated scans, crawling beyond the front page, active
  exploitation, or login testing.
- The 0–100 score measures **only the checks WebGuard performs** — a high score is
  not a guarantee of security.
- AI explanations are generated from scanner evidence only and never invent findings.

## License

MIT — see [LICENSE](LICENSE).
