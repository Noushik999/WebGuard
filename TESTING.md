# WebGuard Testing

## Strategy

| Layer | Tool | What's covered |
|---|---|---|
| Validators | pytest | URL validation, SSRF blocking (schemes, credentials, loopback, metadata IP, DNS failure), normalization |
| Risk engine | pytest | Score math, confidence scaling, grade bands, fingerprint stability, dedupe, comparison diff |
| Scanner | pytest | All 7 modules vs a fixture HTTP server; determinism across runs; module-isolation (a crashing module can't kill the run); progress stages; cancellation |
| API | pytest | Full journey: register → login → target (auth-required, SSRF, dedupe) → scan → poll → findings → triage → AI analysis → report → dashboard → rescan → compare → demo seed; auth isolation; bad password; rate limits; security headers on WebGuard itself |
| Frontend | vitest | Component rendering (badges, score ring) |
| E2E (live) | manual/browser | Real backend + frontend + vulnerable lab; visual QA of every page |

## Running

```bash
# Backend + scanner tests (from repo root)
./.venv/bin/python -m pytest tests/ -q

# Frontend tests
cd frontend && npm test

# Frontend production build
cd frontend && npm run build
```

## Test environment notes

- Tests use throwaway SQLite files in `/tmp` — no Postgres needed.
- `ALLOW_PRIVATE_NETWORKS=true` is set for tests so the fixture server (localhost)
  can be scanned; production defaults to `false`.
- The API tests run the real in-process worker (2s poll); scans of the fixture
  server take a few seconds each.
- The sandbox DNS in some CI environments resolves everything; the DNS-failure
  validator test mocks `socket.getaddrinfo` to stay hermetic.

## Demo environments

**Simulated demo** (no network): `POST /api/demo/seed` or the Demo page in the UI —
creates "WebGuard Demo Target" with 10 realistic findings, clearly marked DEMO.

**Vulnerable lab** (real scan, localhost only):
```bash
cd demo/vuln-target
uvicorn vuln_app:app --port 8901
# backend .env: ALLOW_PRIVATE_NETWORKS=true
# add target http://127.0.0.1:8901/ in the UI and start an assessment
```
Expected: 16 findings, score 18/100, covering all 10 deliberate weaknesses.

## CI

`.github/workflows/ci.yml` runs on push/PR: backend lint (`ruff`), pytest,
frontend `vitest` + production build, `pip audit` / `npm audit`.
