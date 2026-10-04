# WebGuard Security

## Responsible-use policy

WebGuard is a **defensive, passive** assessment tool. It is built for:

1. Websites you own,
2. A deliberately vulnerable local lab (see `demo/vuln-target/`),
3. Systems you have **explicit authorization** to assess.

It must not be used for unauthorized testing. The application enforces this posture:

- **Authorization confirmation is required** to create a target (checkbox + timestamp stored).
- The notice *"Only assess systems that you own or have explicit authorization to test."*
  appears on target creation, before assessment, in every report, and in docs.
- **Passive only**: GET/HEAD/OPTIONS, bounded requests, no payloads, no exploitation,
  no authentication bypass, no credential use.
- **SSRF protections**: only `http/https`, no credentials in URLs, DNS resolved
  up-front, private/loopback/link-local/multicast/reserved addresses blocked by
  default, redirects re-validated per hop, proxy env vars ignored, `ALLOW_PRIVATE_NETWORKS`
  exists only for the local lab and defaults to `false`.

## Security model of WebGuard itself

| Area | Implementation |
|---|---|
| Secrets | Env vars only (`.env` never committed; `.env.example` documents). No secrets in code, logs, or reports. |
| Passwords | PBKDF2-HMAC-SHA256, 600k iterations, 16-byte salt (stdlib, `app/security.py`). |
| Sessions | HS256 JWT (stdlib HMAC), 24h expiry, bearer header. |
| Injection | SQLAlchemy ORM everywhere (parameterized); Jinja2 autoescape on reports; React escapes by default. |
| AuthZ | Every object access checks `target.user_id == current_user`; 404 (not 403) to avoid ID enumeration. |
| Rate limiting | In-memory sliding window per IP; 10/min on auth, 60/min default. |
| Headers | `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Permissions-Policy` lockdown, HSTS, restrictive CSP on API responses. |
| Errors | Global handler returns generic 500; stack traces logged server-side only. |
| Cookies (lab) | The *lab target* sets insecure cookies deliberately — that is the demo, not WebGuard. |
| Audit | `audit_logs` for auth, target, assessment, triage, report events; secret-looking keys stripped. |
| Dependencies | Pinned ranges in `requirements.txt` / `package.json`; CI runs `pip audit` / `npm audit`. |

## Self-review (performed during build)

| # | Check | Result |
|---|---|---|
| 1 | SSRF via target URL (private IPs, metadata IP, redirect bypass, proxy env) | Blocked; per-hop re-validation; `trust_env=False`. Tested. |
| 2 | Auth bypass / IDOR on targets, assessments, findings, reports | Ownership checks on every route; cross-user access returns 404. Tested. |
| 3 | Password storage / JWT forgery | PBKDF2 + HMAC-SHA256 with server secret; expiry enforced. Tested (bad password → 401, tampered token → 401). |
| 4 | Scanner crashing on hostile input | Per-module try/except; request budget; timeouts; body cap. Tested (simulated module crash). |
| 5 | Information leakage in errors | Generic 500 handler; no stack traces to clients. Tested. |
| 6 | CORS misconfiguration on the API | Explicit allow-list (`FRONTEND_URL`), credentials only for the frontend origin. |
| 7 | Token storage on frontend | `localStorage` bearer token (documented trade-off for a static SPA + cross-origin API; mitigation: short 24h expiry, no sensitive data in token). |
| 8 | Dependency vulnerabilities | `pip audit` / `npm audit` in CI; minimal dependency surface (stdlib crypto). |
| 9 | Verbose lab errors | The lab is intentionally vulnerable and clearly labeled; never exposed publicly. |
| 10 | AI inventing vulnerabilities | Analyst cannot create findings; LLM output is prose-only, severity/priority pinned, fallback to rules. |

## Production checklist

- [ ] `SECRET_KEY`: long random value; `APP_ENV=production`
- [ ] `DATABASE_URL`: managed PostgreSQL
- [ ] `ALLOW_PRIVATE_NETWORKS=false`
- [ ] `FRONTEND_URL`: exact production origin
- [ ] Change the bootstrapped admin password immediately
- [ ] Serve API over HTTPS (HSTS header is already sent; terminate TLS at proxy)
- [ ] Restrict `/api/docs` or disable in production
- [ ] Centralized log shipping; alert on `assessment.failed` spikes
- [ ] Backups for the database

## Reporting a vulnerability in WebGuard

Open a GitHub issue (or contact the maintainer directly) with steps to reproduce.
Please do not test the public demo deployment aggressively — run it locally instead.
