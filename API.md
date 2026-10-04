# WebGuard API Reference

Base URL: `http://localhost:8000` (dev). All endpoints are prefixed `/api`.
Auth: `Authorization: Bearer <JWT>` header. Interactive docs: `/api/docs`.

## Auth

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/auth/register` | `{email, password}` → `{access_token, user}` |
| POST | `/api/auth/login` | `{email, password}` → `{access_token, user}` |
| GET | `/api/auth/me` | Current user |

Rate limit: 10/min on register/login.

## Targets

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/targets` | Create target. **Requires `auth_confirmed: true`** (the authorization checkbox). Body: `{name, url, description, scope, auth_confirmed}`. URL is SSRF-validated immediately. |
| GET | `/api/targets` | List own targets (with assessment counts + latest score) |
| GET | `/api/targets/{id}` | Target detail |
| DELETE | `/api/targets/{id}` | Delete target + its assessments |

Errors: `400` invalid/blocked URL, `409` duplicate target, `422` missing authorization confirmation.

## Assessments

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/assessments/targets/{target_id}` | Queue an assessment → returns summary with `status: QUEUED`. `409` if one is already running for the target. |
| GET | `/api/assessments` | History (newest first, max 100) |
| GET | `/api/assessments/{id}` | Detail: status, progress 0–100, `current_stage`, score, severity counts, score breakdown, grade, module errors |
| GET | `/api/assessments/{id}/findings?severity=High` | Findings, ordered by severity |
| POST | `/api/assessments/{id}/cancel` | Request cancellation |
| POST | `/api/assessments/{id}/rescan` | Queue a fresh assessment of the same target |

**Job lifecycle:** `QUEUED → VALIDATING → RUNNING → ANALYZING → GENERATING_RESULTS → COMPLETED`
(`FAILED` / `CANCELLED` are terminal). Poll `GET /api/assessments/{id}` for progress.

## Findings

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/findings/{id}` | Full finding detail (evidence, recommendation, verification, references) |
| PATCH | `/api/findings/{id}` | Triage: `{status: "Open" \| "Fixed" \| "Accepted Risk" \| "False Positive"}` |
| GET | `/api/findings/{id}/analysis` | AI analyst explanation (cached; `?refresh=true` to regenerate) |

## Comparison

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/assessments/{a}/compare/{b}` | Diff two **completed** assessments of the **same** target. Returns `new`, `resolved`, `persistent`, `severity_changes` (+ counts) and `score_delta`. |

## Reports

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/assessments/{id}/report` | Generate HTML report → `{report_id}` (completed assessments only) |
| GET | `/api/reports/{report_id}` | Report HTML |
| GET | `/api/assessments/{id}/report-view` | Latest report HTML for the assessment |

## Dashboard

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/dashboard` | Target/assessment counts, latest score, score history, severity totals (latest scan per target), top findings, recent assessments |

## Demo

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/demo/seed` | Create the "WebGuard Demo Target" with a pre-completed **simulated** assessment (marked DEMO). One per user (`409` if exists). |

## Health

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/health` | `{ok: true, service, version}` (unauthenticated) |

## Finding schema (scanner output)

```json
{
  "title": "Missing Content-Security-Policy",
  "category": "Security Headers",
  "owasp_mapping": "A05:2021 – Security Misconfiguration",
  "severity": "Medium",
  "confidence": 0.95,
  "description": "...", "why_it_matters": "...",
  "evidence": "...", "recommendation": "...", "verification": "...",
  "references": ["https://..."],
  "affected_url": "https://target/",
  "scanner": "security_headers",
  "detected_at": "2026-10-04T...",
  "fingerprint": "a1b2c3..."
}
```

## Error format

```json
{ "detail": "human-readable message" }
```

Internal errors return `{"detail": "Internal server error"}` (HTTP 500) — stack
traces are never exposed.
