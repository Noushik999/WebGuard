# Contributing to WebGuard

## Ground rules

- **Defensive scope only.** WebGuard performs passive, non-destructive assessment.
  Do not add exploitation, authentication bypass, credential theft, DoS, or
  persistence capabilities. PRs expanding offensive capability will be rejected.
- **Evidence first.** Every finding must originate from deterministic scanner
  evidence. The AI layer explains; it never invents.
- **Safety invariants** (add tests if you touch these):
  - SSRF protections in `scanner/target_validator.py` + per-hop redirect validation
  - Request budget / timeouts / body caps in `scanner/http_client.py`
  - Private networks blocked unless `ALLOW_PRIVATE_NETWORKS=true`
  - Per-module isolation in `scanner/engine.py`

## Adding a scanner module

1. Create `backend/scanner/modules/my_check.py` with `NAME`, `CATEGORY`, `OWASP`,
   and `run(ctx: ScanContext, client: SafeHttpClient) -> list[Finding]`.
2. Only use `client.get()` / `client.options()` — never POST/PUT/DELETE.
3. Keep it passive: observe, don't interact. One focused probe max.
4. Register it in `engine.MODULES`.
5. Add fixture-server behavior + assertions in `tests/test_scanner.py`.
6. Document severity rationale in the finding's `why_it_matters`.

## Development

```bash
# backend
cd backend && ../.venv/bin/uvicorn app.main:app --reload --port 8000
# frontend
cd frontend && npm run dev
# tests
../.venv/bin/python -m pytest tests/ -q && cd frontend && npm test
```

## Commit style

Logical commits, conventional prefixes: `feat:`, `fix:`, `test:`, `docs:`, `chore:`.
