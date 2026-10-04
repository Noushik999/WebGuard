"""
WebGuard Vulnerable Lab Target — INTENTIONALLY VULNERABLE.

For LOCAL security education and WebGuard demonstrations ONLY.
- Run:  uvicorn vuln_app:app --port 8901   (from this directory)
- Then add http://127.0.0.1:8901/ as a WebGuard target with
  ALLOW_PRIVATE_NETWORKS=true in the backend .env.

Deliberate weaknesses (each is detected by a WebGuard module):
  1. No Content-Security-Policy, HSTS, X-Content-Type-Options, Referrer-Policy
  2. No clickjacking protection
  3. Verbose Server header with version
  4. Cookies without Secure / HttpOnly / SameSite
  5. CORS reflects any Origin with credentials allowed
  6. Verbose 500 error page with stack trace
  7. Outdated jQuery 1.12.4 referenced
  8. robots.txt listing /admin/ and /backup/
  9. No security.txt
 10. OPTIONS advertises PUT, DELETE, TRACE

DO NOT expose this app to the internet. DO NOT use it as a template.
"""

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, PlainTextResponse

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

HTML = """<!DOCTYPE html>
<html><head>
<title>Demo University — Student Portal (LAB)</title>
<meta name="generator" content="DemoPress 4.2.1">
<script src="/static/jquery-1.12.4.min.js"></script>
</head><body>
<h1>Demo University — Student Portal</h1>
<p><strong>INTENTIONALLY VULNERABLE LAB APP.</strong> Local security education only.</p>
<p>Welcome, student. Your portal dashboard would be here.</p>
</body></html>"""


@app.middleware("http")
async def insecure_defaults(request: Request, call_next):
    response = await call_next(request)
    # Deliberately weak cookie: no Secure, no HttpOnly, no SameSite.
    response.set_cookie("sessid", "lab-session-abc123", path="/")
    # Verbose server banner.
    response.headers["Server"] = "DemoLab-Server/0.9.1"
    # Deliberately permissive CORS: reflect any origin, allow credentials.
    origin = request.headers.get("origin")
    if origin:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
    return response


@app.get("/", response_class=HTMLResponse)
def index():
    return HTML


@app.get("/robots.txt", response_class=PlainTextResponse)
def robots():
    return "User-agent: *\nDisallow: /admin/\nDisallow: /backup/\nDisallow: /.git/\n"


@app.get("/boom")
def boom():
    raise RuntimeError("NullPointerException at com.demouniversity.PortalController")


@app.exception_handler(Exception)
async def verbose_errors(request: Request, exc: Exception):
    # DELIBERATELY verbose: leaks internals on 500 pages.
    import traceback
    body = "500 Internal Server Error\n\n" + traceback.format_exc()
    return PlainTextResponse(body, status_code=500)


@app.get("/{path:path}")
def catch_all(path: str):
    # DELIBERATELY verbose 404-as-500: many misconfigured apps do this.
    raise RuntimeError(
        f"TemplateNotFound: No template named '{path}' in /var/www/portal/templates "
        f"(SQL: SELECT * FROM pages WHERE slug='{path}')"
    )


@app.api_route("/{path:path}", methods=["OPTIONS"])
def options_handler(path: str):
    return PlainTextResponse("", headers={"Allow": "GET, HEAD, POST, PUT, DELETE, TRACE, OPTIONS"})
