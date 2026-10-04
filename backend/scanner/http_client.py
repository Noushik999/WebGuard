"""Safe HTTP client for the scanner.

Safety properties:
- Redirects are followed manually (max 5); every hop is re-validated with the
  same SSRF rules as the original target.
- Hard cap on total requests per assessment.
- Timeouts on connect/read; response bodies truncated to a fixed budget.
- Identifiable User-Agent so target owners can recognize authorized scans.
- No request bodies are ever sent; only GET/HEAD/OPTIONS are used.
"""

from __future__ import annotations

from http.cookies import SimpleCookie
from urllib.parse import urljoin

import httpx

from .target_validator import TargetValidationError, validate_target

MAX_REDIRECTS = 5
MAX_BODY_BYTES = 512 * 1024


class RequestBudgetExceeded(Exception):
    pass


class _SimpleResponse:
    """Minimal response stand-in for streamed GETs (bounded body)."""

    def __init__(self, status_code: int, headers: httpx.Headers, content: bytes,
                 url: str, truncated: bool):
        self.status_code = status_code
        self.headers = headers
        self.content = content
        self.url = url
        self.truncated = truncated
        self.request_chain: list[str] = []

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", errors="replace")


class SafeHttpClient:
    def _new_pool(self):
        try:
            self._client.close()
        except Exception:
            pass
        self._client = httpx.Client(
            timeout=httpx.Timeout(self.timeout, connect=min(self.timeout, 5.0)),
            follow_redirects=False,
            headers={"User-Agent": self.user_agent, "Accept": "*/*"},
            verify=True,
            # Never honor proxy env vars: a proxy would bypass our SSRF protections
            # and route authorized-scan traffic somewhere unintended.
            trust_env=False,
        )

    def __init__(
        self,
        user_agent: str,
        timeout: float = 10.0,
        max_requests: int = 40,
        allow_private_networks: bool = False,
    ):
        self.user_agent = user_agent
        self.timeout = timeout
        self.max_requests = max_requests
        self.allow_private = allow_private_networks
        self.request_count = 0
        self._new_pool()

    def _check_budget(self):
        self.request_count += 1
        if self.request_count > self.max_requests:
            raise RequestBudgetExceeded(f"Request budget exceeded ({self.max_requests})")

    def _validated(self, url: str) -> str:
        try:
            return validate_target(url, allow_private_networks=self.allow)
        except TargetValidationError as e:
            raise TargetValidationError(f"Blocked redirect hop to '{url}': {e}")

    @property
    def allow(self) -> bool:  # alias used by _validated
        return self.allow_private

    def get(self, url: str, headers: dict | None = None) -> httpx.Response:
        """GET with manual redirect handling. Returns the final response."""
        try:
            return self._get_once(url, headers)
        except httpx.TransportError:
            # Stale pooled connection (server closed keep-alive): retry once fresh.
            self._new_pool()
            return self._get_once(url, headers)

    def _get_once(self, url: str, headers: dict | None = None) -> httpx.Response:
        current = self._validated(url)
        chain = [current]
        for _ in range(MAX_REDIRECTS + 1):
            self._check_budget()
            # Stream the body so a hostile server can't OOM us with a giant
            # response; we only keep the first MAX_BODY_BYTES.
            with self._client.stream("GET", current, headers=headers) as resp:
                chunks: list[bytes] = []
                kept = 0
                for chunk in resp.iter_bytes(65536):
                    if kept < MAX_BODY_BYTES:
                        take = min(len(chunk), MAX_BODY_BYTES - kept)
                        chunks.append(chunk[:take])
                        kept += take
                    else:
                        break
                body = b"".join(chunks)
                status = resp.status_code
                resp_headers = resp.headers
                location = resp_headers.get("location")
            # Build a lightweight stand-in carrying what modules need.
            final = _SimpleResponse(
                status_code=status, headers=resp_headers, content=body,
                url=current, truncated=kept >= MAX_BODY_BYTES,
            )
            if status in (301, 302, 303, 307, 308) and location:
                nxt = urljoin(current, location)
                current = self._validated(nxt)
                chain.append(current)
                continue
            final.request_chain = chain
            return final  # type: ignore[return-value]
        raise TargetValidationError("Too many redirects")

    def options(self, url: str) -> httpx.Response:
        try:
            return self._options_once(url)
        except httpx.TransportError:
            self._new_pool()
            return self._options_once(url)

    def _options_once(self, url: str) -> httpx.Response:
        current = self._validated(url)
        self._check_budget()
        return self._client.options(current)

    def close(self):
        self._client.close()


def parse_set_cookies(raw_headers: list[tuple[str | bytes, str | bytes]]) -> list[dict]:
    """Parse Set-Cookie headers into name/value/flags dicts."""
    cookies: list[dict] = []
    jar = SimpleCookie()
    for name, value in raw_headers:
        if isinstance(name, bytes):
            name = name.decode("latin1")
        if isinstance(value, bytes):
            value = value.decode("latin1")
        if name.lower() != "set-cookie":
            continue
        jar.load(value)
        for morsel in jar.values():
            flags = {k.lower() for k in morsel.keys() if morsel[k]}
            cookies.append(
                {
                    "name": morsel.key,
                    "value": morsel.value,
                    "secure": "secure" in flags,
                    "httponly": "httponly" in flags,
                    "samesite": (morsel["samesite"] or "").strip().capitalize() or None,
                    "path": morsel["path"] or "/",
                    "domain": morsel["domain"] or "",
                }
            )
        jar = SimpleCookie()
    return cookies


def looks_session_cookie(name: str) -> bool:
    n = name.lower()
    return any(k in n for k in ("sess", "sid", "auth", "token", "jwt", "login", "user", "remember"))
