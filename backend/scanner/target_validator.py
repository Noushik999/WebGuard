"""Target validation: the first line of defense against SSRF and misuse.

Rules:
- Only http/https schemes; no userinfo (credentials) in URL.
- Hostname must resolve; every resolved IP is checked.
- Private, loopback, link-local, multicast, reserved and unspecified addresses are
  blocked unless explicitly allowed (local lab demo only).
- Hostnames that look like internal names are not special-cased; the IP check is
  the source of truth (best-effort DNS-rebinding mitigation: we resolve once up
  front and the client pins requests to validated hosts — see http_client).
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse, urlunparse

MAX_URL_LENGTH = 2048


class TargetValidationError(ValueError):
    pass


def _is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, allow_private: bool) -> bool:
    if allow_private:
        return False
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def validate_target(raw_url: str, allow_private_networks: bool = False) -> str:
    """Validate and normalize a target URL. Returns the normalized URL."""
    if not raw_url or not raw_url.strip():
        raise TargetValidationError("Target URL is required.")
    raw_url = raw_url.strip()
    if len(raw_url) > MAX_URL_LENGTH:
        raise TargetValidationError("Target URL is too long.")

    parsed = urlparse(raw_url)
    if parsed.scheme not in ("http", "https"):
        raise TargetValidationError("Only http:// and https:// targets are supported.")
    if parsed.username or parsed.password:
        raise TargetValidationError("URLs containing credentials are not allowed.")
    host = parsed.hostname
    if not host:
        raise TargetValidationError("Could not determine a hostname from the URL.")
    if len(host) > 253:
        raise TargetValidationError("Hostname is too long.")

    # Resolve and check every address (best-effort DNS rebinding mitigation).
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise TargetValidationError(f"Could not resolve hostname '{host}'.")
    ips = {info[4][0] for info in infos}
    if not ips:
        raise TargetValidationError(f"Hostname '{host}' did not resolve to any address.")
    for ip_str in ips:
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            raise TargetValidationError(f"Hostname '{host}' resolved to an invalid address.")
        if _is_blocked_ip(ip, allow_private_networks):
            raise TargetValidationError(
                f"Target '{host}' resolves to a non-public address ({ip_str}). "
                "Scanning internal infrastructure is blocked by default."
            )

    # Normalize: drop fragment, default empty path to "/".
    path = parsed.path or "/"
    normalized = urlunparse((parsed.scheme, parsed.netloc.lower(), path, "", parsed.query, ""))
    return normalized
