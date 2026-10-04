"""Unit tests: target validation & SSRF protections."""

import pytest

from scanner.target_validator import TargetValidationError, validate_target


def test_rejects_non_http_schemes():
    for bad in ["ftp://example.com/", "javascript:alert(1)", "file:///etc/passwd", "gopher://x/"]:
        with pytest.raises(TargetValidationError):
            validate_target(bad, allow_private_networks=True)


def test_rejects_credentials_in_url():
    with pytest.raises(TargetValidationError):
        validate_target("http://user:pass@example.com/", allow_private_networks=True)


def test_rejects_empty_and_overlong():
    with pytest.raises(TargetValidationError):
        validate_target("")
    with pytest.raises(TargetValidationError):
        validate_target("http://x/" + "a" * 3000, allow_private_networks=True)


def test_blocks_loopback_by_default():
    for bad in ["http://127.0.0.1:8901/", "http://localhost:8901/", "http://[::1]/"]:
        with pytest.raises(TargetValidationError, match="[Nn]on-public|internal"):
            validate_target(bad, allow_private_networks=False)


def test_blocks_cloud_metadata_ip():
    with pytest.raises(TargetValidationError):
        validate_target("http://169.254.169.254/", allow_private_networks=False)


def test_allows_loopback_when_explicitly_enabled():
    url = validate_target("http://127.0.0.1:8901/", allow_private_networks=True)
    assert url == "http://127.0.0.1:8901/"


def test_normalizes_url():
    assert validate_target("https://Example.COM", allow_private_networks=True) == "https://example.com/"
    assert validate_target("https://example.com/#frag", allow_private_networks=True) == "https://example.com/"


def test_unresolvable_host(monkeypatch):
    import socket
    def boom(*a, **k):
        raise socket.gaierror("mocked DNS failure")
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    with pytest.raises(TargetValidationError, match="[Rr]esolv"):
        validate_target("http://this-host-definitely-does-not-exist-xyz.invalid/",
                        allow_private_networks=True)
