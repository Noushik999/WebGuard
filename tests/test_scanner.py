"""Scanner tests: engine + modules against the fixture server.

Also asserts the resilience rule: a failing module must not crash the assessment.
"""

from scanner import engine
from scanner.engine import run_assessment


def _titles(result):
    return [f.title for f in result.findings]


def test_engine_detects_fixture_weaknesses(fixture_server):
    r = run_assessment(fixture_server, allow_private_networks=True)
    titles = _titles(r)
    assert "Site does not use HTTPS" in titles
    assert "CORS reflects arbitrary origins with credentials allowed" in titles
    assert "Cookie 'sessid' missing HttpOnly flag" in titles
    assert "Missing Content-Security-Policy header" in titles
    assert "Missing clickjacking protection" in titles
    assert "Potentially unsafe HTTP methods advertised: DELETE, PUT, TRACE" in titles
    assert "Verbose error page leaks internals" in titles
    assert "Outdated JavaScript library: jQuery 1.12.4" in titles
    assert any("Server version disclosure" in t for t in titles)
    assert "robots.txt exposes sensitive-looking paths" in titles
    assert not r.module_errors
    assert r.score < 100
    assert r.stats["request_count"] <= 40


def test_engine_is_deterministic(fixture_server):
    r1 = run_assessment(fixture_server, allow_private_networks=True)
    r2 = run_assessment(fixture_server, allow_private_networks=True)
    assert _titles(r1) == _titles(r2)
    assert r1.score == r2.score


def test_module_failure_does_not_crash_assessment(fixture_server, monkeypatch):
    from scanner.modules import cors
    def boom(ctx, client):
        raise RuntimeError("simulated module crash")
    monkeypatch.setattr(cors, "run", boom)
    r = run_assessment(fixture_server, allow_private_networks=True)
    assert "cors" in r.module_errors
    assert "simulated module crash" in r.module_errors["cors"]
    # Other modules still produced findings.
    assert len(r.findings) > 5
    assert r.score is not None


def test_findings_have_required_fields(fixture_server):
    r = run_assessment(fixture_server, allow_private_networks=True)
    assert r.findings, "expected findings"
    for f in r.findings:
        assert f.title and f.category and f.severity
        assert 0.0 <= f.confidence <= 1.0
        assert f.description and f.why_it_matters and f.evidence
        assert f.recommendation and f.verification
        assert f.affected_url and f.scanner and f.fingerprint
        assert f.owasp_mapping.startswith("A0")


def test_progress_callback_receives_stages(fixture_server):
    stages = []
    run_assessment(fixture_server, allow_private_networks=True,
                   progress=lambda s, p: stages.append(s))
    for expected in ["VALIDATING", "RUNNING", "ANALYZING", "COMPLETED"]:
        assert expected in stages


def test_stop_check_cancels(fixture_server):
    from scanner.engine import ScanCancelledByUser
    import pytest
    calls = {"n": 0}
    def stop():
        calls["n"] += 1
        return calls["n"] > 2
    with pytest.raises(ScanCancelledByUser):
        run_assessment(fixture_server, allow_private_networks=True, stop_check=stop)
