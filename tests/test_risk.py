"""Unit tests: risk engine (scoring, grades) and comparison logic."""

from datetime import datetime, timezone

from scanner.normalizer import fingerprint, normalize
from scanner.risk import compare_fingerprints, grade, score_findings, severity_counts
from scanner.schemas import Finding


def _f(title, severity, confidence=1.0, scanner="test", url="https://example.com/"):
    return Finding(
        title=title, category="Test", severity=severity, confidence=confidence,
        description="d", why_it_matters="w", evidence="e", recommendation="r",
        affected_url=url, scanner=scanner, detected_at=datetime.now(timezone.utc),
    )


def test_perfect_score_with_no_findings():
    score, breakdown = score_findings([])
    assert score == 100
    assert breakdown == []


def test_scoring_math():
    # Critical 25*1.0 + High 15*0.5 = 32.5 -> 100-32.5 = 67.5 -> 68 (round half to even: 67.5 -> 68? banker's)
    f1 = _f("C", "Critical", 1.0)
    f2 = _f("H", "High", 0.5)
    score, breakdown = score_findings([f1, f2])
    assert score == round(100 - (25 * 1.0 + 15 * 0.5))
    assert breakdown[0]["title"] == "C"  # sorted by deduction desc
    assert breakdown[0]["deduction"] == 25.0


def test_informational_does_not_deduct():
    score, _ = score_findings([_f("I", "Informational", 1.0)])
    assert score == 100


def test_score_floored_at_zero():
    findings = [_f(f"C{i}", "Critical", 1.0) for i in range(10)]
    score, _ = score_findings(findings)
    assert score == 0


def test_confidence_scales_deduction():
    full = score_findings([_f("M", "Medium", 1.0)])[0]
    half = score_findings([_f("M", "Medium", 0.5)])[0]
    assert half > full  # lower confidence -> smaller deduction


def test_grade_bands():
    assert grade(100) == "Very strong baseline"
    assert grade(95) == "Very strong baseline"
    assert grade(80) == "Good"
    assert grade(65) == "Needs improvement"
    assert grade(45) == "Significant concerns"
    assert grade(10) == "Serious security concerns"


def test_severity_counts():
    counts = severity_counts([_f("a", "High"), _f("b", "High"), _f("c", "Low")])
    assert counts == {"Critical": 0, "High": 2, "Medium": 0, "Low": 1, "Informational": 0}


def test_fingerprint_stable_and_url_normalized():
    a = _f("T", "Medium", url="https://example.com/page?x=1")
    b = _f("T", "Medium", url="https://example.com/page?y=2")
    c = _f("T", "Medium", url="https://example.com/other")
    assert fingerprint(a) == fingerprint(b)  # query ignored
    assert fingerprint(a) != fingerprint(c)


def test_normalize_dedupes_keeps_highest_confidence():
    lo = _f("Dup", "Medium", 0.5)
    hi = _f("Dup", "Medium", 0.9)
    out = normalize([lo, hi, _f("Other", "Low", 1.0)])
    assert len(out) == 2
    assert [f.confidence for f in out if f.title == "Dup"] == [0.9]


def test_normalize_sorts_by_severity_then_confidence():
    out = normalize([_f("low", "Low"), _f("crit", "Critical"), _f("med", "Medium")])
    assert [f.severity for f in out] == ["Critical", "Medium", "Low"]
    assert all(f.fingerprint for f in out)


def test_compare_new_resolved_persistent():
    old = {"fp1": {"severity": "High", "title": "A"},
           "fp2": {"severity": "Low", "title": "B"}}
    new = {"fp2": {"severity": "Medium", "title": "B"},
           "fp3": {"severity": "High", "title": "C"}}
    diff = compare_fingerprints(old, new)
    assert diff["resolved_count"] == 1
    assert diff["new_count"] == 1
    assert diff["persistent_count"] == 1
    assert diff["resolved"][0]["fingerprint"] == "fp1"
    assert diff["new"][0]["fingerprint"] == "fp3"
    assert len(diff["severity_changes"]) == 1
    assert diff["severity_changes"][0]["old_severity"] == "Low"
    assert diff["severity_changes"][0]["new_severity"] == "Medium"


def test_compare_identical():
    m = {"fp1": {"severity": "High", "title": "A"}}
    diff = compare_fingerprints(m, dict(m))
    assert diff["new_count"] == 0 and diff["resolved_count"] == 0
    assert diff["persistent_count"] == 1
