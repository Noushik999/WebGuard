"""AI security analyst.

Design (per spec §10/§12/§45):
- The deterministic scanner is the source of truth. The analyst NEVER creates,
  upgrades, or invents findings — it only explains scanner evidence.
- A rule-based analyst is always available (offline, no API key).
- If OPENAI_API_KEY is configured, an LLM may *rephrase/enrich* the explanation,
  but only from the finding's evidence, with a strict grounding prompt.
  Any LLM failure falls back to the rule-based version.
- Every output carries a confidence note and states when evidence is thin.
"""

from __future__ import annotations

import httpx

from scanner.schemas import Finding
from .config import get_settings

PRIORITY_BY_SEVERITY = {
    "Critical": "P0 — fix immediately, before any new feature work",
    "High": "P1 — fix in the current sprint / within days",
    "Medium": "P2 — schedule within weeks",
    "Low": "P3 — fix opportunistically / during hardening",
    "Informational": "P4 — awareness / best practice",
}


def rule_based_analysis(f: Finding) -> dict:
    sev_note = {
        "Critical": "This is the highest severity WebGuard assigns. Treat it as an active risk, not a theoretical one.",
        "High": "This is a serious, practically exploitable-class issue.",
        "Medium": "This meaningfully weakens the site's defenses and should be scheduled.",
        "Low": "A defense-in-depth improvement rather than an immediate threat.",
        "Informational": "Not a vulnerability — context to help you make informed decisions.",
    }[f.severity]
    return {
        "plain_english": (
            f"WebGuard noticed: {f.title}. In plain terms — {f.description} "
            f"{f.why_it_matters}"
        ),
        "technical": f.evidence,
        "impact": f.why_it_matters,
        "priority": PRIORITY_BY_SEVERITY[f.severity],
        "remediation_steps": _steps_from_recommendation(f.recommendation),
        "verification": f.verification or "Re-run the WebGuard assessment and confirm this finding no longer appears.",
        "confidence_note": (
            f"{sev_note} WebGuard's confidence in this observation is {f.confidence:.0%}, "
            f"based on direct evidence from the '{f.scanner}' check. "
            "If the evidence below looks thin or contextual, treat the priority as advisory."
            if f.confidence < 0.8 else
            f"{sev_note} WebGuard's confidence in this observation is {f.confidence:.0%}, "
            f"based on direct evidence from the '{f.scanner}' check."
        ),
        "source": "rules",
    }


def _steps_from_recommendation(rec: str) -> list[str]:
    sentences = [s.strip(" .") for s in rec.replace("\n", " ").split(". ") if s.strip()]
    steps = [s + "." for s in sentences if len(s) > 12]
    return steps[:6] or [rec]


LLM_SYSTEM = """You are WebGuard's security analyst. You explain web-security findings to developers.

STRICT RULES:
1. Reason ONLY from the finding evidence provided. NEVER invent new evidence, URLs, payloads, or attack details.
2. NEVER upgrade the severity or claim exploitability beyond what the evidence supports.
3. If evidence is insufficient, say so explicitly.
4. Output JSON with keys: plain_english, technical, impact, priority, remediation_steps (array), verification, confidence_note.
5. Keep plain_english under 80 words. Be concrete and developer-focused."""


def llm_enrich(f: Finding) -> dict | None:
    """Try LLM enrichment; return None on any failure (caller falls back to rules)."""
    settings = get_settings()
    if not settings.OPENAI_API_KEY:
        return None
    try:
        payload = {
            "model": settings.OPENAI_MODEL,
            "messages": [
                {"role": "system", "content": LLM_SYSTEM},
                {"role": "user", "content":
                 f"Finding: {f.title}\nSeverity: {f.severity} (do not change)\n"
                 f"Confidence: {f.confidence}\nCategory: {f.category}\n"
                 f"Description: {f.description}\nWhy it matters: {f.why_it_matters}\n"
                 f"Evidence:\n{f.evidence}\nRecommendation: {f.recommendation}\n"
                 f"Verification: {f.verification}"},
            ],
            "temperature": 0.2,
            "response_format": {"type": "json_object"},
        }
        r = httpx.post(
            f"{settings.OPENAI_BASE_URL}/chat/completions",
            headers={"Authorization": f"Bearer {settings.OPENAI_API_KEY}"},
            json=payload, timeout=25.0,
        )
        r.raise_for_status()
        import json as _json
        data = _json.loads(r.json()["choices"][0]["message"]["content"])
        data["source"] = "llm"
        # Guardrail: LLM must not change severity/priority semantics silently.
        data["priority"] = PRIORITY_BY_SEVERITY[f.severity]
        if "remediation_steps" not in data or not isinstance(data["remediation_steps"], list):
            return None
        return data
    except Exception:
        return None


def analyze(f: Finding) -> dict:
    """Public entry: rule-based always; LLM enrichment when configured and healthy."""
    base = rule_based_analysis(f)
    enriched = llm_enrich(f)
    if enriched:
        # Merge: keep deterministic priority + confidence note, take LLM prose.
        enriched["priority"] = base["priority"]
        enriched["confidence_note"] = base["confidence_note"] + " (Prose refined by an LLM from the same evidence.)"
        return enriched
    return base
