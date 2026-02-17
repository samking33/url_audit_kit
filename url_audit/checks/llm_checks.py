import re
from typing import Dict

from ..nvidia_analyzers import analyze_text_with_nvidia
from ..utils import CheckResult, domain_parts, fetch, get_fetch_diagnostics


def _to_yes_no(flag: bool, reason: str) -> str:
    return f"{'YES' if flag else 'NO'}: {reason}"


def _local_text_analysis(text: str) -> Dict[str, str]:
    lower = text.lower()

    grammar_like = bool(re.search(r"\b(click here now|act now|limited time only)\b", lower))
    too_good = bool(re.search(r"\b(free money|guaranteed return|risk[- ]?free profit|instant winnings)\b", lower))
    credential_risk = bool(re.search(r"\b(password|otp|cvv|credit card|bank account|seed phrase)\b", lower))
    brand_mismatch = bool(re.search(r"\b(official support team)\b", lower)) and "contact" not in lower
    generic = len(set(re.findall(r"[a-z]{4,}", lower))) < 40
    phishy_tone = bool(re.search(r"\b(verify your account|suspended immediately|urgent action required)\b", lower))

    signals = sum(
        int(flag)
        for flag in [grammar_like, too_good, credential_risk, brand_mismatch, phishy_tone]
    )
    overall = "HIGH" if signals >= 3 else ("MEDIUM" if signals >= 1 else "LOW")

    return {
        "grammar_issues": _to_yes_no(grammar_like, "lexical urgency pattern"),
        "too_good_claims": _to_yes_no(too_good, "implausible marketing phrase"),
        "credential_or_payment_risk": _to_yes_no(credential_risk, "credential/payment terms present"),
        "brand_mismatch": _to_yes_no(brand_mismatch, "trust language without clear ownership cues"),
        "generic_content": _to_yes_no(generic, "low unique-word variety"),
        "phishy_tone": _to_yes_no(phishy_tone, "coercive security phrasing"),
        "overall_risk": overall,
        "summary": "Local heuristic fallback used for content-risk scoring.",
        "enabled": True,
        "_via": "local-heuristic",
    }


def _extract_flags(analysis: Dict[str, str]) -> list:
    flags = []
    if "YES" in str(analysis.get("grammar_issues", "")).upper():
        flags.append("grammar")
    if "YES" in str(analysis.get("too_good_claims", "")).upper():
        flags.append("too-good-claims")
    if "YES" in str(analysis.get("credential_or_payment_risk", "")).upper():
        flags.append("credential-risk")
    if "YES" in str(analysis.get("brand_mismatch", "")).upper():
        flags.append("brand-mismatch")
    if "YES" in str(analysis.get("phishy_tone", "")).upper():
        flags.append("phishy-tone")
    return flags


def check_llm_content_analysis(url: str) -> CheckResult:
    """(41) AI-powered content analysis for phishing signals."""
    try:
        response, html, soup = fetch(url)
        if not soup:
            diagnostics = get_fetch_diagnostics(url)
            error_text = diagnostics.get("error") or "Page content unavailable"
            return CheckResult(
                41,
                "AI Content Analysis",
                "WARN",
                evidence=f"Could not parse page content: {str(error_text)[:180]}",
                data={"diagnostics": diagnostics},
            )

        text = soup.get_text(" ", strip=True)
        if not text or len(text) < 50:
            return CheckResult(
                41,
                "AI Content Analysis",
                "INFO",
                evidence="Insufficient text for high-confidence AI analysis",
            )

        _, host, _ = domain_parts(url)
        ai_result = analyze_text_with_nvidia(text, host or "unknown")

        if not ai_result.get("enabled"):
            local_analysis = _local_text_analysis(text)
            local_analysis["fallback_reason"] = ai_result.get("error", "NIM unavailable")
            analysis = local_analysis
        else:
            analysis = ai_result

        flags = _extract_flags(analysis)
        overall = str(analysis.get("overall_risk", "LOW")).upper()
        status = "FAIL" if overall == "HIGH" else ("WARN" if overall == "MEDIUM" or flags else "PASS")

        evidence_bits = [f"risk={overall}", f"source={analysis.get('_via', 'nvidia')}"]
        if flags:
            evidence_bits.append(f"flags={','.join(flags)}")

        summary = str(analysis.get("summary", "")).strip()
        if summary:
            evidence_bits.append(summary[:160])

        return CheckResult(
            41,
            "AI Content Analysis",
            status,
            evidence=" | ".join(evidence_bits),
            data=analysis,
        )
    except Exception as exc:  # noqa: BLE001
        return CheckResult(41, "AI Content Analysis", "WARN", evidence=f"Analysis error: {type(exc).__name__}: {str(exc)[:140]}")
