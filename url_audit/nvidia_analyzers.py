"""
NVIDIA NIM-powered analysis for URL audit content and results.
"""
import json
import os
from datetime import datetime
from typing import Any, Dict, List

import requests

from .utils import CheckResult


def analyze_text_with_nvidia(page_text: str, domain: str) -> Dict[str, Any]:
    """Analyze page text for phishing indicators using NVIDIA NIM."""
    config = _load_config()
    if not config["api_key"]:
        return {"enabled": False, "error": "NVIDIA_NIM_API_KEY not configured"}

    prompt = f"""Analyze this webpage for phishing/security risks. Domain: {domain}

Text: {page_text[:8000]}

Respond with JSON only:
{{
  "grammar_issues": "YES|NO: reason",
  "too_good_claims": "YES|NO: reason",
  "credential_or_payment_risk": "YES|NO: reason",
  "brand_mismatch": "YES|NO: reason",
  "generic_content": "YES|NO: reason",
  "phishy_tone": "YES|NO: reason",
  "overall_risk": "LOW|MEDIUM|HIGH",
  "summary": "one sentence"
}}"""

    try:
        content = _chat_completion(
            api_key=config["api_key"],
            base_url=config["base_url"],
            model=config["model"],
            timeout=config["timeout"],
            messages=[
                {
                    "role": "system",
                    "content": "/no_think You are a cybersecurity analyst. Return strict JSON only.",
                },
                {"role": "user", "content": prompt},
            ],
            max_tokens=1000,
            temperature=0.1,
        )
        parsed = _parse_json(content)
        normalized = _normalize_text_analysis(parsed)
        normalized["_via"] = "nvidia"
        normalized["enabled"] = True
        return normalized
    except Exception as exc:
        return {"enabled": False, "error": str(exc)}


def analyze_results_with_nvidia(results: List[CheckResult]) -> Dict[str, Any]:
    """Generate final threat report from check results using NVIDIA NIM."""
    config = _load_config()
    if not config["api_key"]:
        return {"enabled": False, "error": "NVIDIA_NIM_API_KEY not configured"}

    checks_summary = []
    for r in results[:50]:
        checks_summary.append({"name": r.name, "status": r.status, "evidence": (r.evidence or "")[:150]})

    prompt = f"""Analyze these security check results and create a threat intelligence report.

Checks: {json.dumps(checks_summary)}

Respond with JSON only:
{{
  "per_check": [
    {{"name": "check name", "status": "PASS|WARN|FAIL", "summary_sentence": "brief analysis", "risk_level": "LOW|MODERATE|HIGH"}}
  ],
  "threat_report": {{
    "executive_summary": "2-3 sentences",
    "key_findings": ["finding 1", "finding 2", "finding 3"],
    "verdict": "BENIGN|SUSPICIOUS|MALICIOUS",
    "verdict_rationale": "explanation",
    "recommendations": ["rec 1", "rec 2", "rec 3"]
  }},
  "metadata": {{
    "generator": "nvidia-nim",
    "model": "{config["model"]}",
    "timestamp": "{datetime.utcnow().isoformat()}Z"
  }}
}}"""

    try:
        content = _chat_completion(
            api_key=config["api_key"],
            base_url=config["base_url"],
            model=config["model"],
            timeout=config["timeout"],
            messages=[
                {
                    "role": "system",
                    "content": "/no_think You are a senior threat analyst. Return strict JSON only.",
                },
                {"role": "user", "content": prompt},
            ],
            max_tokens=2000,
            temperature=0.2,
        )
        parsed = _parse_json(content)
        normalized = _normalize_results_analysis(parsed, config["model"])
        normalized["enabled"] = True
        return normalized
    except Exception as exc:
        return {"enabled": False, "error": str(exc)}


def _load_config() -> Dict[str, Any]:
    return {
        "api_key": (
            os.getenv("NVIDIA_NIM_API_KEY")
            or os.getenv("NVIDIA_API_KEY")
            or os.getenv("NIM_API_KEY")
        ),
        "model": os.getenv("NVIDIA_TEXT_MODEL", "nvidia/llama-3.3-nemotron-super-49b-v1.5"),
        "base_url": os.getenv("NVIDIA_NIM_BASE_URL", "https://integrate.api.nvidia.com/v1").rstrip("/"),
        "timeout": int(os.getenv("NVIDIA_TIMEOUT", "60")),
    }


def _chat_completion(
    api_key: str,
    base_url: str,
    model: str,
    timeout: int,
    messages: List[Dict[str, str]],
    max_tokens: int,
    temperature: float,
) -> str:
    response = requests.post(
        f"{base_url}/chat/completions",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        },
        timeout=timeout,
    )
    if not response.ok:
        detail = response.text[:300]
        raise RuntimeError(f"NVIDIA NIM API error {response.status_code}: {detail}")

    payload = response.json()
    return str(payload["choices"][0]["message"]["content"]).strip()


def _parse_json(text: str) -> Dict[str, Any]:
    text = text.strip()
    candidates: List[str] = [text]

    if "```json" in text:
        candidates.append(text.split("```json", 1)[1].split("```", 1)[0].strip())
    elif "```" in text:
        candidates.append(text.split("```", 1)[1].split("```", 1)[0].strip())

    left = text.find("{")
    right = text.rfind("}")
    if left != -1 and right > left:
        candidates.append(text[left : right + 1].strip())

    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            continue

    parsed_from_blob = _find_first_json_object(text)
    if parsed_from_blob:
        return parsed_from_blob

    raise ValueError("Failed to parse JSON response from NVIDIA NIM")


def _find_first_json_object(text: str) -> Dict[str, Any]:
    for start in range(len(text)):
        if text[start] != "{":
            continue
        depth = 0
        in_string = False
        escaped = False
        for end in range(start, len(text)):
            char = text[end]
            if in_string:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    in_string = False
                continue

            if char == '"':
                in_string = True
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    candidate = text[start : end + 1]
                    try:
                        parsed = json.loads(candidate)
                        if isinstance(parsed, dict):
                            return parsed
                    except json.JSONDecodeError:
                        break
    return {}


def _normalize_text_analysis(raw: Dict[str, Any]) -> Dict[str, Any]:
    defaults = {
        "grammar_issues": "NO: no clear grammar issues detected",
        "too_good_claims": "NO: no implausible claims detected",
        "credential_or_payment_risk": "NO: no direct credential/payment solicitation detected",
        "brand_mismatch": "NO: no obvious brand mismatch detected",
        "generic_content": "NO: content appears sufficiently specific",
        "phishy_tone": "NO: no obvious phishing language patterns detected",
        "overall_risk": "LOW",
        "summary": "No high-confidence phishing signals found in page text.",
    }
    normalized = dict(defaults)
    for key in defaults:
        if key in raw and raw[key] is not None:
            normalized[key] = str(raw[key]).strip()
    normalized["overall_risk"] = str(normalized.get("overall_risk", "LOW")).upper()
    return normalized


def _normalize_results_analysis(raw: Any, model: str) -> Dict[str, Any]:
    if not isinstance(raw, dict):
        return {
            "per_check": [],
            "threat_report": {},
            "metadata": {
                "generator": "nvidia-nim",
                "model": model,
                "timestamp": f"{datetime.utcnow().isoformat()}Z",
            },
        }

    analysis: Dict[str, Any] = dict(raw)
    analysis["per_check"] = _normalize_per_check(analysis.get("per_check"))
    analysis["threat_report"] = _normalize_threat_report(analysis.get("threat_report"))
    analysis["metadata"] = _normalize_metadata(analysis.get("metadata"), model)
    return analysis


def _normalize_per_check(per_check: Any) -> List[Dict[str, str]]:
    if not isinstance(per_check, list):
        return []

    normalised: List[Dict[str, str]] = []
    for entry in per_check:
        if not isinstance(entry, dict):
            continue
        status = str(entry.get("status") or entry.get("result") or "INFO").upper()
        normalised.append(
            {
                "name": str(entry.get("name") or entry.get("check") or entry.get("id") or "Unnamed check"),
                "status": status,
                "summary_sentence": str(
                    entry.get("summary_sentence")
                    or entry.get("summary")
                    or entry.get("analysis")
                    or entry.get("insight")
                    or ""
                ).strip(),
                "risk_level": str(entry.get("risk_level") or _status_to_risk(status)).upper(),
            }
        )
    return normalised


def _normalize_threat_report(report: Any) -> Dict[str, Any]:
    if not isinstance(report, dict):
        report = {}

    summary = _coerce_text(
        report.get("executive_summary")
        or report.get("summary")
        or report.get("overview")
        or report.get("verdict_rationale")
    )
    verdict = _normalise_verdict(report.get("verdict"), report.get("risk_level"))
    rationale = _coerce_text(
        report.get("verdict_rationale")
        or report.get("analysis")
        or report.get("rationale")
        or report.get("explanation")
        or report.get("verdict_reason")
    )
    key_findings = _coerce_list(report.get("key_findings") or report.get("findings"))
    recommendations = _coerce_list(report.get("recommendations") or report.get("remediation"))

    return {
        "executive_summary": summary,
        "verdict": verdict,
        "verdict_rationale": rationale,
        "key_findings": key_findings,
        "recommendations": recommendations,
    }


def _normalize_metadata(metadata: Any, model: str) -> Dict[str, Any]:
    if not isinstance(metadata, dict):
        metadata = {}
    metadata = dict(metadata)
    metadata.setdefault("generator", "nvidia-nim")
    metadata.setdefault("model", model)
    metadata.setdefault("timestamp", f"{datetime.utcnow().isoformat()}Z")
    return metadata


def _coerce_text(value: Any) -> str:
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, list):
        return "; ".join(str(v).strip() for v in value if str(v).strip())
    if value is None:
        return ""
    return str(value)


def _coerce_list(value: Any) -> List[str]:
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    if isinstance(value, str):
        candidates = [segment.strip(" -•\t") for segment in value.replace("\r", "\n").split("\n") if segment.strip()]
        if not candidates and value:
            candidates = [value.strip()]
        return candidates
    if value is None:
        return []
    return [str(value).strip()]


def _normalise_verdict(verdict: Any, risk_level: Any) -> str:
    candidates = [verdict, risk_level]
    for candidate in candidates:
        if not candidate:
            continue
        text = str(candidate).strip().upper()
        if text in {"BENIGN", "SUSPICIOUS", "MALICIOUS"}:
            return text
        if text in {"LOW", "MINIMAL", "SAFE"}:
            return "BENIGN"
        if text in {"MEDIUM", "MODERATE"}:
            return "SUSPICIOUS"
        if text in {"HIGH", "CRITICAL", "SEVERE", "DANGEROUS"}:
            return "MALICIOUS"
    return "UNKNOWN"


def _status_to_risk(status: str) -> str:
    mapping = {
        "PASS": "LOW",
        "INFO": "LOW",
        "WARN": "MODERATE",
        "FAIL": "HIGH",
    }
    return mapping.get(status.upper(), "MODERATE")
