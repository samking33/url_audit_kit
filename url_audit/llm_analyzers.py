import os
import json
import re
import subprocess
import shlex
from typing import Dict, Any, Optional, Iterable

from .utils import get_env

try:
    from ollama import Client
except Exception:  # noqa: BLE001
    Client = None

# Optional JSON auto-repair (install with: pip install json-repair)
try:
    from json_repair import repair_json
except Exception:  # noqa: BLE001
    repair_json = None


def _client() -> Optional["Client"]:
    host = get_env("OLLAMA_HOST", "http://localhost:11434")
    return Client(host=host) if Client else None


def _extract_json_candidates(text: str) -> Iterable[str]:
    """
    Yield likely JSON blocks from a text response.
    Finds one or more {...} blocks; yields longest-first, then others.
    """
    matches = list(re.finditer(r"\{.*?\}", text, re.S))
    if not matches:
        return []
    # sort by length descending so we try the largest block first
    blocks = sorted((m.group(0) for m in matches), key=len, reverse=True)
    return blocks


def _parse_json_lenient(text: str) -> Optional[dict]:
    """
    Try parsing JSON from the model output:
    1) parse full text
    2) parse JSON-looking blocks (largest to smallest)
    3) attempt auto-repair when available
    """
    # First try the whole text as-is
    for candidate in [text, *list(_extract_json_candidates(text))]:
        # Raw
        try:
            return json.loads(candidate)
        except Exception:
            pass
        # Attempt repair, if available
        if repair_json is not None:
            try:
                fixed = repair_json(candidate)
                return json.loads(fixed)
            except Exception:
                pass
    return None


def _subprocess_fallback(model: str, prompt: str, timeout: int = 60) -> Dict[str, Any]:
    """
    Fallback to `ollama run` to ensure we can still get an answer even if the python client fails.
    """
    try:
        cmd = f"ollama run {shlex.quote(model)} {shlex.quote(prompt)}"
        out = subprocess.check_output(
            cmd,
            shell=True,
            timeout=timeout,
            stderr=subprocess.STDOUT,
            text=True,
        )
        parsed = _parse_json_lenient(out)
        if parsed is not None:
            return {"enabled": True, **parsed, "_via": "subprocess"}
        return {"enabled": True, "raw": out, "_via": "subprocess"}
    except Exception as e:  # noqa: BLE001
        return {"enabled": False, "error": f"subprocess: {e}"}


def analyze_text_with_llm(page_text: str, domain: str) -> Dict[str, Any]:
    """
    Uses a local Ollama model to judge:
    - grammar/spelling anomalies
    - too-good-to-be-true signals
    - brand consistency red flags
    - login/payment risk cues
    Returns a dict with booleans/notes and a compact summary.
    """
    model = get_env("OLLAMA_MODEL", "llama3.1:8b")
    timeout = int(get_env("OLLAMA_TIMEOUT", "60") or "60")

    prompt = f"""You are a security reviewer. Given the domain "{domain}" and this web page text:
---
{page_text[:12000]}
---
Respond ONLY with a single JSON object (no prose before/after). Use double quotes for all keys/strings.
Include 8–10 concise bullet findings with YES/NO + one-line reason.
Use exactly these keys:
  "grammar_issues", "too_good_claims", "credential_or_payment_risk",
  "brand_mismatch", "generic_content", "phishy_tone",
  "overall_risk", "summary"
Where:
- grammar_issues: "YES|NO: reason"
- too_good_claims: "YES|NO: reason"
- credential_or_payment_risk: "YES|NO: reason"
- brand_mismatch: "YES|NO: reason"
- generic_content: "YES|NO: reason"
- phishy_tone: "YES|NO: reason"
- overall_risk: "LOW|MEDIUM|HIGH"
- summary: one sentence.
"""

    # Try Python client first
    if Client:
        try:
            cli = _client()
            resp = cli.generate(
                model=model,
                prompt=prompt,
                options={"temperature": 0.1},
            )
            content = resp.get("response", "") if isinstance(resp, dict) else str(resp)
            parsed = _parse_json_lenient(content)
            if parsed is not None:
                return {"enabled": True, **parsed, "_via": "python-client"}
            # If not valid JSON, still return raw so user can see what came back
            return {"enabled": True, "raw": content, "_via": "python-client"}
        except Exception as e:  # noqa: BLE001
            py_err = str(e)
            fb = _subprocess_fallback(model, prompt, timeout=timeout)
            if fb.get("enabled"):
                fb["_python_error"] = py_err
                return fb
            return {"enabled": False, "error": f"python-client: {py_err}; {fb.get('error','')}"}

    # Fallback directly to CLI
    fb = _subprocess_fallback(model, prompt, timeout=timeout)
    return fb