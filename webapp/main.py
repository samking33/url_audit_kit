import asyncio
import json
import os
from datetime import datetime
from typing import Dict, List, Optional

from dotenv import load_dotenv
from fastapi import FastAPI, Form, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.websockets import WebSocketDisconnect

from url_audit.runner import run_all_with_context, summarize, total_steps

load_dotenv(override=True)

app = FastAPI(
    title="URL Audit Kit API",
    description="DB-free URL audit backend with 41 checks and optional AI threat analysis.",
)

default_allow_origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:8765",
    "http://127.0.0.1:8765",
]

extra_allow_origins = [origin.strip() for origin in os.getenv("CORS_ALLOW_ORIGINS", "").split(",") if origin.strip()]
allow_origins = sorted(set(default_allow_origins + extra_allow_origins))
allow_origin_regex = os.getenv("CORS_ALLOW_ORIGIN_REGEX", r"^https://.*\.vercel\.app$")

app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_origin_regex=allow_origin_regex,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

SECTION_RULES: List[Dict[str, object]] = [
    {
        "section": "Domain Intelligence",
        "patterns": [
            "Domain Name Legitimacy",
            "Top-Level Domain",
            "WHOIS",
            "DNS / Email",
            "DNS / Email Records -",
            "Registrar Details",
            "Domain Expiry",
            "Domain Expiry and Renewal",
            "Previous Domain Ownership",
            "Previous Ownership History",
            "Domain Transfer",
            "Domain Transfer Records",
        ],
    },
    {
        "section": "Security Posture",
        "patterns": [
            "SSL Validity",
            "SSL/TLS Certificate Validity",
            "HTTPS Presence",
            "Presence of HTTPS",
            "Certificate Issuer",
            "Certificate Issuer (Reputable CA)",
            "Security Headers",
            "Security Header:",
            "IP Reputation",
            "IP Reputation & Hosting",
            "Server Geolocation",
            "Geolocation of Server",
            "Hosting Provider",
            "Hosting Provider Legitimacy",
            "Page Load Speed",
            "Mozilla Observatory",
        ],
    },
    {
        "section": "Content Integrity",
        "patterns": [
            "Content Quality",
            "Website Content and Design Quality",
            "Spelling Errors",
            "Grammar/Spelling Errors",
            "Brand Consistency",
            "Consistency with Brand Identity",
            "Contact Information",
            "Presence of Contact Information",
            "About / Privacy",
            "About Us / Privacy Policy Pages",
            "Too-Good Offers",
            "Too-Good-To-Be-True Offers",
            "Logos & Images",
            "Logo/Images Authenticity",
            "Broken Links",
            "Broken Links or Inactive Pages",
        ],
    },
    {
        "section": "Reputation & Trust",
        "patterns": [
            "Security Blacklists",
            "Reputation in Security Databases",
            "Google Safe Browsing",
            "Search Visibility",
            "Search Engine Visibility",
            "Social Mentions",
            "Social Media/Official Mentions",
            "Wayback Machine",
            "Historical Records (Wayback)",
            "News & Reviews",
            "News/Reviews about Domain",
            "Blacklists & Email Filters",
            "Blacklist Status in Email/URL Filters",
            "Community Feedback",
            "User Community Feedback",
            "Business Directories",
            "Presence on Business Directories",
        ],
    },
    {
        "section": "Behavioural Signals",
        "patterns": [
            "Redirect Behaviour",
            "Redirects and Shortened URLs",
            "Popups & Downloads",
            "Pop-Ups or Forced Downloads",
            "Suspicious Requests",
            "Suspicious Login or Payment Requests",
            "URL Length",
            "URL Length and Structure",
            "Homoglyph Detection",
            "Typosquatting or Homoglyph Domains",
            "Email Links",
            "Email Link Safety Advisory",
            "Mobile Friendliness",
            "Ads & Prompts",
            "Frequency of Unexpected Ads/Prompts",
        ],
    },
    {
        "section": "AI Observations",
        "patterns": [
            "AI Content Analysis",
        ],
    },
]

STATUS_STYLES: Dict[str, Dict[str, str]] = {
    "PASS": {"badge": "success", "icon": "verified"},
    "WARN": {"badge": "warning", "icon": "report"},
    "FAIL": {"badge": "danger", "icon": "dangerous"},
    "INFO": {"badge": "info", "icon": "info"},
}

_progress_lock = asyncio.Lock()
_progress_channels: Dict[str, asyncio.Queue] = {}


async def _get_progress_queue(job_id: str) -> asyncio.Queue:
    async with _progress_lock:
        queue = _progress_channels.get(job_id)
        if queue is None:
            queue = asyncio.Queue()
            _progress_channels[job_id] = queue
        return queue


async def _discard_progress_queue(job_id: str) -> None:
    async with _progress_lock:
        _progress_channels.pop(job_id, None)


async def _schedule_discard(job_id: str, delay: float = 120.0) -> None:
    await asyncio.sleep(delay)
    await _discard_progress_queue(job_id)


def _lookup_section(name: str) -> str:
    lower_name = name.lower()
    for rule in SECTION_RULES:
        patterns = rule.get("patterns") or []
        for pattern in patterns:
            if isinstance(pattern, str) and pattern.lower() in lower_name:
                return str(rule.get("section", "Additional Checks"))
    return "Additional Checks"


def _status_to_risk(status: str) -> str:
    mapping = {
        "PASS": "LOW",
        "INFO": "LOW",
        "WARN": "MODERATE",
        "FAIL": "HIGH",
    }
    return mapping.get(status.upper(), "MODERATE")


def _default_summary(result) -> Dict[str, str]:
    return {
        "summary_sentence": result.evidence or f"Status reported as {result.status}",
        "risk_level": _status_to_risk(result.status),
        "section": _lookup_section(result.name),
    }


def _build_summary_lookup(analysis: Dict[str, object], raw_results) -> Dict[str, Dict[str, str]]:
    lookup: Dict[str, Dict[str, str]] = {}
    per_check = analysis.get("per_check") if isinstance(analysis, dict) else None
    if isinstance(per_check, list):
        for entry in per_check:
            name = entry.get("name") if isinstance(entry, dict) else None
            if not name:
                continue
            risk_value = entry.get("risk_level", "") if isinstance(entry, dict) else ""
            if isinstance(risk_value, str):
                risk_value = risk_value.upper()
            lookup[name] = {
                "summary_sentence": entry.get("summary_sentence", "") if isinstance(entry, dict) else "",
                "risk_level": risk_value,
                "section": entry.get("section", _lookup_section(name)),
            }

    for result in raw_results:
        lookup.setdefault(result.name, _default_summary(result))

    return lookup


def _prepare_results(
    raw_results,
    summaries: Dict[str, Dict[str, str]],
) -> List[Dict[str, Optional[str]]]:
    prepared: List[Dict[str, Optional[str]]] = []
    for result in raw_results:
        style = STATUS_STYLES.get(result.status, {"badge": "secondary", "icon": "adjust"})
        details = ""
        if result.data:
            try:
                details = json.dumps(result.data, indent=2, default=str)
            except TypeError:
                details = str(result.data)

        summary_info = summaries.get(result.name) or _default_summary(result)
        prepared.append(
            {
                "id": result.id,
                "name": result.name,
                "status": result.status,
                "badge": style["badge"],
                "icon": style["icon"],
                "evidence": result.evidence or "",
                "details": details,
                "summary": summary_info.get("summary_sentence")
                or result.evidence
                or f"Status reported as {result.status}",
                "risk_level": summary_info.get("risk_level") or _status_to_risk(result.status),
                "section": summary_info.get("section") or _lookup_section(result.name),
            }
        )
    return prepared


def _build_summary_cards(counts: Dict[str, int]) -> List[Dict[str, Optional[str]]]:
    cards: List[Dict[str, Optional[str]]] = []
    for status in ["PASS", "WARN", "FAIL", "INFO"]:
        style = STATUS_STYLES.get(status, {"badge": "secondary", "icon": "bi-dot"})
        cards.append(
            {
                "status": status,
                "count": counts.get(status, 0),
                "badge": style["badge"],
                "icon": style["icon"],
            }
        )
    return cards


def _group_by_section(prepared_results: List[Dict[str, Optional[str]]]) -> List[Dict[str, object]]:
    sections: Dict[str, List[Dict[str, Optional[str]]]] = {}
    order: List[str] = []
    for item in prepared_results:
        section = item.get("section", "Additional Checks")
        if section not in sections:
            sections[section] = []
            order.append(section)
        sections[section].append(item)
    return [{"name": name, "checks": sections[name]} for name in order]


async def _run_ai_results_analysis(raw_results) -> Dict[str, object]:
    try:
        from url_audit.nvidia_analyzers import analyze_results_with_nvidia

        return await asyncio.to_thread(analyze_results_with_nvidia, raw_results)
    except Exception as exc:
        return {"enabled": False, "error": str(exc)}


async def _run_audit(clean_url: str, job_id: Optional[str]) -> Dict[str, object]:
    progress_queue: Optional[asyncio.Queue] = None
    loop = asyncio.get_running_loop()
    total = total_steps()

    if job_id:
        progress_queue = await _get_progress_queue(job_id)
        await progress_queue.put(
            {
                "type": "start",
                "step": 0,
                "total": total,
                "percent": 0,
                "label": "Preparing audit",
            }
        )

    def progress_callback(step_index: int, step_total: int, label: str, _: List) -> None:
        if not progress_queue:
            return
        adjusted_index = step_index if step_index <= step_total else step_total
        percent = int((adjusted_index / total) * 100)
        payload = {
            "type": "progress",
            "step": adjusted_index,
            "total": total,
            "percent": percent,
            "label": label,
        }
        loop.call_soon_threadsafe(progress_queue.put_nowait, payload)

    raw_results, target_context = await asyncio.to_thread(run_all_with_context, clean_url, progress_callback)
    counts = summarize(raw_results)
    analysis = await _run_ai_results_analysis(raw_results)
    summary_lookup = _build_summary_lookup(analysis, raw_results)
    prepared_results = _prepare_results(raw_results, summary_lookup)
    grouped_results = _group_by_section(prepared_results)
    threat_report = analysis.get("threat_report") if isinstance(analysis, dict) else None
    if not isinstance(threat_report, dict):
        threat_report = None

    metadata = analysis.get("metadata") if isinstance(analysis, dict) else None
    if not isinstance(metadata, dict):
        metadata = None

    analysis_error = analysis.get("error") if isinstance(analysis, dict) else None
    if analysis_error == "unparsed":
        analysis_error = "AI response could not be parsed."

    if progress_queue:
        await progress_queue.put(
            {
                "type": "complete",
                "step": total,
                "total": total,
                "percent": 100,
                "label": "Audit complete",
            }
        )
        if job_id:
            asyncio.create_task(_schedule_discard(job_id))

    summary_cards = _build_summary_cards(counts)
    total_checks = sum(counts.values())

    return {
        "results": prepared_results,
        "grouped_results": grouped_results,
        "summary_cards": summary_cards,
        "target_url": target_context.get("normalized_url", clean_url),
        "input_url": target_context.get("input_url", clean_url),
        "normalized_url": target_context.get("normalized_url", clean_url),
        "resolved_url": target_context.get("resolved_url", target_context.get("normalized_url", clean_url)),
        "total_checks": total_checks,
        "ai_threat_report": threat_report,
        "ai_metadata": metadata,
        "ai_error": analysis_error,
    }


@app.get("/")
async def index() -> Dict[str, object]:
    return {
        "name": "URL Audit Kit API",
        "version": "1.0.0",
        "status": "ok",
        "timestamp": f"{datetime.utcnow().isoformat()}Z",
        "endpoints": {
            "audit": "/api/audit",
            "health": "/healthz",
            "docs": "/docs",
            "progress_ws": "/ws/progress/{job_id}",
        },
    }


@app.get("/healthz")
async def healthz() -> Dict[str, str]:
    return {"status": "ok"}


@app.post("/api/audit")
@app.post("/audit")
async def audit_api(
    url: str = Form(...),
    job_id: Optional[str] = Form(None),
) -> JSONResponse:
    clean_url = url.strip()
    if not clean_url:
        return JSONResponse(
            content={"error": "Please enter a URL to audit."},
            status_code=400,
        )

    try:
        payload = await _run_audit(clean_url, job_id)
        return JSONResponse(content=payload)
    except Exception as exc:  # noqa: BLE001
        if job_id:
            queue = await _get_progress_queue(job_id)
            await queue.put({"type": "error", "message": str(exc)})
            asyncio.create_task(_schedule_discard(job_id))
        return JSONResponse(
            content={"error": f"Failed to audit URL: {exc}"},
            status_code=500,
        )


@app.websocket("/ws/progress/{job_id}")
async def audit_progress(websocket: WebSocket, job_id: str) -> None:
    await websocket.accept()
    queue = await _get_progress_queue(job_id)
    try:
        while True:
            message = await queue.get()
            await websocket.send_json(message)
            if message.get("type") in {"complete", "error"}:
                break
    except WebSocketDisconnect:  # pragma: no cover
        pass
    finally:
        await _discard_progress_queue(job_id)
