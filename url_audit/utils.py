import os
import re
import socket
import ssl
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urlunparse

import dns.resolver
import requests
import tldextract
from bs4 import BeautifulSoup, FeatureNotFound

TIMEOUT = int(os.getenv("AUDIT_TIMEOUT_SECONDS", "15"))
DEFAULT_HEADERS = {"User-Agent": "URL-Audit-Kit/1.0"}

_FETCH_CACHE: Dict[str, Tuple[Optional[requests.Response], Optional[str], Optional[BeautifulSoup]]] = {}
_FETCH_DIAGNOSTICS: Dict[str, Dict[str, Any]] = {}


def get_env(name: str, default: Optional[str] = None) -> Optional[str]:
    value = os.getenv(name, default)
    return value if value not in ("", None) else None


@dataclass
class CheckResult:
    id: int
    name: str
    status: str  # PASS | WARN | FAIL | INFO
    evidence: str = ""
    data: Dict[str, Any] = field(default_factory=dict)


def normalize_url(raw_url: str, default_scheme: str = "https") -> str:
    value = (raw_url or "").strip()
    if not value:
        raise ValueError("URL is empty")

    if "://" not in value:
        value = f"{default_scheme}://{value}"

    parsed = urlparse(value)
    scheme = (parsed.scheme or default_scheme).lower()
    if scheme not in {"http", "https"}:
        raise ValueError(f"Unsupported URL scheme: {scheme}")

    host = (parsed.hostname or "").strip().lower().strip(".")
    if not host:
        raise ValueError("URL host is missing")

    try:
        host_ascii = host.encode("idna").decode("ascii")
    except Exception:
        host_ascii = host

    port = parsed.port
    include_port = bool(
        port
        and not (scheme == "https" and port == 443)
        and not (scheme == "http" and port == 80)
    )
    netloc = f"{host_ascii}:{port}" if include_port else host_ascii

    path = parsed.path or "/"
    if not path.startswith("/"):
        path = "/" + path
    path = re.sub(r"/{2,}", "/", path)

    return urlunparse((scheme, netloc, path, "", parsed.query, ""))


def _candidate_urls(normalized_url: str) -> List[str]:
    parsed = urlparse(normalized_url)
    https_url = urlunparse(("https", parsed.netloc, parsed.path or "/", "", parsed.query, ""))
    http_url = urlunparse(("http", parsed.netloc, parsed.path or "/", "", parsed.query, ""))

    candidates = [https_url]
    if http_url != https_url:
        candidates.append(http_url)
    return candidates


def _parse_html(html: str) -> Tuple[Optional[BeautifulSoup], Optional[str], Optional[str]]:
    if not html:
        return None, None, None

    for parser in ("lxml", "html.parser"):
        try:
            return BeautifulSoup(html, parser), parser, None
        except FeatureNotFound as exc:
            last_error = str(exc)
        except Exception as exc:  # noqa: BLE001
            last_error = str(exc)
    return None, None, last_error


def _cache_fetch(
    key: str,
    response: Optional[requests.Response],
    html: Optional[str],
    soup: Optional[BeautifulSoup],
    diagnostics: Dict[str, Any],
) -> None:
    _FETCH_CACHE[key] = (response, html, soup)
    _FETCH_DIAGNOSTICS[key] = diagnostics


def fetch(url: str) -> Tuple[Optional[requests.Response], Optional[str], Optional[BeautifulSoup]]:
    input_url = (url or "").strip()
    try:
        normalized_url = normalize_url(input_url)
    except Exception as exc:  # noqa: BLE001
        diagnostics = {
            "input_url": input_url,
            "normalized_url": None,
            "attempted_urls": [],
            "resolved_url": None,
            "success": False,
            "error": f"normalize_error: {exc}",
        }
        _FETCH_DIAGNOSTICS[input_url] = diagnostics
        return None, None, None

    if normalized_url in _FETCH_CACHE:
        return _FETCH_CACHE[normalized_url]

    attempted: List[str] = []
    errors: List[str] = []

    for candidate in _candidate_urls(normalized_url):
        attempted.append(candidate)
        try:
            response = requests.get(
                candidate,
                timeout=TIMEOUT,
                allow_redirects=True,
                headers=DEFAULT_HEADERS,
            )
            html = response.text if response.content else ""
            soup, parser_used, parse_error = _parse_html(html)
            resolved_url = response.url or candidate

            diagnostics = {
                "input_url": input_url,
                "normalized_url": normalized_url,
                "attempted_urls": attempted,
                "resolved_url": resolved_url,
                "success": True,
                "http_status": response.status_code,
                "parser": parser_used,
                "parse_error": parse_error,
            }

            _cache_fetch(normalized_url, response, html, soup, diagnostics)

            if resolved_url:
                try:
                    normalized_resolved = normalize_url(resolved_url)
                    _cache_fetch(normalized_resolved, response, html, soup, diagnostics)
                except Exception:
                    pass

            return response, html, soup
        except requests.exceptions.RequestException as exc:
            errors.append(f"{candidate} ({type(exc).__name__}): {exc}")
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{candidate} ({type(exc).__name__}): {exc}")

    diagnostics = {
        "input_url": input_url,
        "normalized_url": normalized_url,
        "attempted_urls": attempted,
        "resolved_url": None,
        "success": False,
        "error": " | ".join(errors) if errors else "request failed",
    }
    _cache_fetch(normalized_url, None, None, None, diagnostics)
    return None, None, None


def get_fetch_diagnostics(url: str) -> Dict[str, Any]:
    key = (url or "").strip()
    if key in _FETCH_DIAGNOSTICS:
        return dict(_FETCH_DIAGNOSTICS[key])

    try:
        normalized_key = normalize_url(key)
    except Exception:
        normalized_key = key

    if normalized_key in _FETCH_DIAGNOSTICS:
        return dict(_FETCH_DIAGNOSTICS[normalized_key])

    return {
        "input_url": key,
        "normalized_url": normalized_key,
        "attempted_urls": [],
        "resolved_url": None,
        "success": False,
        "error": "No fetch attempted",
    }


def resolve_audit_target(raw_url: str) -> Dict[str, str]:
    input_url = (raw_url or "").strip()
    normalized_url = input_url

    try:
        normalized_url = normalize_url(input_url)
    except Exception:
        pass

    response, _, _ = fetch(normalized_url)
    diagnostics = get_fetch_diagnostics(normalized_url)

    resolved_url = diagnostics.get("resolved_url") or (response.url if response else None) or normalized_url

    return {
        "input_url": input_url,
        "normalized_url": normalized_url,
        "resolved_url": resolved_url,
    }


def head(url: str) -> Optional[requests.Response]:
    input_url = (url or "").strip()
    try:
        normalized_url = normalize_url(input_url)
        candidates = _candidate_urls(normalized_url)
    except Exception:
        candidates = [input_url]

    for candidate in candidates:
        try:
            return requests.head(
                candidate,
                timeout=TIMEOUT,
                allow_redirects=True,
                headers=DEFAULT_HEADERS,
            )
        except Exception:
            continue
    return None


def get_cert_chain(hostname: str, port: int = 443):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
                return secure_sock.getpeercert()
    except Exception:
        return None


def domain_parts(url: str):
    value = (url or "").strip()
    try:
        parsed = urlparse(normalize_url(value))
    except Exception:
        if "://" not in value and value:
            value = f"https://{value}"
        parsed = urlparse(value)

    host = (parsed.hostname or "").lower()
    ext = tldextract.extract(host)
    return parsed, host, ext


def txt_records(domain: str) -> List[str]:
    records: List[str] = []
    try:
        for rdata in dns.resolver.resolve(domain, "TXT"):
            records.extend(
                [
                    part.decode("utf-8") if isinstance(part, bytes) else str(part)
                    for part in rdata.strings
                ]
            )
    except Exception:
        pass
    return records


def mx_records(domain: str) -> List[str]:
    try:
        return [str(record.exchange).rstrip(".") for record in dns.resolver.resolve(domain, "MX")]
    except Exception:
        return []


def whois_lookup(domain: str):
    try:
        import whois

        return whois.whois(domain)
    except Exception:
        return None


def http_json(url: str, params=None, headers=None):
    try:
        response = requests.get(url, params=params, headers=headers, timeout=TIMEOUT)
        if response.ok:
            return response.json()
    except Exception:
        return None
    return None


def post_json(url: str, json_body=None, headers=None):
    try:
        response = requests.post(url, json=json_body, headers=headers, timeout=TIMEOUT)
        if response.ok:
            return response.json()
    except Exception:
        return None
    return None


def normalize_status(ok: bool, warn: bool = False) -> str:
    if ok and not warn:
        return "PASS"
    if ok and warn:
        return "WARN"
    return "FAIL"


def has_security_header(headers: dict, key: str) -> bool:
    return any(header.lower() == key.lower() for header in headers.keys())


def count_redirects(url: str) -> int:
    input_url = (url or "").strip()
    try:
        normalized_url = normalize_url(input_url)
        candidates = _candidate_urls(normalized_url)
    except Exception:
        candidates = [input_url]

    for candidate in candidates:
        try:
            response = requests.get(candidate, timeout=TIMEOUT, allow_redirects=True, headers=DEFAULT_HEADERS)
            return len(response.history)
        except Exception:
            continue
    return 0
