import ipaddress
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Optional, Tuple

import requests

from ..utils import CheckResult, domain_parts, fetch


def _resolve_host(url: str) -> Tuple[Optional[str], Optional[str]]:
    try:
        _, host, _ = domain_parts(url)
        if not host:
            return None, None
        return host, socket.gethostbyname(host)
    except Exception:
        return None, None


def _get_cert(host: str, port: int = 443):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as secure_sock:
                return secure_sock.getpeercert(), secure_sock.getpeercert(binary_form=True)
    except Exception as exc:  # noqa: BLE001
        raise exc


def _parse_not_after(peercert_info) -> Optional[datetime]:
    try:
        value = peercert_info.get("notAfter")
        if not value:
            return None
        parsed = datetime.strptime(value, "%b %d %H:%M:%S %Y %Z")
        return parsed.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def _parse_subject_common_name(peercert_info) -> Optional[str]:
    try:
        for item in peercert_info.get("subject") or []:
            for pair in item:
                if str(pair[0]).lower() in {"commonname", "cn"}:
                    return str(pair[1])
    except Exception:
        return None
    return None


def _parse_issuer(peercert_info) -> Optional[str]:
    try:
        parts = []
        for item in peercert_info.get("issuer") or []:
            for pair in item:
                key = str(pair[0]).lower()
                if key in {"organizationname", "commonname", "countryname"}:
                    parts.append(str(pair[1]))
        return " ".join(parts) if parts else None
    except Exception:
        return None


def _reverse_dns(ip: str) -> Optional[str]:
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except Exception:
        return None


def check_ssl_validity(url: str) -> CheckResult:
    # (9) SSL/TLS Certificate Validity
    try:
        _, host, _ = domain_parts(url)
        if not host:
            return CheckResult(9, "SSL/TLS Certificate Validity", "WARN", evidence="no host")

        cert_info, _ = _get_cert(host, 443)
        not_after = _parse_not_after(cert_info)
        subject = _parse_subject_common_name(cert_info)

        if not not_after:
            return CheckResult(9, "SSL/TLS Certificate Validity", "WARN", evidence=f"subject={subject} expiry unavailable")

        days_left = (not_after - datetime.now(timezone.utc)).days
        status = "PASS" if days_left > 14 else "WARN"
        return CheckResult(9, "SSL/TLS Certificate Validity", status, evidence=f"subject={subject} expires_in_days={days_left}")
    except Exception as exc:  # noqa: BLE001
        return CheckResult(9, "SSL/TLS Certificate Validity", "WARN", evidence=str(exc))


def check_https_presence(url: str) -> CheckResult:
    # (10) Presence of HTTPS
    try:
        scheme = (url.split(":", 1)[0] if ":" in url else "").lower()
        status = "PASS" if scheme == "https" else "WARN"
        return CheckResult(10, "Presence of HTTPS", status, evidence=f"scheme={scheme or 'unknown'}")
    except Exception as exc:  # noqa: BLE001
        return CheckResult(10, "Presence of HTTPS", "WARN", evidence=str(exc))


def check_certificate_issuer(url: str) -> CheckResult:
    # (11) Certificate Issuer (Reputable CA)
    try:
        _, host, _ = domain_parts(url)
        if not host:
            return CheckResult(11, "Certificate Issuer (Reputable CA)", "WARN", evidence="no host")

        cert_info, _ = _get_cert(host, 443)
        issuer = _parse_issuer(cert_info)
        return CheckResult(
            11,
            "Certificate Issuer (Reputable CA)",
            "PASS" if issuer else "WARN",
            evidence=f"issuer={issuer or 'unknown'}",
        )
    except Exception as exc:  # noqa: BLE001
        return CheckResult(11, "Certificate Issuer (Reputable CA)", "WARN", evidence=str(exc))


def check_security_headers(url: str):
    # (12) Security Headers (CSP/HSTS/XFO)
    results = []
    try:
        response, _, _ = fetch(url)
        if not response:
            raise RuntimeError("page fetch failed")

        headers = {k.lower(): v for k, v in response.headers.items()}
        checks = [
            ("content-security-policy", "Security Header: Content-Security-Policy"),
            ("strict-transport-security", "Security Header: Strict-Transport-Security"),
            ("x-frame-options", "Security Header: X-Frame-Options"),
        ]
        for key, name in checks:
            present = key in headers
            results.append(CheckResult(12, name, "PASS" if present else "WARN", evidence=f"{key} present={present}"))
    except Exception as exc:  # noqa: BLE001
        for name in [
            "Security Header: Content-Security-Policy",
            "Security Header: Strict-Transport-Security",
            "Security Header: X-Frame-Options",
        ]:
            results.append(CheckResult(12, name, "WARN", evidence=str(exc)))
    return results


def check_ip_reputation(url: str) -> CheckResult:
    # (13) Local IP risk classification (replaces AbuseIPDB)
    try:
        host, ip = _resolve_host(url)
        if not ip:
            return CheckResult(13, "IP Reputation & Hosting", "WARN", evidence="could not resolve host")

        addr = ipaddress.ip_address(ip)
        flags = {
            "is_private": addr.is_private,
            "is_reserved": addr.is_reserved,
            "is_loopback": addr.is_loopback,
            "is_multicast": addr.is_multicast,
            "is_global": addr.is_global,
        }
        reverse_dns = _reverse_dns(ip)

        if flags["is_global"] and not any(flags[k] for k in ["is_reserved", "is_loopback", "is_multicast"]):
            status = "PASS"
        else:
            status = "WARN"

        return CheckResult(
            13,
            "IP Reputation & Hosting",
            status,
            evidence=f"ip={ip} reverse_dns={reverse_dns or 'none'} flags={flags}",
        )
    except Exception as exc:  # noqa: BLE001
        return CheckResult(13, "IP Reputation & Hosting", "WARN", evidence=str(exc))


def check_server_geolocation(url: str) -> CheckResult:
    # (14) Geolocation inference without external IP intelligence APIs
    try:
        _, host, ext = domain_parts(url)
        _, ip = _resolve_host(url)

        tld_hint = (ext.suffix.split(".")[-1] if ext and ext.suffix else "unknown").upper()
        hint = f"tld_hint={tld_hint}"
        if ip:
            hint += f" ip={ip}"

        return CheckResult(14, "Geolocation of Server", "INFO", evidence=f"{hint} (exact geolocation unavailable without local geo DB)")
    except Exception as exc:  # noqa: BLE001
        return CheckResult(14, "Geolocation of Server", "WARN", evidence=str(exc))


def check_hosting_provider(url: str) -> CheckResult:
    # (15) Hosting provider inference from reverse DNS
    try:
        host, ip = _resolve_host(url)
        if not ip:
            return CheckResult(15, "Hosting Provider Legitimacy", "WARN", evidence="could not resolve host")

        reverse_dns = _reverse_dns(ip)
        if reverse_dns:
            status = "INFO"
            evidence = f"ip={ip} ptr={reverse_dns}"
        else:
            status = "WARN"
            evidence = f"ip={ip} ptr_lookup_failed"

        return CheckResult(15, "Hosting Provider Legitimacy", status, evidence=evidence)
    except Exception as exc:  # noqa: BLE001
        return CheckResult(15, "Hosting Provider Legitimacy", "WARN", evidence=str(exc))


def check_page_load_speed(url: str):
    # (16) Local timing-based performance check (replaces PSI/GTmetrix)
    try:
        start = time.perf_counter()
        response = requests.get(url, timeout=30, allow_redirects=True)
        total_ms = (time.perf_counter() - start) * 1000
        ttfb_ms = response.elapsed.total_seconds() * 1000 if response.elapsed else total_ms
        size_kb = len(response.content or b"") / 1024

        if ttfb_ms < 800 and total_ms < 2500 and size_kb < 1500:
            status = "PASS"
        elif ttfb_ms > 2200 or total_ms > 4500 or size_kb > 3000:
            status = "WARN"
        else:
            status = "INFO"

        evidence = (
            f"status_code={response.status_code} ttfb_ms={ttfb_ms:.1f} "
            f"total_ms={total_ms:.1f} size_kb={size_kb:.1f}"
        )
        return CheckResult(16, "Page Load Speed", status, evidence=evidence)
    except Exception as exc:  # noqa: BLE001
        return CheckResult(16, "Page Load Speed", "WARN", evidence=f"local speed check error: {exc}")


def check_mozilla_observatory(url: str) -> CheckResult:
    # (17) Local header/cookie hardening score (replaces Observatory API)
    try:
        response, _, _ = fetch(url)
        if not response:
            return CheckResult(17, "Mozilla Observatory", "WARN", evidence="page fetch failed")

        headers = {k.lower(): v for k, v in response.headers.items()}
        hardening_headers = {
            "content-security-policy": "CSP",
            "strict-transport-security": "HSTS",
            "x-frame-options": "XFO",
            "x-content-type-options": "XCTO",
            "referrer-policy": "Referrer-Policy",
            "permissions-policy": "Permissions-Policy",
        }
        present = [label for key, label in hardening_headers.items() if key in headers]

        set_cookie = (headers.get("set-cookie") or "").lower()
        cookie_flags = {
            "secure": "secure" in set_cookie,
            "httponly": "httponly" in set_cookie,
            "samesite": "samesite" in set_cookie,
        }

        score = len(present) + sum(int(v) for v in cookie_flags.values())
        if score >= 7:
            status = "PASS"
        elif score >= 4:
            status = "INFO"
        else:
            status = "WARN"

        return CheckResult(
            17,
            "Mozilla Observatory",
            status,
            evidence=f"hardening_score={score}/9 headers={present} cookie_flags={cookie_flags}",
        )
    except Exception as exc:  # noqa: BLE001
        return CheckResult(17, "Mozilla Observatory", "WARN", evidence=f"local hardening check error: {exc}")
