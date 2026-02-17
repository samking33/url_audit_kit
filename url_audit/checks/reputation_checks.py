import json
import re
from urllib.parse import urljoin, urlparse

import dns.resolver

from ..utils import CheckResult, domain_parts, fetch, mx_records, txt_records


def _domain_from_url(url: str) -> str:
    try:
        _, host, ext = domain_parts(url)
        if ext.suffix:
            return ".".join([ext.domain, ext.suffix]).strip(".")
        return host
    except Exception:
        return ""


def _origin_from_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"
    return ""


def _dmarc_present(domain: str) -> bool:
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        for record in answers:
            parts = [p.decode("utf-8") if isinstance(p, bytes) else str(p) for p in record.strings]
            txt = "".join(parts).strip().lower()
            if txt.startswith("v=dmarc1"):
                return True
    except Exception:
        return False
    return False


def check_security_blacklists(url: str):
    """(25) Local threat-reputation heuristic (replaces VirusTotal dependency)."""
    try:
        parsed, host, ext = domain_parts(url)
        domain = ".".join([ext.domain, ext.suffix]).strip(".") if ext.suffix else host
        path = (parsed.path or "").lower()

        risk_points = 0
        reasons = []

        suspicious_tokens = [
            "login",
            "verify",
            "secure",
            "account",
            "update",
            "wallet",
            "invoice",
            "gift",
            "bonus",
        ]
        if any(token in (host or "") for token in suspicious_tokens):
            risk_points += 2
            reasons.append("suspicious-host-token")

        if "xn--" in (host or ""):
            risk_points += 2
            reasons.append("punycode-domain")

        if (host or "").count("-") >= 3:
            risk_points += 1
            reasons.append("high-hyphen-count")

        if len(host or "") >= 40:
            risk_points += 1
            reasons.append("long-hostname")

        if re.search(r"\d{4,}", host or ""):
            risk_points += 1
            reasons.append("numeric-host-pattern")

        if any(marker in path for marker in ["@", "%40", "//", "..", "%2f"]):
            risk_points += 1
            reasons.append("path-obfuscation")

        if risk_points >= 4:
            status = "FAIL"
        elif risk_points >= 2:
            status = "WARN"
        else:
            status = "PASS"

        evidence = f"domain={domain or host} score={risk_points}"
        if reasons:
            evidence += f" signals={','.join(reasons)}"

        return CheckResult(25, "Security Blacklists", status, evidence=evidence)
    except Exception as exc:  # noqa: BLE001
        return CheckResult(25, "Security Blacklists", "WARN", evidence=f"heuristic error: {exc}")


def check_google_safe_browsing(url: str):
    """(25b) Local safe-browsing heuristic (replaces Google Safe Browsing API)."""
    try:
        response, html, soup = fetch(url)
        if not html or not soup:
            return CheckResult(25, "Google Safe Browsing", "WARN", evidence="page content unavailable")

        html_lower = html.lower()
        page_host = (urlparse(response.url if response else url).hostname or "").lower()

        password_inputs = len(re.findall(r'type=["\']password["\']', html_lower))
        external_post_forms = 0
        for form in soup.find_all("form"):
            action = (form.get("action") or "").strip()
            if not action:
                continue
            action_host = (urlparse(urljoin(response.url if response else url, action)).hostname or "").lower()
            if action_host and page_host and action_host != page_host:
                external_post_forms += 1

        obfuscated_js = bool(re.search(r"(eval\(|atob\(|fromcharcode\(|unescape\()", html_lower))
        forced_download = "download=" in html_lower or "application/octet-stream" in html_lower
        urgent_security_copy = bool(re.search(r"(verify your account|urgent action required|suspended)\b", html_lower))

        if password_inputs > 0 and external_post_forms > 0:
            return CheckResult(
                25,
                "Google Safe Browsing",
                "FAIL",
                evidence=f"password_inputs={password_inputs} external_forms={external_post_forms}",
            )

        signals = int(obfuscated_js) + int(forced_download) + int(urgent_security_copy)
        status = "WARN" if signals > 0 else "PASS"
        return CheckResult(
            25,
            "Google Safe Browsing",
            status,
            evidence=(
                f"obfuscated_js={obfuscated_js} forced_download={forced_download} "
                f"urgent_copy={urgent_security_copy}"
            ),
        )
    except Exception as exc:  # noqa: BLE001
        return CheckResult(25, "Google Safe Browsing", "WARN", evidence=f"heuristic error: {exc}")


def check_search_visibility(url: str):
    """(26) Local search-visibility readiness signals."""
    try:
        response, html, soup = fetch(url)
        if not response:
            return CheckResult(26, "Search Visibility", "WARN", evidence="page fetch failed")

        origin = _origin_from_url(response.url or url)
        robots_ok = False
        sitemap_ok = False

        if origin:
            robots_response, robots_text, _ = fetch(urljoin(origin, "/robots.txt"))
            if robots_response and robots_response.status_code < 400:
                robots_ok = bool(robots_text and "user-agent" in robots_text.lower())

            sitemap_response, sitemap_text, _ = fetch(urljoin(origin, "/sitemap.xml"))
            if sitemap_response and sitemap_response.status_code < 400:
                sitemap_ok = bool(sitemap_text and "<urlset" in sitemap_text.lower())

        title_present = bool(soup and soup.title and (soup.title.string or "").strip())
        canonical_present = bool(soup and soup.find("link", attrs={"rel": lambda v: v and "canonical" in str(v).lower()}))
        description_present = bool(
            soup and soup.find("meta", attrs={"name": lambda v: v and v.lower() == "description"})
        )

        score = sum(int(x) for x in [robots_ok, sitemap_ok, title_present, canonical_present, description_present])
        if score >= 4:
            status = "PASS"
        elif score >= 2:
            status = "INFO"
        else:
            status = "WARN"

        evidence = (
            f"score={score} robots={robots_ok} sitemap={sitemap_ok} "
            f"title={title_present} canonical={canonical_present} description={description_present}"
        )
        return CheckResult(26, "Search Visibility", status, evidence=evidence)
    except Exception as exc:  # noqa: BLE001
        return CheckResult(26, "Search Visibility", "WARN", evidence=f"heuristic error: {exc}")


def check_social_mentions(url: str):
    """(27) Detect first-party social profile links on the audited page."""
    try:
        response, _, soup = fetch(url)
        if not soup:
            return CheckResult(27, "Social Mentions", "WARN", evidence="page content unavailable")

        social_domains = {
            "x.com",
            "twitter.com",
            "facebook.com",
            "linkedin.com",
            "instagram.com",
            "youtube.com",
            "github.com",
            "t.me",
        }

        found = set()
        for anchor in soup.find_all("a"):
            href = (anchor.get("href") or "").strip()
            if not href:
                continue
            host = (urlparse(urljoin(response.url if response else url, href)).hostname or "").lower()
            for domain in social_domains:
                if host.endswith(domain):
                    found.add(domain)

        if found:
            return CheckResult(27, "Social Mentions", "INFO", evidence=f"profiles={','.join(sorted(found))}")
        return CheckResult(27, "Social Mentions", "WARN", evidence="no official social profile links detected")
    except Exception as exc:  # noqa: BLE001
        return CheckResult(27, "Social Mentions", "WARN", evidence=f"heuristic error: {exc}")


def check_wayback(url: str):
    """(28) Local archiveability signal (replaces Wayback API lookup)."""
    try:
        response, html, soup = fetch(url)
        if not response:
            return CheckResult(28, "Wayback Machine", "INFO", evidence="archiveability unknown (page unavailable)")

        headers = {k.lower(): v for k, v in response.headers.items()}
        x_robots = (headers.get("x-robots-tag") or "").lower()

        meta_robots = ""
        if soup:
            meta = soup.find("meta", attrs={"name": lambda v: v and v.lower() == "robots"})
            if meta:
                meta_robots = str(meta.get("content") or "").lower()

        blocked = any(token in (x_robots + " " + meta_robots) for token in ["noarchive", "nosnippet"])
        cache_control = (headers.get("cache-control") or "").lower()
        strict_cache = "no-store" in cache_control

        status = "WARN" if blocked else "INFO"
        return CheckResult(
            28,
            "Wayback Machine",
            status,
            evidence=f"archive_blocked={blocked} strict_cache={strict_cache}",
            data={"x_robots_tag": x_robots, "meta_robots": meta_robots},
        )
    except Exception as exc:  # noqa: BLE001
        return CheckResult(28, "Wayback Machine", "INFO", evidence=f"archiveability check error: {exc}")


def check_news_reviews(url: str):
    """(29) Local review/news trust cues from on-page content."""
    try:
        _, html, soup = fetch(url)
        if not html or not soup:
            return CheckResult(29, "News & Reviews", "WARN", evidence="page content unavailable")

        text = soup.get_text(" ", strip=True).lower()
        review_terms = ["review", "rating", "testimonial", "press", "newsroom", "case study"]
        review_hits = sum(1 for term in review_terms if term in text)

        schema_hits = 0
        for script in soup.find_all("script", attrs={"type": "application/ld+json"}):
            try:
                payload = json.loads(script.string or "{}")
                as_text = json.dumps(payload).lower()
                if any(token in as_text for token in ["aggregaterating", "review", "newsarticle"]):
                    schema_hits += 1
            except Exception:
                continue

        score = review_hits + schema_hits
        status = "INFO" if score > 0 else "WARN"
        return CheckResult(29, "News & Reviews", status, evidence=f"review_terms={review_hits} schema_hits={schema_hits}")
    except Exception as exc:  # noqa: BLE001
        return CheckResult(29, "News & Reviews", "WARN", evidence=f"heuristic error: {exc}")


def check_blacklists_email_filters(url: str):
    """(30) Local mail trust posture (SPF/DMARC/MX) without DNSBL providers."""
    try:
        domain = _domain_from_url(url)
        if not domain:
            return CheckResult(30, "Blacklists & Email Filters", "WARN", evidence="could not extract domain")

        txt = txt_records(domain)
        mx = mx_records(domain)
        spf = any("v=spf1" in record.lower() for record in txt)
        dmarc = _dmarc_present(domain)

        passed = int(spf) + int(dmarc) + int(bool(mx))
        status = "PASS" if passed == 3 else "WARN"
        return CheckResult(
            30,
            "Blacklists & Email Filters",
            status,
            evidence=f"spf={spf} dmarc={dmarc} mx={bool(mx)}",
            data={"mx_hosts": mx[:5]},
        )
    except Exception as exc:  # noqa: BLE001
        return CheckResult(30, "Blacklists & Email Filters", "WARN", evidence=f"heuristic error: {exc}")


def check_user_community_feedback(url: str):
    """(31) Local community-support cues (FAQ/support/contact presence)."""
    try:
        _, _, soup = fetch(url)
        if not soup:
            return CheckResult(31, "Community Feedback", "WARN", evidence="page content unavailable")

        text = soup.get_text(" ", strip=True).lower()
        cues = {
            "faq": "faq" in text,
            "support": "support" in text,
            "contact": "contact" in text,
            "forum": "forum" in text or "community" in text,
        }
        score = sum(int(v) for v in cues.values())
        status = "INFO" if score >= 2 else "WARN"
        return CheckResult(31, "Community Feedback", status, evidence=f"signals={score} cues={cues}")
    except Exception as exc:  # noqa: BLE001
        return CheckResult(31, "Community Feedback", "WARN", evidence=f"heuristic error: {exc}")


def check_business_directories(url: str):
    """(32) Local business-identity evidence (schema.org/org metadata)."""
    try:
        _, html, soup = fetch(url)
        if not html or not soup:
            return CheckResult(32, "Business Directories", "WARN", evidence="page content unavailable")

        schema_org_hits = 0
        for script in soup.find_all("script", attrs={"type": "application/ld+json"}):
            blob = (script.string or "").lower()
            if any(token in blob for token in ["organization", "localbusiness", "corporation"]):
                schema_org_hits += 1

        text = soup.get_text(" ", strip=True).lower()
        business_identifiers = ["company", "registration", "vat", "ein", "inc", "llc", "ltd"]
        identifier_hits = sum(1 for token in business_identifiers if token in text)

        score = schema_org_hits + identifier_hits
        if score >= 3:
            status = "PASS"
        elif score >= 1:
            status = "INFO"
        else:
            status = "WARN"

        return CheckResult(
            32,
            "Business Directories",
            status,
            evidence=f"schema_org_hits={schema_org_hits} identifier_hits={identifier_hits}",
        )
    except Exception as exc:  # noqa: BLE001
        return CheckResult(32, "Business Directories", "WARN", evidence=f"heuristic error: {exc}")
