from typing import List
from .utils import CheckResult, fetch, domain_parts
from .checks import domain_checks as dc
from .checks import security_checks as sc
from .checks import content_checks as cc
from .checks import reputation_checks as rc
from .checks import behavior_checks as bc
from .llm_analyzers import analyze_text_with_llm

def run_all(url: str) -> List[CheckResult]:
    results: List[CheckResult] = []

    # Domain & Registration
    results.append(dc.check_domain_legitimacy(url))
    results.append(dc.check_tld(url))
    results.append(dc.check_whois_age(url))
    results.extend(dc.check_dns_email_records(url))
    results.append(dc.check_registrar_transparency(url))
    results.append(dc.check_domain_expiry(url))
    results.append(dc.check_previous_ownership(url))
    results.append(dc.check_domain_transfers(url))

    # Security & Technical
    results.append(sc.check_ssl_validity(url))
    results.append(sc.check_https_presence(url))
    results.append(sc.check_certificate_issuer(url))
    results.extend(sc.check_security_headers(url))
    results.append(sc.check_ip_reputation(url))
    results.append(sc.check_server_geolocation(url))
    results.append(sc.check_hosting_provider(url))
    results.append(sc.check_page_load_speed(url))
    results.append(sc.check_mozilla_observatory(url))  # NEW

    # Content & Appearance
    results.append(cc.check_content_quality(url))
    results.append(cc.check_spelling_errors(url))
    results.append(cc.check_brand_consistency(url))
    results.append(cc.check_contact_info(url))
    results.append(cc.check_about_privacy(url))
    results.append(cc.check_too_good_offers(url))
    results.append(cc.check_logo_images(url))
    results.append(cc.check_broken_links(url))

    # External Reputation & Search
    results.append(rc.check_security_blacklists(url))   # VirusTotal
    results.append(rc.check_google_safe_browsing(url))  # NEW
    results.append(rc.check_search_visibility(url))     # SerpAPI
    results.append(rc.check_social_mentions(url))       # SerpAPI
    results.append(rc.check_wayback(url))
    results.append(rc.check_news_reviews(url))          # SerpAPI
    results.append(rc.check_blacklists_email_filters(url))
    results.append(rc.check_user_community_feedback(url))  # SerpAPI
    results.append(rc.check_business_directories(url))     # Crunchbase

    # URL Behavior & Employee Safety
    results.append(bc.check_redirects(url))
    results.append(bc.check_popups_downloads(url))
    results.append(bc.check_suspicious_requests(url))
    results.append(bc.check_url_length(url))
    results.append(bc.check_homoglyph(url))
    results.append(bc.check_email_links(url))
    results.append(bc.check_mobile_friendly(url))
    results.append(bc.check_ads_prompts(url))

    # LLM analysis (Ollama)
    resp, html, soup = fetch(url)
    text = (soup.get_text(" ") if soup else "")[:20000]
    _, host, _ = domain_parts(url)
    llm = analyze_text_with_llm(text, host or "")
    # Show either JSON summary, connection error, or which transport was used (python-client/subprocess)
    results.append(CheckResult(
        0,
        "LLM Content Analysis (Ollama)",
        "INFO" if llm.get("enabled") else "SKIP",
        evidence=llm.get("summary", llm.get("error", "")) or llm.get("_via", ""),
        data=llm
    ))

    return results

def summarize(results: List[CheckResult]):
    counts = {"PASS": 0, "WARN": 0, "FAIL": 0, "SKIP": 0, "INFO": 0}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1
    return counts