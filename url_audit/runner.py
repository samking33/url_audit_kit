from typing import Callable, Iterable, List, Optional, Sequence, Tuple, Union

from .checks import behavior_checks as bc
from .checks import content_checks as cc
from .checks import domain_checks as dc
from .checks import llm_checks as lc
from .checks import reputation_checks as rc
from .checks import security_checks as sc
from .utils import CheckResult, resolve_audit_target

StepReturn = Union[CheckResult, Sequence[CheckResult], None]
StepFunc = Callable[[str], StepReturn]
Step = Tuple[str, StepFunc]

VALID_STATUSES = {"PASS", "WARN", "FAIL", "INFO"}


CHECK_STEPS: List[Step] = [
    ("Domain Name Legitimacy", dc.check_domain_legitimacy),
    ("Top-Level Domain (TLD)", dc.check_tld),
    ("WHOIS and Domain Age", dc.check_whois_age),
    ("DNS / Email Records", dc.check_dns_email_records),
    ("Registrar Details Transparency", dc.check_registrar_transparency),
    ("Domain Expiry", dc.check_domain_expiry),
    ("Previous Domain Ownership", dc.check_previous_ownership),
    ("Domain Transfer History", dc.check_domain_transfers),
    ("SSL Validity", sc.check_ssl_validity),
    ("HTTPS Presence", sc.check_https_presence),
    ("Certificate Issuer", sc.check_certificate_issuer),
    ("Security Headers", sc.check_security_headers),
    ("IP Reputation", sc.check_ip_reputation),
    ("Server Geolocation", sc.check_server_geolocation),
    ("Hosting Provider", sc.check_hosting_provider),
    ("Page Load Speed", sc.check_page_load_speed),
    ("Mozilla Observatory", sc.check_mozilla_observatory),
    ("Content Quality", cc.check_content_quality),
    ("Spelling Errors", cc.check_spelling_errors),
    ("Brand Consistency", cc.check_brand_consistency),
    ("Contact Information", cc.check_contact_info),
    ("About / Privacy", cc.check_about_privacy),
    ("Too-Good Offers", cc.check_too_good_offers),
    ("Logos & Images", cc.check_logo_images),
    ("Broken Links", cc.check_broken_links),
    ("Security Blacklists", rc.check_security_blacklists),
    ("Google Safe Browsing", rc.check_google_safe_browsing),
    ("Search Visibility", rc.check_search_visibility),
    ("Social Mentions", rc.check_social_mentions),
    ("Wayback Machine", rc.check_wayback),
    ("News & Reviews", rc.check_news_reviews),
    ("Blacklists & Email Filters", rc.check_blacklists_email_filters),
    ("Community Feedback", rc.check_user_community_feedback),
    ("Business Directories", rc.check_business_directories),
    ("Redirect Behaviour", bc.check_redirects),
    ("Popups & Downloads", bc.check_popups_downloads),
    ("Suspicious Requests", bc.check_suspicious_requests),
    ("URL Length", bc.check_url_length),
    ("Homoglyph Detection", bc.check_homoglyph),
    ("Email Links", bc.check_email_links),
    ("Mobile Friendliness", bc.check_mobile_friendly),
    ("Ads & Prompts", bc.check_ads_prompts),
    ("AI Content Analysis", lc.check_llm_content_analysis),
]


def total_steps() -> int:
    return len(CHECK_STEPS)


ProgressCallback = Callable[[int, int, str, List[CheckResult]], None]


def _ensure_list(value: StepReturn) -> List[CheckResult]:
    if value is None:
        return []
    if isinstance(value, CheckResult):
        return [value]
    if isinstance(value, Iterable):
        return [item for item in value if isinstance(item, CheckResult)]
    return []


def _normalize_result_status(result: CheckResult) -> CheckResult:
    status = (result.status or "").upper()
    if status in VALID_STATUSES:
        result.status = status
        return result

    evidence = (result.evidence or "").strip()
    if status == "SKIP":
        result.status = "WARN"
        result.evidence = f"{evidence} | converted_from_skip" if evidence else "converted_from_skip"
        return result

    result.status = "WARN"
    result.evidence = f"{evidence} | normalized_status={status}" if evidence else f"normalized_status={status}"
    return result


def _fallback_result(label: str, index: int, reason: str) -> CheckResult:
    return CheckResult(
        1000 + index,
        label,
        "FAIL",
        evidence=reason,
        data={"error": reason},
    )


def _run_step(url: str, step: Step, index: int) -> List[CheckResult]:
    label, func = step
    try:
        step_results = _ensure_list(func(url))
        if not step_results:
            return [_fallback_result(label, index, "check returned no results")]
        return [_normalize_result_status(result) for result in step_results]
    except Exception as exc:  # noqa: BLE001
        return [_fallback_result(label, index, f"check crashed: {type(exc).__name__}: {exc}")]


def run_all_with_context(
    url: str,
    progress_callback: Optional[ProgressCallback] = None,
) -> Tuple[List[CheckResult], dict]:
    target = resolve_audit_target(url)
    audit_url = target.get("resolved_url") or target.get("normalized_url") or (url or "").strip()

    results: List[CheckResult] = []
    steps = total_steps()

    for index, step in enumerate(CHECK_STEPS, start=1):
        step_results = _run_step(audit_url, step, index)
        if not step_results:
            # Defensive invariant guard.
            step_results = [_fallback_result(step[0], index, "invariant breach: no check result")]

        results.extend(step_results)

        if progress_callback:
            label = step_results[0].name if step_results else step[0]
            progress_callback(index, steps, label, step_results)

    return results, target


def run_all(url: str, progress_callback: Optional[ProgressCallback] = None) -> List[CheckResult]:
    results, _ = run_all_with_context(url, progress_callback)
    return results


def summarize(results: List[CheckResult]):
    counts = {"PASS": 0, "WARN": 0, "FAIL": 0, "INFO": 0}
    for result in results:
        status = (result.status or "").upper()
        if status not in counts:
            status = "WARN"
        counts[status] += 1
    return counts
