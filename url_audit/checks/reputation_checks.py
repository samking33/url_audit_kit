from ..utils import CheckResult, http_json
import os, requests, dns.resolver, time, base64
from urllib.parse import urlparse

def _domain_from_url(url: str) -> str:
    p = urlparse(url)
    host = (p.hostname or "").lower()
    try:
        import tldextract
        ext = tldextract.extract(host)
        return ".".join([ext.domain, ext.suffix]) if ext.suffix else host
    except Exception:
        return host

def check_security_blacklists(url: str):
    """
    (25) Reputation in Security Databases (VirusTotal)
    Flow:
      1) Submit URL -> get analysis_id
      2) Compute url_id = base64url(url) with '=' padding removed
      3) Poll /analyses/{analysis_id} until 'completed'
      4) Then poll /urls/{url_id} until last_analysis_stats are present
    """
    key = os.getenv("VIRUSTOTAL_API_KEY")
    if not key:
        return CheckResult(25, "Reputation in Security Databases (VirusTotal)", "SKIP", evidence="Set VIRUSTOTAL_API_KEY")

    headers = {"x-apikey": key}

    # VT url_id is base64url of the original URL, WITHOUT '=' padding
    try:
        url_id = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")
    except Exception as e:
        return CheckResult(25, "Reputation in Security Databases (VirusTotal)", "WARN", evidence=f"base64url error: {e}")

    # 1) Submit URL for analysis
    try:
        submit = requests.post("https://www.virustotal.com/api/v3/urls",
                               headers=headers, data={"url": url}, timeout=30)
        if not submit.ok:
            return CheckResult(25, "Reputation in Security Databases (VirusTotal)", "WARN",
                               evidence=f"submit {submit.status_code}: {submit.text[:160]}")
        analysis_id = (submit.json().get("data") or {}).get("id")
        if not analysis_id:
            return CheckResult(25, "Reputation in Security Databases (VirusTotal)", "WARN", evidence="no analysis id")
    except Exception as e:
        return CheckResult(25, "Reputation in Security Databases (VirusTotal)", "WARN", evidence=str(e))

    # 3) Poll analyses/{analysis_id} until completed
    analyses_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    completed = False
    last_err = None
    for _ in range(30):  # ~60–90s
        time.sleep(2)
        try:
            r = requests.get(analyses_url, headers=headers, timeout=30)
            if not r.ok:
                last_err = f"analyses {r.status_code}: {r.text[:160]}"
                continue
            status = ((r.json().get("data") or {}).get("attributes") or {}).get("status")
            if (status or "").lower() == "completed":
                completed = True
                break
            last_err = f"analysis status={status or 'unknown'}"
        except Exception as e:
            last_err = f"analyses exception: {e}"

    if not completed:
        return CheckResult(25, "Reputation in Security Databases (VirusTotal)", "WARN",
                           evidence=last_err or "analysis polling timeout")

    # 4) Poll urls/{url_id} for consolidated last_analysis_stats
    urls_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    for _ in range(30):  # another ~60–90s
        time.sleep(2)
        try:
            g = requests.get(urls_url, headers=headers, timeout=30)
            if not g.ok:
                last_err = f"urls {g.status_code}: {g.text[:160]}"
                continue
            attrs = ((g.json().get("data") or {}).get("attributes") or {})
            stats = attrs.get("last_analysis_stats")
            if stats:
                malicious = int(stats.get("malicious", 0) or 0)
                suspicious = int(stats.get("suspicious", 0) or 0)
                harmless = int(stats.get("harmless", 0) or 0)
                undetected = int(stats.get("undetected", 0) or 0)
                evidence = (f"malicious_engines={malicious} suspicious={suspicious} "
                            f"harmless={harmless} undetected={undetected}")
                status = "PASS" if malicious == 0 and suspicious == 0 else "WARN"
                return CheckResult(25, "Reputation in Security Databases (VirusTotal)", status, evidence=evidence, data=stats)
            last_err = "consolidated stats not ready"
        except Exception as e:
            last_err = f"urls exception: {e}"

    return CheckResult(25, "Reputation in Security Databases (VirusTotal)", "WARN",
                       evidence=last_err or "Timeout awaiting consolidated stats")

def check_google_safe_browsing(url: str):
    # (25b) Google Safe Browsing v4
    key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
    if not key:
        return CheckResult(25, "Google Safe Browsing", "SKIP", evidence="Set GOOGLE_SAFE_BROWSING_API_KEY")
    body = {
        "client": {"clientId": "url-audit-kit", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE","POTENTIALLY_HARMFUL_APPLICATION","THREAT_TYPE_UNSPECIFIED"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    r = requests.post(
        f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}",
        json=body, timeout=15
    )
    if not r.ok:
        return CheckResult(25, "Google Safe Browsing", "WARN", evidence=f"HTTP {r.status_code}")
    j = r.json() or {}
    matches = j.get("matches", [])
    if matches:
        return CheckResult(25, "Google Safe Browsing", "FAIL", evidence=f"matches={len(matches)}", data=matches)
    return CheckResult(25, "Google Safe Browsing", "PASS", evidence="no matches")

def check_search_visibility(url: str):
    # (26) Google via SerpAPI (optional)
    key = os.getenv("SERPAPI_API_KEY")
    if not key:
        return CheckResult(26, "Search Engine Visibility", "INFO", evidence="Set SERPAPI_API_KEY for SERP check")
    r = requests.get("https://serpapi.com/search",
                     params={"engine": "google", "q": url, "api_key": key},
                     timeout=20)
    if r.ok:
        j = r.json()
        organic = j.get("organic_results", [])
        status = "PASS" if organic else "WARN"
        return CheckResult(26, "Search Engine Visibility", status, evidence=f"organic_results={len(organic)}")
    return CheckResult(26, "Search Engine Visibility", "WARN", evidence="SERP API error")

def check_social_mentions(url: str):
    # (27) SerpAPI: social sites
    key = os.getenv("SERPAPI_API_KEY")
    if not key:
        return CheckResult(27, "Social Media/Official Mentions", "SKIP", evidence="Set SERPAPI_API_KEY")
    domain = _domain_from_url(url)
    q = f'site:twitter.com OR site:x.com OR site:facebook.com OR site:linkedin.com "{domain}"'
    r = requests.get("https://serpapi.com/search",
                     params={"engine": "google", "q": q, "api_key": key},
                     timeout=20)
    if r.ok:
        j = r.json()
        organic = j.get("organic_results", [])
        return CheckResult(27, "Social Media/Official Mentions", "INFO", evidence=f"hits={len(organic)}")
    return CheckResult(27, "Social Media/Official Mentions", "WARN", evidence="SERP API error")

def check_wayback(url: str):
    # (28) Wayback Machine presence
    data = http_json("http://archive.org/wayback/available", params={"url": url})
    if not data:
        return CheckResult(28, "Historical Records (Wayback)", "WARN", evidence="API error/unavailable")
    archived = bool(data.get("archived_snapshots", {}).get("closest"))
    return CheckResult(28, "Historical Records (Wayback)", "INFO", evidence=f"archived={archived}", data=data)

def check_news_reviews(url: str):
    # (29) Google News via SerpAPI (optional)
    key = os.getenv("SERPAPI_API_KEY")
    if not key:
        return CheckResult(29, "News/Reviews about Domain", "SKIP", evidence="Set SERPAPI_API_KEY")
    domain = _domain_from_url(url)
    q = f'{domain} reviews OR scam OR fraud OR rating'
    r = requests.get("https://serpapi.com/search",
                     params={"engine": "google_news", "q": q, "api_key": key},
                     timeout=20)
    if r.ok:
        items = r.json().get("news_results", [])
        return CheckResult(29, "News/Reviews about Domain", "INFO", evidence=f"news_results={len(items)}")
    return CheckResult(29, "News/Reviews about Domain", "WARN", evidence="SERP API error")

def _dns_query(name: str) -> bool:
    try:
        dns.resolver.resolve(name, "A")
        return True
    except Exception:
        return False

def check_blacklists_email_filters(url: str):
    # (30) Spamhaus DBL + SURBL via DNS (no API key required)
    domain = _domain_from_url(url)
    # Spamhaus DBL lookup: query domain.dbl.spamhaus.org; any A response => listed
    s_listed = _dns_query(f"{domain}.dbl.spamhaus.org")
    # SURBL lookup: query domain.multi.surbl.org; A response => listed
    u_listed = _dns_query(f"{domain}.multi.surbl.org")

    evidence = f"spamhaus_dbl={s_listed} surbl={u_listed}"
    if s_listed or u_listed:
        return CheckResult(30, "Blacklist Status in Email/URL Filters", "FAIL", evidence=evidence)
    return CheckResult(30, "Blacklist Status in Email/URL Filters", "PASS", evidence=evidence)

def check_user_community_feedback(url: str):
    # (31) Forums via SerpAPI (optional)
    key = os.getenv("SERPAPI_API_KEY")
    if not key:
        return CheckResult(31, "User Community Feedback", "SKIP", evidence="Set SERPAPI_API_KEY")
    domain = _domain_from_url(url)
    q = f'site:reddit.com OR site:stackexchange.com OR site:quora.com "{domain}"'
    r = requests.get("https://serpapi.com/search",
                     params={"engine": "google", "q": q, "api_key": key},
                     timeout=20)
    if r.ok:
        organic = r.json().get("organic_results", [])
        return CheckResult(31, "User Community Feedback", "INFO", evidence=f"threads_found={len(organic)}")
    return CheckResult(31, "User Community Feedback", "WARN", evidence="SERP API error")

def check_business_directories(url: str):
    # (32) Crunchbase v4 (optional)
    key = os.getenv("CRUNCHBASE_API_KEY")
    if not key:
        return CheckResult(32, "Presence on Business Directories (Crunchbase)", "SKIP", evidence="Set CRUNCHBASE_API_KEY")
    domain = _domain_from_url(url)
    try:
        payload = {
            "field_ids": ["identifier", "website", "num_employees_enum", "founded_on"],
            "query": [
                {"type": "predicate", "field_id": "website", "operator_id": "contains", "values": [domain]}
            ],
            "limit": 1
        }
        r = requests.post("https://api.crunchbase.com/api/v4/searches/organizations",
                          headers={"X-Cb-User-Key": key, "Content-Type":"application/json"},
                          json=payload, timeout=20)
        if not r.ok:
            return CheckResult(32, "Presence on Business Directories (Crunchbase)", "WARN", evidence=f"HTTP {r.status_code}")
        data = r.json() or {}
        count = len(data.get("entities", []) or [])
        status = "PASS" if count > 0 else "WARN"
        return CheckResult(32, "Presence on Business Directories (Crunchbase)", status, evidence=f"entities={count}", data=data)
    except Exception as e:
        return CheckResult(32, "Presence on Business Directories (Crunchbase)", "WARN", evidence=str(e))