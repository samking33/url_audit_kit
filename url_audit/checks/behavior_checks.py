from ..utils import CheckResult, fetch, count_redirects
import re, requests

def check_redirects(url: str):
    # (33)
    n = count_redirects(url)
    status = "WARN" if n>2 else "PASS"
    return CheckResult(33, "Redirects and Shortened URLs", status, evidence=f"redirects={n}")

def check_popups_downloads(url: str):
    # (34)
    resp, html, soup = fetch(url)
    if not html:
        return CheckResult(34, "Pop-Ups or Forced Downloads", "WARN", evidence="No HTML")
    poplike = bool(re.search(r"(window\.open|showModal|confirm\(|prompt\()", html, re.I))
    downloady = bool(re.search(r"download=", html, re.I)) or ("application/octet-stream" in (resp.headers.get("content-type","").lower()))
    verdict = "WARN" if (poplike or downloady) else "PASS"
    return CheckResult(34, "Pop-Ups or Forced Downloads", verdict, evidence=f"popup={poplike} downloadish={downloady}")

def check_suspicious_requests(url: str):
    # (35)
    resp, html, soup = fetch(url)
    if not soup:
        return CheckResult(35, "Suspicious Login or Payment Requests", "WARN", evidence="No HTML")
    text = soup.get_text(" ").lower()
    flags = any(k in text for k in ["login","password","credit card","debit card","otp"])
    return CheckResult(35, "Suspicious Login or Payment Requests", "WARN" if flags else "PASS", evidence=f"flags={flags}")

def check_url_length(url: str):
    # (36)
    L = len(url)
    status = "WARN" if L>120 else "PASS"
    return CheckResult(36, "URL Length and Structure", status, evidence=f"length={L}")

def check_homoglyph(url: str):
    # (37)
    try:
        url.encode("ascii")
        non_ascii = False
    except Exception:
        non_ascii = True
    return CheckResult(37, "Typosquatting or Homoglyph Domains", "WARN" if non_ascii else "PASS", evidence=f"non_ascii={non_ascii}")

def check_email_links(url: str):
    # (38)
    return CheckResult(38, "Unexpected Attachments or Links in Emails", "INFO", evidence="Advise caution with unsolicited emails")

def check_mobile_friendly(url: str):
    # (39)
    resp, html, soup = fetch(url)
    if not soup:
        return CheckResult(39, "Mobile Friendliness", "WARN", evidence="No HTML")
    vp = soup.find("meta", attrs={"name":"viewport"}) or soup.find("meta", attrs={"content": re.compile("width=device-width")})
    return CheckResult(39, "Mobile Friendliness", "PASS" if vp else "WARN", evidence=f"viewport_meta_present={bool(vp)}")

def check_ads_prompts(url: str):
    # (40)
    resp, html, soup = fetch(url)
    if not html:
        return CheckResult(40, "Frequency of Unexpected Ads/Prompts", "WARN", evidence="No HTML")
    ad_patterns = ["googlesyndication.com","doubleclick.net","propellerads","onclickads","popunder"]
    found = any(p in html for p in ad_patterns)
    return CheckResult(40, "Frequency of Unexpected Ads/Prompts", "WARN" if found else "PASS", evidence=f"ad_scripts_found={found}")
