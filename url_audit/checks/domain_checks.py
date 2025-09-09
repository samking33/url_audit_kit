from typing import List, Optional
from ..utils import CheckResult, domain_parts, whois_lookup
import re, requests, os
from urllib.parse import urlparse
from datetime import datetime

RDAP_ENDPOINTS = [
    "https://rdap.educause.edu/domain/{domain}",  # prefer for .edu
    "https://rdap.org/domain/{domain}",
    "https://rdap.verisign.com/com/v1/domain/{domain}",  # works for many .com
]

from datetime import datetime
from typing import Optional

def _rdap_first_date(obj: dict, keys: list) -> Optional[datetime]:
    """
    Tries common RDAP date locations/keys used by various registries.
    keys: list of candidate top-level keys (e.g., ["created", "registrationDate"])
    Also inspects events[] with known actions.
    """
    # 1) direct keys at top level
    from dateutil import parser as dtp
    if obj:
        for k in keys:
            v = obj.get(k)
            if isinstance(v, str):
                try:
                    return dtp.parse(v)
                except Exception:
                    pass
        # 2) nested events
        for ev in (obj.get("events") or []):
            act = (ev.get("eventAction") or "").lower()
            if any(a in act for a in ["registration", "registered", "domain registration", "create", "created"]) and "created" in keys:
                try:
                    return dtp.parse(ev.get("eventDate"))
                except Exception:
                    pass
            if any(a in act for a in ["expiration", "expiry", "expire", "domain expiration", "auto-renew grace"]) and "expires" in keys:
                try:
                    return dtp.parse(ev.get("eventDate"))
                except Exception:
                    pass
    return None

def _domain_only(url: str) -> str:
    p = urlparse(url)
    host = (p.hostname or "").lower()
    # fall back to tldextract if needed
    try:
        import tldextract
        ext = tldextract.extract(host)
        return ".".join([ext.domain, ext.suffix]) if ext.suffix else host
    except Exception:
        return host

def _rdap_fetch(domain: str) -> Optional[dict]:
    headers = {
        "Accept": "application/rdap+json, application/json;q=0.9",
        "User-Agent": "url-audit-kit/1.0 (+https://example)"
    }
    for tmpl in RDAP_ENDPOINTS:
        try:
            r = requests.get(
                tmpl.format(domain=domain),
                headers=headers,
                timeout=20,
                allow_redirects=True
            )
            ctype = (r.headers.get("content-type") or "").lower()
            if r.ok and (ctype.startswith("application/rdap+json") or ctype.startswith("application/json")):
                return r.json()
        except Exception:
            continue
    return None

def check_domain_legitimacy(url: str) -> CheckResult:
    # (1) Lookalike heuristic
    _, host, ext = domain_parts(url)
    suspicious = bool(re.search(r"(paypa1|faceb00k|g00gle|micr0soft|appleid|supp0rt)", host or "", re.I))
    return CheckResult(1, "Domain Name Legitimacy", "WARN" if suspicious else "PASS", evidence=f"host={host}")

def check_tld(url: str) -> CheckResult:
    # (2) High-risk TLD heuristic
    _, host, ext = domain_parts(url)
    risky = {"xyz","top","tk","gq","cf","ml"}
    status = "WARN" if ext.suffix in risky else "PASS"
    return CheckResult(2, "Top-Level Domain (TLD)", status, evidence=f"tld={ext.suffix}")

def check_whois_age(url: str) -> CheckResult:
    # (3) WHOIS age with RDAP fallback (handles .edu and others)
    _, host, ext = domain_parts(url)
    domain = ".".join([p for p in [ext.domain, ext.suffix] if p])
    w = whois_lookup(domain)
    cd = getattr(w, "creation_date", None)
    if isinstance(cd, list):
        cd = cd[0]

    # RDAP fallback if WHOIS missing/unparseable
    if not cd:
        rdap = _rdap_fetch(domain)
        try:
            from dateutil import parser as dtp
            cd = _rdap_first_date(rdap or {}, ["created", "creationDate", "registrationDate"])
        except Exception:
            cd = None

    if not cd:
        return CheckResult(3, "WHOIS and Domain Age", "WARN", evidence="WHOIS/RDAP creation date unavailable")

    try:
        from datetime import datetime, timezone
        if not getattr(cd, "tzinfo", None):
            # assume UTC if naive
            cd = cd.replace(tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - cd).days
        status = "PASS" if age_days >= 90 else "WARN"
        return CheckResult(3, "WHOIS and Domain Age", status, evidence=f"age_days={age_days}")
    except Exception:
        return CheckResult(3, "WHOIS and Domain Age", "WARN", evidence="Could not parse creation_date")

def _has_dmarc(domain: str) -> bool:
    """
    Return True if a valid DMARC TXT record exists at _dmarc.<domain>.
    Handles split TXT strings and ignores non-DMARC TXT.
    """
    import dns.resolver
    try:
        name = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(name, "TXT")
        for rr in answers:
            parts = [s.decode("utf-8") if isinstance(s, bytes) else str(s) for s in getattr(rr, "strings", [])]
            txt = "".join(parts).strip().lower()
            if txt.startswith("v=dmarc1"):
                return True
    except Exception:
        pass
    return False

def check_dns_email_records(url: str) -> List[CheckResult]:
    # (4) SPF, DMARC, MX
    from ..utils import txt_records, mx_records
    _, host, ext = domain_parts(url)
    domain = ".".join([p for p in [ext.domain, ext.suffix] if p])

    # SPF: present on root domain TXT
    txts = txt_records(domain)
    spf = any("v=spf1" in (t or "").lower() for t in txts)

    # DMARC: must exist at _dmarc.<domain> TXT and begin with v=DMARC1
    dmarc_present = _has_dmarc(domain)

    # MX
    mx = mx_records(domain)

    return [
        CheckResult(4, "DNS / Email Records - SPF", "PASS" if spf else "WARN", evidence=f"spf_present={spf}"),
        CheckResult(4, "DNS / Email Records - DMARC", "PASS" if dmarc_present else "WARN", evidence=f"dmarc_present={dmarc_present}"),
        CheckResult(4, "DNS / Email Records - MX", "PASS" if mx else "WARN", evidence=f"mx_hosts={mx}")
    ]

def check_registrar_transparency(url: str) -> CheckResult:
    # (5) Registrar details from WHOIS with RDAP fallback (.edu-friendly)
    _, host, ext = domain_parts(url)
    domain = ".".join([p for p in [ext.domain, ext.suffix] if p])
    w = whois_lookup(domain)
    registrar = getattr(w, "registrar", None)

    if not registrar:
        rdap = _rdap_fetch(domain) or {}
        try:
            # Prefer entities with role=registrar
            ents = (rdap.get("entities") or [])
            for e in ents:
                roles = [r.lower() for r in (e.get("roles") or [])]
                if "registrar" in roles:
                    v = e.get("vcardArray", [])
                    if isinstance(v, list) and len(v) >= 2 and isinstance(v[1], list):
                        for item in v[1]:
                            if item and item[0] in ("fn", "org"):
                                registrar = item[-1]
                                if registrar:
                                    break
                if registrar:
                    break
            # Fallback: some RDAPs include "port43" or custom registrarName fields
            if not registrar:
                registrar = rdap.get("port43") or rdap.get("registrarName")
        except Exception:
            pass

    status = "PASS" if registrar else "WARN"
    return CheckResult(5, "Registrar Details Transparency", status, evidence=f"registrar={registrar}")

def check_domain_expiry(url: str) -> CheckResult:
    # (6) Expiration via WHOIS with RDAP fallback
    _, host, ext = domain_parts(url)
    domain = ".".join([p for p in [ext.domain, ext.suffix] if p])
    w = whois_lookup(domain)
    ed = getattr(w, "expiration_date", None)
    if isinstance(ed, list):
        ed = ed[0]

    if not ed:
        rdap = _rdap_fetch(domain) or {}
        try:
            ed = _rdap_first_date(rdap, ["expires", "expirationDate"])
        except Exception:
            ed = None

    if not ed:
        return CheckResult(6, "Domain Expiry and Renewal", "WARN", evidence="expiration_date unavailable")

    try:
        from datetime import datetime, timezone
        if not getattr(ed, "tzinfo", None):
            ed = ed.replace(tzinfo=timezone.utc)
        days_left = (ed - datetime.now(timezone.utc)).days
        status = "WARN" if days_left < 30 else "PASS"
        return CheckResult(6, "Domain Expiry and Renewal", status, evidence=f"days_left={days_left}")
    except Exception:
        return CheckResult(6, "Domain Expiry and Renewal", "WARN", evidence="parse error")

def check_previous_ownership(url: str) -> CheckResult:
    # (7) Ownership/registrant changes via RDAP; optional DomainTools if configured
    domain = _domain_only(url)
    rdap = _rdap_fetch(domain)
    changes = 0
    if rdap:
        for ev in rdap.get("events", []) or []:
            act = (ev.get("eventAction") or "").lower()
            if any(k in act for k in ["registrant", "registrar", "ownership", "transfer", "update", "changed", "reassigned", "reregistration"]):
                changes += 1
    # Optional DomainTools (if you add creds, we try; otherwise we rely on RDAP)
    dt_key = os.getenv("DOMAINTOOLS_API_KEY")
    if dt_key:
        # Placeholder/simple attempt (exact signing varies by plan; keep lenient)
        try:
            r = requests.get(
                f"https://api.domaintools.com/v1/{domain}/whois/history",
                headers={"Authorization": f"Bearer {dt_key}"},
                timeout=15
            )
            if r.ok:
                j = r.json()
                # Count distinct historical records if present
                hist = j.get("response", {}).get("history", [])
                if isinstance(hist, list) and hist:
                    changes = max(changes, len(hist))
        except Exception:
            pass

    status = "INFO" if changes > 0 else "WARN"
    return CheckResult(7, "Previous Ownership History", status, evidence=f"change_events~={changes}", data={"rdap_events": rdap.get("events") if rdap else None})

def check_domain_transfers(url: str) -> CheckResult:
    # (8) Transfers via RDAP events
    domain = _domain_only(url)
    rdap = _rdap_fetch(domain)
    transfers = 0
    if rdap:
        for ev in rdap.get("events", []) or []:
            act = (ev.get("eventAction") or "").lower()
            if "transfer" in act or "transferred" in act:
                transfers += 1
    status = "INFO" if transfers > 0 else "PASS"
    return CheckResult(8, "Domain Transfer Records", status, evidence=f"transfer_events={transfers}", data={"rdap_events": rdap.get("events") if rdap else None})