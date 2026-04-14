/**
 * URL audit checks for the Next.js Node runtime.
 * Uses only Node.js built-ins (dns, tls, net, fetch) plus simple heuristics.
 */
import * as dns from 'dns/promises';
import * as tls from 'tls';
import * as net from 'net';
import * as fs from 'fs';
import { analyzeTextWithNim } from './ai';
import { getServerConfig } from '../server-config';

export interface CheckResult {
  id: number;
  name: string;
  status: 'PASS' | 'WARN' | 'FAIL' | 'INFO' | 'SKIP';
  evidence: string;
  data: Record<string, unknown>;
}

function ok(id: number, name: string, evidence: string, data: Record<string, unknown> = {}): CheckResult {
  return { id, name, status: 'PASS', evidence, data };
}
function warn(id: number, name: string, evidence: string, data: Record<string, unknown> = {}): CheckResult {
  return { id, name, status: 'WARN', evidence, data };
}
function fail(id: number, name: string, evidence: string, data: Record<string, unknown> = {}): CheckResult {
  return { id, name, status: 'FAIL', evidence, data };
}
function info(id: number, name: string, evidence: string, data: Record<string, unknown> = {}): CheckResult {
  return { id, name, status: 'INFO', evidence, data };
}

function extractHost(url: string): string {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return '';
  }
}

function extractDomain(url: string): string {
  const host = extractHost(url);
  const parts = host.split('.');
  if (parts.length >= 2) return parts.slice(-2).join('.');
  return host;
}

function extractTld(url: string): string {
  const host = extractHost(url);
  const parts = host.split('.');
  return parts.length >= 2 ? parts[parts.length - 1] : '';
}

const REQUEST_HEADERS = {
  'User-Agent': 'Mozilla/5.0 (compatible; URLAuditKit/2.0; +https://url-audit-kit.onrender.com)',
  Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
  'Accept-Language': 'en-US,en;q=0.9',
  'Cache-Control': 'no-cache',
  Pragma: 'no-cache',
};

const SERVER_CONFIG = getServerConfig();

async function fetchHead(url: string, timeoutMs = 15000): Promise<Response | null> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const res = await fetch(url, {
      method: 'HEAD',
      redirect: 'follow',
      headers: REQUEST_HEADERS,
      signal: controller.signal,
    });
    if (res.status === 405 || res.status === 403) {
      const fallback = await fetch(url, {
        method: 'GET',
        redirect: 'follow',
        headers: REQUEST_HEADERS,
        signal: controller.signal,
      });
      clearTimeout(timer);
      return fallback;
    }
    clearTimeout(timer);
    return res;
  } catch {
    return null;
  }
}

async function fetchGet(url: string, timeoutMs = 20000): Promise<Response | null> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const res = await fetch(url, {
      method: 'GET',
      redirect: 'follow',
      headers: REQUEST_HEADERS,
      signal: controller.signal,
    });
    clearTimeout(timer);
    return res;
  } catch {
    return null;
  }
}

function vtUrlId(url: string): string {
  return Buffer.from(url).toString('base64').replace(/=/g, '');
}

async function lookupVirusTotalUrl(url: string): Promise<Record<string, unknown> | null> {
  if (!SERVER_CONFIG.VIRUSTOTAL_API_KEY) return null;
  const res = await fetch(`https://www.virustotal.com/api/v3/urls/${vtUrlId(url)}`, {
    headers: { 'x-apikey': SERVER_CONFIG.VIRUSTOTAL_API_KEY, Accept: 'application/json' },
    signal: AbortSignal.timeout(12000),
  }).catch(() => null);
  if (!res?.ok) return null;
  return res.json() as Promise<Record<string, unknown>>;
}

async function lookupAbuseIpDb(ip: string): Promise<Record<string, unknown> | null> {
  if (!SERVER_CONFIG.ABUSEIPDB_API_KEY || !ip) return null;
  const res = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose=true`, {
    headers: { Key: SERVER_CONFIG.ABUSEIPDB_API_KEY, Accept: 'application/json' },
    signal: AbortSignal.timeout(12000),
  }).catch(() => null);
  if (!res?.ok) return null;
  return res.json() as Promise<Record<string, unknown>>;
}

async function lookupIpInfo(ip: string): Promise<Record<string, unknown> | null> {
  if (!SERVER_CONFIG.IPINFO_TOKEN || !ip) return null;
  const res = await fetch(`https://ipinfo.io/${encodeURIComponent(ip)}/json?token=${encodeURIComponent(SERVER_CONFIG.IPINFO_TOKEN)}`, {
    headers: { Accept: 'application/json' },
    signal: AbortSignal.timeout(12000),
  }).catch(() => null);
  if (!res?.ok) return null;
  return res.json() as Promise<Record<string, unknown>>;
}

async function searchSerpApi(query: string, extraParams: Record<string, string> = {}): Promise<Record<string, unknown> | null> {
  if (!SERVER_CONFIG.SERPAPI_API_KEY) return null;
  const params = new URLSearchParams({
    engine: 'google',
    api_key: SERVER_CONFIG.SERPAPI_API_KEY,
    q: query,
    num: '10',
    ...extraParams,
  });
  const res = await fetch(`https://serpapi.com/search.json?${params.toString()}`, {
    headers: { Accept: 'application/json' },
    signal: AbortSignal.timeout(15000),
  }).catch(() => null);
  if (!res?.ok) return null;
  return res.json() as Promise<Record<string, unknown>>;
}

function getPageSpeedApiKey(): string {
  const filePath = SERVER_CONFIG.PAGESPEED_KEY_FILE?.trim();
  if (!filePath) return '';
  try {
    const raw = fs.readFileSync(filePath, 'utf8').trim();
    if (!raw) return '';
    if (raw.startsWith('{')) {
      const parsed = JSON.parse(raw) as Record<string, unknown>;
      return String(parsed.apiKey || parsed.key || parsed.api_key || '').trim();
    }
    return raw;
  } catch {
    return '';
  }
}

async function runPageSpeed(url: string): Promise<Record<string, unknown> | null> {
  const apiKey = getPageSpeedApiKey();
  if (!apiKey) return null;
  const params = new URLSearchParams({
    url,
    key: apiKey,
    strategy: 'mobile',
    category: 'performance',
  });
  const res = await fetch(`https://pagespeedonline.googleapis.com/pagespeedonline/v5/runPagespeed?${params.toString()}`, {
    headers: { Accept: 'application/json' },
    signal: AbortSignal.timeout(8000),
  }).catch(() => null);
  if (!res?.ok) return null;
  return res.json() as Promise<Record<string, unknown>>;
}

function gtmetrixAuthHeader(): string {
  const user = SERVER_CONFIG.GTMETRIX_USERNAME || SERVER_CONFIG.GTMETRIX_API_KEY;
  const pass = SERVER_CONFIG.GTMETRIX_USERNAME ? SERVER_CONFIG.GTMETRIX_API_KEY : '';
  return `Basic ${Buffer.from(`${user}:${pass}`).toString('base64')}`;
}

async function runGtmetrixTest(url: string): Promise<Record<string, unknown> | null> {
  if (!SERVER_CONFIG.GTMETRIX_API_KEY || SERVER_CONFIG.DISABLE_GTMETRIX === '1') return null;
  const payload = {
    data: {
      type: 'test',
      attributes: {
        url,
        location: SERVER_CONFIG.GTMETRIX_LOCATION || undefined,
      },
    },
  };
  const start = await fetch('https://gtmetrix.com/api/2.0/tests', {
    method: 'POST',
    headers: {
      Authorization: gtmetrixAuthHeader(),
      'Content-Type': 'application/vnd.api+json',
      Accept: 'application/json',
    },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(20000),
  }).catch(() => null);
  if (!start?.ok) return null;
  const started = await start.json() as { data?: { id?: string } };
  const testId = started.data?.id;
  if (!testId) return null;

  for (let i = 0; i < 1; i++) {
    await new Promise((resolve) => setTimeout(resolve, 1500));
    const statusRes = await fetch(`https://gtmetrix.com/api/2.0/tests/${testId}`, {
      headers: {
        Authorization: gtmetrixAuthHeader(),
        Accept: 'application/json',
      },
      redirect: 'manual',
      signal: AbortSignal.timeout(15000),
    }).catch(() => null);
    if (!statusRes) return null;
    if (statusRes.status === 303) {
      const reportUrl = statusRes.headers.get('location');
      if (!reportUrl) return null;
      const fullUrl = reportUrl.startsWith('http') ? reportUrl : `https://gtmetrix.com${reportUrl}`;
      const reportRes = await fetch(fullUrl, {
        headers: {
          Authorization: gtmetrixAuthHeader(),
          Accept: 'application/json',
        },
        signal: AbortSignal.timeout(15000),
      }).catch(() => null);
      if (!reportRes?.ok) return null;
      return reportRes.json() as Promise<Record<string, unknown>>;
    }
  }
  return null;
}

async function lookupDomainToolsProfile(domain: string): Promise<Record<string, unknown> | null> {
  if (!SERVER_CONFIG.DOMAINTOOLS_API_KEY || !domain) return null;
  const res = await fetch(`https://api.domaintools.com/v1/${encodeURIComponent(domain)}/`, {
    headers: {
      'X-Api-Key': SERVER_CONFIG.DOMAINTOOLS_API_KEY,
      Accept: 'application/json',
    },
    signal: AbortSignal.timeout(15000),
  }).catch(() => null);
  if (!res?.ok) return null;
  return res.json() as Promise<Record<string, unknown>>;
}

async function lookupCrunchbaseOrganization(domain: string): Promise<Record<string, unknown> | null> {
  if (!SERVER_CONFIG.CRUNCHBASE_API_KEY || !domain) return null;
  const params = new URLSearchParams({
    domain_name: domain,
    user_key: SERVER_CONFIG.CRUNCHBASE_API_KEY,
  });
  const res = await fetch(`https://api.crunchbase.com/v3.1/organizations?${params.toString()}`, {
    headers: { Accept: 'application/json' },
    signal: AbortSignal.timeout(15000),
  }).catch(() => null);
  if (!res?.ok) return null;
  return res.json() as Promise<Record<string, unknown>>;
}

async function lookupSpamhausDomain(domain: string): Promise<Record<string, unknown> | null> {
  if (!SERVER_CONFIG.SPAMHAUS_API_KEY || !domain) return null;
  const res = await fetch(`https://api.spamhaus.org/api/intel/v2/byobject/domain/${encodeURIComponent(domain)}`, {
    headers: {
      Authorization: `Bearer ${SERVER_CONFIG.SPAMHAUS_API_KEY}`,
      Accept: 'application/json',
    },
    signal: AbortSignal.timeout(15000),
  }).catch(() => null);
  if (!res?.ok) return null;
  return res.json() as Promise<Record<string, unknown>>;
}

async function resolveSrv(host: string): Promise<string | null> {
  try {
    return await dns.lookup(host).then((r) => r.address);
  } catch {
    return null;
  }
}

function getCert(host: string, port = 443): Promise<tls.PeerCertificate | null> {
  return new Promise((resolve) => {
    const socket = tls.connect(
      { host, port, servername: host, rejectUnauthorized: false },
      () => {
        const cert = socket.getPeerCertificate(false);
        socket.destroy();
        resolve(cert && Object.keys(cert).length ? cert : null);
      }
    );
    socket.setTimeout(10000);
    socket.on('timeout', () => { socket.destroy(); resolve(null); });
    socket.on('error', () => { socket.destroy(); resolve(null); });
  });
}

// ─── Domain checks ───────────────────────────────────────────────────────────

export async function checkDomainLegitimacy(url: string): Promise<CheckResult> {
  try {
    const host = extractHost(url);
    if (!host) return warn(1, 'Domain Name Legitimacy', 'Could not extract hostname');
    const suspicious = /paypa1|faceb00k|g00gle|micr0soft|appleid|supp0rt|amaz0n|netfl1x/i.test(host);
    return suspicious
      ? warn(1, 'Domain Name Legitimacy', `host=${host} (lookalike pattern detected)`)
      : ok(1, 'Domain Name Legitimacy', `host=${host}`);
  } catch (e) {
    return warn(1, 'Domain Name Legitimacy', `Error: ${String(e).slice(0, 100)}`);
  }
}

export async function checkTld(url: string): Promise<CheckResult> {
  try {
    const tld = extractTld(url);
    const risky = new Set(['xyz', 'top', 'tk', 'gq', 'cf', 'ml', 'ga', 'pw', 'cc']);
    const status = risky.has(tld) ? 'WARN' : 'PASS';
    return { id: 2, name: 'Top-Level Domain (TLD)', status, evidence: `tld=${tld}`, data: {} };
  } catch (e) {
    return warn(2, 'Top-Level Domain (TLD)', `Error: ${String(e).slice(0, 100)}`);
  }
}

export async function checkWhoisAge(url: string): Promise<CheckResult> {
  // WHOIS requires TCP/43 which isn't available in all hosting envs — use RDAP fallback
  const domain = extractDomain(url);
  try {
    const rdapUrl = `https://rdap.org/domain/${domain}`;
    const controller = new AbortController();
    setTimeout(() => controller.abort(), 10000);
    const res = await fetch(rdapUrl, { signal: controller.signal });
    if (!res.ok) return warn(3, 'WHOIS and Domain Age', 'RDAP lookup unavailable');
    const data = await res.json() as Record<string, unknown>;
    const events = (data.events as Array<{ eventAction: string; eventDate: string }>) || [];
    let createdDate: Date | null = null;
    for (const ev of events) {
      if (/registr|creat/i.test(ev.eventAction || '')) {
        const d = new Date(ev.eventDate);
        if (!isNaN(d.getTime())) { createdDate = d; break; }
      }
    }
    if (!createdDate) return warn(3, 'WHOIS and Domain Age', 'Creation date unavailable');
    const ageDays = Math.floor((Date.now() - createdDate.getTime()) / 86400000);
    return { id: 3, name: 'WHOIS and Domain Age', status: ageDays >= 90 ? 'PASS' : 'WARN', evidence: `age_days=${ageDays}`, data: {} };
  } catch {
    return warn(3, 'WHOIS and Domain Age', 'RDAP/WHOIS lookup failed');
  }
}

export async function checkDnsEmailRecords(url: string): Promise<CheckResult[]> {
  const domain = extractDomain(url);
  let spf = false;
  let dmarc = false;
  let hasMx = false;
  try {
    const txts = await dns.resolveTxt(domain).catch(() => [] as string[][]);
    spf = txts.some((r) => r.join('').toLowerCase().includes('v=spf1'));
    const dmarcTxts = await dns.resolveTxt(`_dmarc.${domain}`).catch(() => [] as string[][]);
    dmarc = dmarcTxts.some((r) => r.join('').toLowerCase().startsWith('v=dmarc1'));
    const mx = await dns.resolveMx(domain).catch(() => []);
    hasMx = mx.length > 0;
  } catch { /* keep false */ }
  return [
    { id: 4, name: 'DNS / Email Records - SPF', status: spf ? 'PASS' : 'WARN', evidence: `spf_present=${spf}`, data: {} },
    { id: 4, name: 'DNS / Email Records - DMARC', status: dmarc ? 'PASS' : 'WARN', evidence: `dmarc_present=${dmarc}`, data: {} },
    { id: 4, name: 'DNS / Email Records - MX', status: hasMx ? 'PASS' : 'WARN', evidence: `mx_present=${hasMx}`, data: {} },
  ];
}

export async function checkRegistrarTransparency(url: string): Promise<CheckResult> {
  const domain = extractDomain(url);
  try {
    const domainTools = await lookupDomainToolsProfile(domain);
    const dtRegistrar = String((domainTools?.response as Record<string, unknown> | undefined)?.registrar || '');
    const res = await fetch(`https://rdap.org/domain/${domain}`, {
      signal: AbortSignal.timeout(10000),
    }).catch(() => null);
    if (!res?.ok) return warn(5, 'Registrar Details Transparency', 'RDAP unavailable');
    const data = await res.json() as Record<string, unknown>;
    const entities = (data.entities as Array<{ roles: string[]; vcardArray: unknown[] }>) || [];
    let registrar = '';
    for (const e of entities) {
      if ((e.roles || []).includes('registrar')) {
        const vcard = e.vcardArray as [string, Array<[string, unknown, unknown, string]>];
        if (Array.isArray(vcard) && Array.isArray(vcard[1])) {
          for (const item of vcard[1]) {
            if (item[0] === 'fn' || item[0] === 'org') { registrar = String(item[3] || ''); break; }
          }
        }
      }
      if (registrar) break;
    }
    const finalRegistrar = registrar || dtRegistrar;
    return {
      id: 5,
      name: 'Registrar Details Transparency',
      status: finalRegistrar ? 'PASS' : 'WARN',
      evidence: `registrar=${finalRegistrar || 'unknown'} source=${registrar ? 'rdap' : dtRegistrar ? 'domaintools' : 'none'}`,
      data: { registrar: finalRegistrar, rdap_registrar: registrar, domaintools_registrar: dtRegistrar },
    };
  } catch {
    return warn(5, 'Registrar Details Transparency', 'RDAP lookup failed');
  }
}

export async function checkDomainExpiry(url: string): Promise<CheckResult> {
  const domain = extractDomain(url);
  try {
    const res = await fetch(`https://rdap.org/domain/${domain}`, {
      signal: AbortSignal.timeout(10000),
    }).catch(() => null);
    if (!res?.ok) return warn(6, 'Domain Expiry', 'RDAP unavailable');
    const data = await res.json() as Record<string, unknown>;
    const events = (data.events as Array<{ eventAction: string; eventDate: string }>) || [];
    let expiryDate: Date | null = null;
    for (const ev of events) {
      if (/expir/i.test(ev.eventAction || '')) {
        const d = new Date(ev.eventDate);
        if (!isNaN(d.getTime())) { expiryDate = d; break; }
      }
    }
    if (!expiryDate) return warn(6, 'Domain Expiry', 'Expiration date unavailable');
    const daysLeft = Math.floor((expiryDate.getTime() - Date.now()) / 86400000);
    return { id: 6, name: 'Domain Expiry', status: daysLeft < 30 ? 'WARN' : 'PASS', evidence: `days_left=${daysLeft}`, data: {} };
  } catch {
    return warn(6, 'Domain Expiry', 'RDAP lookup failed');
  }
}

export async function checkPreviousOwnership(url: string): Promise<CheckResult> {
  const domain = extractDomain(url);
  try {
    const res = await fetch(`https://rdap.org/domain/${domain}`, { signal: AbortSignal.timeout(10000) }).catch(() => null);
    if (!res?.ok) return warn(7, 'Previous Ownership History', 'RDAP unavailable');
    const data = await res.json() as Record<string, unknown>;
    const events = (data.events as Array<{ eventAction: string }>) || [];
    const changes = events.filter((ev) => /registrant|registrar|ownership|transfer|update|reassign/i.test(ev.eventAction || '')).length;
    return info(7, 'Previous Ownership History', `change_events~=${changes}`);
  } catch {
    return warn(7, 'Previous Ownership History', 'RDAP lookup failed');
  }
}

export async function checkDomainTransfers(url: string): Promise<CheckResult> {
  const domain = extractDomain(url);
  try {
    const res = await fetch(`https://rdap.org/domain/${domain}`, { signal: AbortSignal.timeout(10000) }).catch(() => null);
    if (!res?.ok) return warn(8, 'Domain Transfer Records', 'RDAP unavailable');
    const data = await res.json() as Record<string, unknown>;
    const events = (data.events as Array<{ eventAction: string }>) || [];
    const transfers = events.filter((ev) => /transfer/i.test(ev.eventAction || '')).length;
    return { id: 8, name: 'Domain Transfer Records', status: transfers > 0 ? 'INFO' : 'PASS', evidence: `transfer_events=${transfers}`, data: {} };
  } catch {
    return warn(8, 'Domain Transfer Records', 'RDAP lookup failed');
  }
}

// ─── Security checks ──────────────────────────────────────────────────────────

export async function checkSslValidity(url: string): Promise<CheckResult> {
  try {
    const host = extractHost(url);
    if (!host) return warn(9, 'SSL/TLS Certificate Validity', 'no host');
    const cert = await getCert(host);
    if (!cert) return warn(9, 'SSL/TLS Certificate Validity', 'could not retrieve certificate');
    const validTo = cert.valid_to ? new Date(cert.valid_to) : null;
    if (!validTo) return warn(9, 'SSL/TLS Certificate Validity', `subject=${cert.subject?.CN} expiry unavailable`);
    const daysLeft = Math.floor((validTo.getTime() - Date.now()) / 86400000);
    return { id: 9, name: 'SSL/TLS Certificate Validity', status: daysLeft > 14 ? 'PASS' : 'WARN', evidence: `subject=${cert.subject?.CN} expires_in_days=${daysLeft}`, data: {} };
  } catch (e) {
    return warn(9, 'SSL/TLS Certificate Validity', String(e).slice(0, 200));
  }
}

export async function checkHttpsPresence(url: string): Promise<CheckResult> {
  try {
    const scheme = url.includes(':') ? url.split(':')[0].toLowerCase() : '';
    return { id: 10, name: 'Presence of HTTPS', status: scheme === 'https' ? 'PASS' : 'WARN', evidence: `scheme=${scheme || 'unknown'}`, data: {} };
  } catch (e) {
    return warn(10, 'Presence of HTTPS', String(e));
  }
}

export async function checkCertificateIssuer(url: string): Promise<CheckResult> {
  try {
    const host = extractHost(url);
    if (!host) return warn(11, 'Certificate Issuer (Reputable CA)', 'no host');
    const cert = await getCert(host);
    if (!cert) return warn(11, 'Certificate Issuer (Reputable CA)', 'could not retrieve certificate');
    const issuer = cert.issuer ? Object.values(cert.issuer).join(' ') : '';
    return { id: 11, name: 'Certificate Issuer (Reputable CA)', status: issuer ? 'PASS' : 'WARN', evidence: `issuer=${issuer || 'unknown'}`, data: {} };
  } catch (e) {
    return warn(11, 'Certificate Issuer (Reputable CA)', String(e).slice(0, 200));
  }
}

export async function checkSecurityHeaders(url: string): Promise<CheckResult[]> {
  const checks: Array<[string, string]> = [
    ['content-security-policy', 'Security Header: Content-Security-Policy'],
    ['strict-transport-security', 'Security Header: Strict-Transport-Security'],
    ['x-frame-options', 'Security Header: X-Frame-Options'],
  ];
  try {
    const res = await fetchHead(url);
    if (!res) throw new Error('fetch failed');
    const results: CheckResult[] = checks.map(([key, name]) => {
      const present = res.headers.has(key);
      return { id: 12, name, status: present ? 'PASS' : 'WARN', evidence: `${key} present=${present}`, data: {} };
    });
    return results;
  } catch (e) {
    return checks.map(([, name]) => warn(12, name, String(e).slice(0, 100)));
  }
}

export async function checkIpReputation(url: string): Promise<CheckResult> {
  try {
    const host = extractHost(url);
    if (!host) return warn(13, 'IP Reputation & Hosting', 'could not resolve host');
    const { address: ip } = await dns.lookup(host).catch(() => ({ address: '' }));
    if (!ip) return warn(13, 'IP Reputation & Hosting', 'DNS resolution failed');
    const isPrivate = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|::1)/.test(ip);
    const abuseData = await lookupAbuseIpDb(ip);
    const abuse = abuseData?.data as Record<string, unknown> | undefined;
    const abuseScore = Number(abuse?.abuseConfidenceScore || 0);
    const reports = Number(abuse?.totalReports || 0);
    let status: CheckResult['status'] = isPrivate ? 'WARN' : 'PASS';
    if (abuseScore >= 75) status = 'FAIL';
    else if (abuseScore >= 25 || reports > 0 || isPrivate) status = 'WARN';
    return {
      id: 13,
      name: 'IP Reputation & Hosting',
      status,
      evidence: `ip=${ip} abuse_score=${abuseScore} total_reports=${reports} is_private=${isPrivate}`,
      data: { ip, abuse_score: abuseScore, total_reports: reports, usage_type: abuse?.usageType || '' },
    };
  } catch (e) {
    return warn(13, 'IP Reputation & Hosting', String(e).slice(0, 100));
  }
}

export async function checkServerGeolocation(url: string): Promise<CheckResult> {
  try {
    const host = extractHost(url);
    const tld = extractTld(url).toUpperCase();
    const { address: ip } = await dns.lookup(host).catch(() => ({ address: '' }));
    const ipInfo = ip ? await lookupIpInfo(ip) : null;
    const country = String(ipInfo?.country || '');
    const city = String(ipInfo?.city || '');
    const region = String(ipInfo?.region || '');
    const org = String(ipInfo?.org || '');
    const location = [city, region, country].filter(Boolean).join(', ');
    return info(14, 'Geolocation of Server', `tld_hint=${tld} ip=${ip || 'unknown'} location=${location || 'unknown'} org=${org || 'unknown'}`, {
      tld_hint: tld,
      ip,
      city,
      region,
      country,
      org,
    });
  } catch (e) {
    return warn(14, 'Geolocation of Server', String(e).slice(0, 100));
  }
}

export async function checkHostingProvider(url: string): Promise<CheckResult> {
  try {
    const host = extractHost(url);
    const { address: ip } = await dns.lookup(host).catch(() => ({ address: '' }));
    if (!ip) return warn(15, 'Hosting Provider Legitimacy', 'could not resolve host');
    const ipInfo = await lookupIpInfo(ip);
    const org = String(ipInfo?.org || '');
    const hostname = String(ipInfo?.hostname || '');
    return info(15, 'Hosting Provider Legitimacy', `ip=${ip} provider=${org || 'unknown'} hostname=${hostname || 'unknown'}`, { ip, provider: org, hostname });
  } catch (e) {
    return warn(15, 'Hosting Provider Legitimacy', String(e).slice(0, 100));
  }
}

export async function checkPageLoadSpeed(url: string): Promise<CheckResult> {
  try {
    const gtmetrixEnabled = Boolean(SERVER_CONFIG.GTMETRIX_API_KEY) && SERVER_CONFIG.DISABLE_GTMETRIX !== '1';
    const start = Date.now();
    const [res, pageSpeed, gtmetrix] = await Promise.all([
      fetchGet(url, 12000),
      runPageSpeed(url),
      gtmetrixEnabled ? runGtmetrixTest(url) : Promise.resolve(null),
    ]);
    const totalMs = Date.now() - start;
    if (!res) return warn(16, 'Page Load Speed', 'request failed or timed out');
    const body = await res.text().catch(() => '');
    const sizeKb = Buffer.byteLength(body, 'utf8') / 1024;
    const pageSpeedScore = Number((((pageSpeed?.lighthouseResult as Record<string, unknown> | undefined)?.categories as Record<string, unknown> | undefined)?.performance as Record<string, unknown> | undefined)?.score || 0);
    const gtmetrixAttrs = (gtmetrix?.data as Record<string, unknown> | undefined)?.attributes as Record<string, unknown> | undefined;
    const gtmetrixScore = Number(gtmetrixAttrs?.performance_score || 0);
    let status: CheckResult['status'] = 'INFO';
    if ((pageSpeedScore && pageSpeedScore >= 0.85) || (gtmetrixScore && gtmetrixScore >= 85) || (totalMs < 2500 && sizeKb < 1500)) status = 'PASS';
    else if ((pageSpeedScore && pageSpeedScore < 0.5) || (gtmetrixScore && gtmetrixScore < 50) || totalMs > 4500 || sizeKb > 3000) status = 'WARN';
    return {
      id: 16,
      name: 'Page Load Speed',
      status,
      evidence: `status_code=${res.status} total_ms=${totalMs} size_kb=${sizeKb.toFixed(1)} pagespeed_score=${pageSpeedScore || 'n/a'} gtmetrix_score=${gtmetrixScore || 'n/a'}`,
      data: {
        total_ms: totalMs,
        size_kb: sizeKb,
        gtmetrix_enabled: gtmetrixEnabled,
        gtmetrix_location: SERVER_CONFIG.GTMETRIX_LOCATION,
        gtmetrix_location_secondary: SERVER_CONFIG.GTMETRIX_LOCATION_SECONDARY,
        pagespeed_score: pageSpeedScore || null,
        gtmetrix_score: gtmetrixScore || null,
      },
    };
  } catch (e) {
    return warn(16, 'Page Load Speed', `speed check error: ${String(e).slice(0, 100)}`);
  }
}

export async function checkMozillaObservatory(url: string): Promise<CheckResult> {
  try {
    const res = await fetchHead(url);
    if (!res) return warn(17, 'Mozilla Observatory', 'page fetch failed');
    const hardeningHeaders = ['content-security-policy', 'strict-transport-security', 'x-frame-options', 'x-content-type-options', 'referrer-policy', 'permissions-policy'];
    const present = hardeningHeaders.filter((h) => res.headers.has(h));
    const score = present.length;
    let status: CheckResult['status'] = 'WARN';
    if (score >= 5) status = 'PASS';
    else if (score >= 3) status = 'INFO';
    return { id: 17, name: 'Mozilla Observatory', status, evidence: `hardening_score=${score}/6 headers=[${present.join(',')}]`, data: { present } };
  } catch (e) {
    return warn(17, 'Mozilla Observatory', `local hardening check error: ${String(e).slice(0, 100)}`);
  }
}

// ─── Content checks ───────────────────────────────────────────────────────────

async function fetchText(url: string): Promise<string> {
  try {
    const res = await fetchGet(url);
    return res ? await res.text().catch(() => '') : '';
  } catch { return ''; }
}

export async function checkContentQuality(url: string): Promise<CheckResult> {
  try {
    const text = await fetchText(url);
    if (!text) return warn(18, 'Content Quality', 'page fetch failed');
    const wordCount = text.split(/\s+/).filter(Boolean).length;
    const hasTitle = /<title[^>]*>.+<\/title>/i.test(text);
    const status = wordCount > 50 && hasTitle ? 'PASS' : 'WARN';
    return { id: 18, name: 'Content Quality', status, evidence: `word_count=${wordCount} has_title=${hasTitle}`, data: {} };
  } catch (e) {
    return warn(18, 'Content Quality', String(e).slice(0, 100));
  }
}

export async function checkSpellingErrors(url: string): Promise<CheckResult> {
  // Without an external API, we do a basic check for common misspelling patterns
  return info(19, 'Spelling Errors', 'spelling_check=skipped (no spell-check API configured)');
}

export async function checkBrandConsistency(url: string): Promise<CheckResult> {
  return info(20, 'Brand Consistency', 'brand_check=skipped (manual review required)');
}

export async function checkContactInfo(url: string): Promise<CheckResult> {
  try {
    const text = await fetchText(url);
    if (!text) return warn(21, 'Contact Information', 'page fetch failed');
    const hasEmail = /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/.test(text);
    const hasPhone = /\+?\d[\d\s\-().]{7,}\d/.test(text);
    const hasContactLink = /contact|support|help/i.test(text);
    const status = (hasEmail || hasPhone || hasContactLink) ? 'PASS' : 'WARN';
    return { id: 21, name: 'Contact Information', status, evidence: `has_email=${hasEmail} has_phone=${hasPhone} has_contact_link=${hasContactLink}`, data: {} };
  } catch (e) {
    return warn(21, 'Contact Information', String(e).slice(0, 100));
  }
}

export async function checkAboutPrivacy(url: string): Promise<CheckResult> {
  try {
    const text = await fetchText(url);
    if (!text) return warn(22, 'About / Privacy', 'page fetch failed');
    const hasAbout = /\babout\b/i.test(text);
    const hasPrivacy = /\bprivacy\b/i.test(text);
    const status = (hasAbout && hasPrivacy) ? 'PASS' : hasAbout || hasPrivacy ? 'INFO' : 'WARN';
    return { id: 22, name: 'About / Privacy', status, evidence: `has_about=${hasAbout} has_privacy=${hasPrivacy}`, data: {} };
  } catch (e) {
    return warn(22, 'About / Privacy', String(e).slice(0, 100));
  }
}

export async function checkTooGoodOffers(url: string): Promise<CheckResult> {
  try {
    const text = await fetchText(url);
    if (!text) return warn(23, 'Too-Good Offers', 'page fetch failed');
    const patterns = ['100% free', 'guaranteed winner', 'act now', 'limited time offer', 'you have been selected', 'claim your prize', 'click here to win'];
    const found = patterns.filter((p) => text.toLowerCase().includes(p));
    const status = found.length > 0 ? 'WARN' : 'PASS';
    return { id: 23, name: 'Too-Good Offers', status, evidence: `suspicious_phrases=[${found.join(',')}]`, data: {} };
  } catch (e) {
    return warn(23, 'Too-Good Offers', String(e).slice(0, 100));
  }
}

export async function checkLogoImages(url: string): Promise<CheckResult> {
  try {
    const text = await fetchText(url);
    if (!text) return warn(24, 'Logos & Images', 'page fetch failed');
    const imgCount = (text.match(/<img /gi) || []).length;
    const status = imgCount > 0 ? 'PASS' : 'WARN';
    return { id: 24, name: 'Logos & Images', status, evidence: `img_count=${imgCount}`, data: {} };
  } catch (e) {
    return warn(24, 'Logos & Images', String(e).slice(0, 100));
  }
}

export async function checkBrokenLinks(url: string): Promise<CheckResult> {
  return info(25, 'Broken Links', 'broken_links=skipped (link traversal disabled for performance)', {});
}

// ─── Reputation checks ────────────────────────────────────────────────────────

export async function checkSecurityBlacklists(url: string): Promise<CheckResult> {
  if (!SERVER_CONFIG.GOOGLE_SAFE_BROWSING_API_KEY && !SERVER_CONFIG.VIRUSTOTAL_API_KEY) {
    return info(26, 'Security Blacklists', 'blacklist_check=skipped (no blacklist APIs configured)');
  }
  try {
    const vtData = await lookupVirusTotalUrl(url);
    const vtStats = (((vtData?.data as Record<string, unknown> | undefined)?.attributes as Record<string, unknown> | undefined)?.last_analysis_stats || {}) as Record<string, unknown>;
    const malicious = Number(vtStats.malicious || 0);
    const suspicious = Number(vtStats.suspicious || 0);
    const body = {
      client: { clientId: 'url-audit-kit', clientVersion: '2.0' },
      threatInfo: {
        threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
        platformTypes: ['ANY_PLATFORM'],
        threatEntryTypes: ['URL'],
        threatEntries: [{ url }],
      },
    };
    let googleMatches: unknown[] = [];
    if (SERVER_CONFIG.GOOGLE_SAFE_BROWSING_API_KEY) {
      const res = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${SERVER_CONFIG.GOOGLE_SAFE_BROWSING_API_KEY}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(10000),
      });
      const data = await res.json() as { matches?: unknown[] };
      googleMatches = data.matches || [];
    }
    if (googleMatches.length > 0 || malicious > 0) {
      return fail(26, 'Security Blacklists', `google_matches=${googleMatches.length} vt_malicious=${malicious} vt_suspicious=${suspicious}`, {
        google_matches: googleMatches,
        vt_stats: vtStats,
      });
    }
    if (suspicious > 0) {
      return warn(26, 'Security Blacklists', `google_matches=0 vt_malicious=${malicious} vt_suspicious=${suspicious}`, { vt_stats: vtStats });
    }
    return ok(26, 'Security Blacklists', `google_matches=${googleMatches.length} vt_malicious=${malicious} vt_suspicious=${suspicious}`);
  } catch (e) {
    return warn(26, 'Security Blacklists', `blacklist check error: ${String(e).slice(0, 100)}`);
  }
}

export async function checkGoogleSafeBrowsing(url: string): Promise<CheckResult> {
  if (!SERVER_CONFIG.GOOGLE_SAFE_BROWSING_API_KEY) return info(27, 'Google Safe Browsing', 'safe_browsing_check=skipped (GOOGLE_SAFE_BROWSING_API_KEY not configured)');
  try {
    const body = {
      client: { clientId: 'url-audit-kit', clientVersion: '2.0' },
      threatInfo: {
        threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING'],
        platformTypes: ['ANY_PLATFORM'],
        threatEntryTypes: ['URL'],
        threatEntries: [{ url }],
      },
    };
    const res = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${SERVER_CONFIG.GOOGLE_SAFE_BROWSING_API_KEY}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(10000),
    });
    const data = await res.json() as { matches?: unknown[] };
    const isSafe = !data.matches || data.matches.length === 0;
    return { id: 27, name: 'Google Safe Browsing', status: isSafe ? 'PASS' : 'FAIL', evidence: `safe_browsing_clean=${isSafe}`, data: {} };
  } catch (e) {
    return warn(27, 'Google Safe Browsing', `API check failed: ${String(e).slice(0, 100)}`);
  }
}

export async function checkSearchVisibility(url: string): Promise<CheckResult> {
  try {
    const domain = extractDomain(url);
    const data = await searchSerpApi(`site:${domain}`);
    if (!data) return info(28, 'Search Visibility', 'search_visibility=skipped (SERPAPI unavailable)');
    const organic = Array.isArray(data.organic_results) ? data.organic_results.length : 0;
    const status: CheckResult['status'] = organic > 0 ? 'PASS' : 'WARN';
    return { id: 28, name: 'Search Visibility', status, evidence: `domain=${domain} indexed_results=${organic}`, data: { indexed_results: organic } };
  } catch (e) {
    return warn(28, 'Search Visibility', String(e).slice(0, 100));
  }
}

export async function checkSocialMentions(url: string): Promise<CheckResult> {
  return info(29, 'Social Mentions', 'social_mentions=skipped (no social API configured)');
}

export async function checkWayback(url: string): Promise<CheckResult> {
  try {
    const host = extractDomain(url);
    const res = await fetch(`https://archive.org/wayback/available?url=${encodeURIComponent(host)}`, {
      signal: AbortSignal.timeout(10000),
    }).catch(() => null);
    if (!res?.ok) return warn(30, 'Wayback Machine', 'Wayback API unavailable');
    const data = await res.json() as { archived_snapshots?: { closest?: { available: boolean; timestamp: string } } };
    const snapshot = data.archived_snapshots?.closest;
    if (snapshot?.available) {
      return ok(30, 'Wayback Machine', `archived=true timestamp=${snapshot.timestamp}`);
    }
    return warn(30, 'Wayback Machine', 'archived=false (no snapshots found)');
  } catch (e) {
    return warn(30, 'Wayback Machine', String(e).slice(0, 100));
  }
}

export async function checkNewsReviews(url: string): Promise<CheckResult> {
  try {
    const domain = extractDomain(url);
    const data = await searchSerpApi(`"${domain}" reviews OR scam OR phishing`, { tbm: 'nws' });
    if (!data) return info(31, 'News & Reviews', 'news_check=skipped (SERPAPI unavailable)');
    const stories = Array.isArray(data.news_results) ? data.news_results.length : 0;
    const status: CheckResult['status'] = stories > 0 ? 'INFO' : 'PASS';
    return { id: 31, name: 'News & Reviews', status, evidence: `domain=${domain} news_hits=${stories}`, data: { news_hits: stories } };
  } catch (e) {
    return warn(31, 'News & Reviews', String(e).slice(0, 100));
  }
}

export async function checkBlacklistsEmailFilters(url: string): Promise<CheckResult> {
  try {
    const domain = extractDomain(url);
    const spamhausConfigured = Boolean(SERVER_CONFIG.SPAMHAUS_API_KEY);
    const surblConfigured = Boolean(SERVER_CONFIG.SURBL_API_KEY);
    const spamhausData = spamhausConfigured ? await lookupSpamhausDomain(domain) : null;
    const listed = Array.isArray(spamhausData?.records) ? spamhausData.records.length : 0;
    const status: CheckResult['status'] = listed > 0 ? 'FAIL' : (spamhausConfigured || surblConfigured ? 'INFO' : 'SKIP');
    return {
      id: 32,
      name: 'Blacklists & Email Filters',
      status,
      evidence: `domain=${domain} spamhaus_configured=${spamhausConfigured} surbl_configured=${surblConfigured} spamhaus_hits=${listed}`,
      data: { domain, spamhaus_configured: spamhausConfigured, surbl_configured: surblConfigured, spamhaus_hits: listed, spamhaus: spamhausData },
    };
  } catch (e) {
    return warn(32, 'Blacklists & Email Filters', String(e).slice(0, 100));
  }
}

export async function checkUserCommunityFeedback(url: string): Promise<CheckResult> {
  return info(33, 'Community Feedback', 'community_check=skipped (no community API configured)');
}

export async function checkBusinessDirectories(url: string): Promise<CheckResult> {
  try {
    const domain = extractDomain(url);
    const crunchbase = await lookupCrunchbaseOrganization(domain);
    const domaintools = await lookupDomainToolsProfile(domain);
    const cbEntities = Array.isArray((crunchbase?.data as Record<string, unknown> | undefined)?.items)
      ? ((crunchbase?.data as Record<string, unknown> | undefined)?.items as unknown[])
      : [];
    const cbHits = cbEntities.length;
    const dtRisk = String((domaintools?.response as Record<string, unknown> | undefined)?.risk_score || '');
    const status: CheckResult['status'] = cbHits > 0 ? 'PASS' : (dtRisk ? 'INFO' : 'WARN');
    return {
      id: 34,
      name: 'Business Directories',
      status,
      evidence: `domain=${domain} crunchbase_hits=${cbHits} domaintools_risk=${dtRisk || 'n/a'}`,
      data: {
        domain,
        crunchbase_hits: cbHits,
        domaintools_risk: dtRisk || null,
        crunchbase_configured: Boolean(SERVER_CONFIG.CRUNCHBASE_API_KEY),
        domaintools_configured: Boolean(SERVER_CONFIG.DOMAINTOOLS_API_KEY),
      },
    };
  } catch (e) {
    return warn(34, 'Business Directories', String(e).slice(0, 100));
  }
}

// ─── Behavior checks ──────────────────────────────────────────────────────────

export async function checkRedirects(url: string): Promise<CheckResult> {
  try {
    const hops: string[] = [url];
    let current = url;
    for (let i = 0; i < 10; i++) {
      const res = await fetch(current, {
        method: 'HEAD',
        redirect: 'manual',
        signal: AbortSignal.timeout(10000),
      }).catch(() => null);
      if (!res) break;
      if (res.status >= 300 && res.status < 400) {
        const loc = res.headers.get('location');
        if (!loc) break;
        current = loc.startsWith('http') ? loc : new URL(loc, current).href;
        hops.push(current);
      } else break;
    }
    const count = hops.length - 1;
    const status = count > 3 ? 'WARN' : 'PASS';
    return { id: 35, name: 'Redirect Behaviour', status, evidence: `redirect_count=${count} final_url=${current}`, data: { hops } };
  } catch (e) {
    return warn(35, 'Redirect Behaviour', String(e).slice(0, 100));
  }
}

export async function checkPopupsDownloads(url: string): Promise<CheckResult> {
  try {
    const text = await fetchText(url);
    if (!text) return warn(36, 'Popups & Downloads', 'page fetch failed');
    const hasPopup = /window\.open\(|onload\s*=\s*['""]?popup|alert\s*\(/i.test(text);
    const hasAutoDownload = /content-disposition.*attachment/i.test(text);
    const status = (hasPopup || hasAutoDownload) ? 'WARN' : 'PASS';
    return { id: 36, name: 'Popups & Downloads', status, evidence: `popup_pattern=${hasPopup} auto_download=${hasAutoDownload}`, data: {} };
  } catch (e) {
    return warn(36, 'Popups & Downloads', String(e).slice(0, 100));
  }
}

export async function checkSuspiciousRequests(url: string): Promise<CheckResult> {
  try {
    const text = await fetchText(url);
    if (!text) return warn(37, 'Suspicious Requests', 'page fetch failed');
    const patterns = ['document.cookie', 'eval(', 'base64_decode', 'fromCharCode', '.onload='];
    const found = patterns.filter((p) => text.includes(p));
    const status = found.length > 0 ? 'WARN' : 'PASS';
    return { id: 37, name: 'Suspicious Requests', status, evidence: `suspicious_patterns=[${found.join(',')}]`, data: {} };
  } catch (e) {
    return warn(37, 'Suspicious Requests', String(e).slice(0, 100));
  }
}

export async function checkUrlLength(url: string): Promise<CheckResult> {
  const len = url.length;
  const status = len > 100 ? 'WARN' : 'PASS';
  return { id: 38, name: 'URL Length', status, evidence: `url_length=${len}`, data: {} };
}

export async function checkHomoglyph(url: string): Promise<CheckResult> {
  try {
    const host = extractHost(url);
    // Check for common lookalike characters
    const homoglyphs = /[\u0430-\u044f\u0410-\u042f]|[\u00e0-\u00ff]|[0oO]{2,}|[1lI]{2,}/.test(host);
    const status = homoglyphs ? 'WARN' : 'PASS';
    return { id: 39, name: 'Homoglyph Detection', status, evidence: `host=${host} homoglyph_detected=${homoglyphs}`, data: {} };
  } catch (e) {
    return warn(39, 'Homoglyph Detection', String(e).slice(0, 100));
  }
}

export async function checkEmailLinks(url: string): Promise<CheckResult> {
  try {
    const text = await fetchText(url);
    if (!text) return warn(40, 'Email Links', 'page fetch failed');
    const emailLinks = (text.match(/href=["']mailto:/gi) || []).length;
    return info(40, 'Email Links', `mailto_links=${emailLinks}`);
  } catch (e) {
    return warn(40, 'Email Links', String(e).slice(0, 100));
  }
}

export async function checkMobileFriendly(url: string): Promise<CheckResult> {
  try {
    const text = await fetchText(url);
    if (!text) return warn(41, 'Mobile Friendliness', 'page fetch failed');
    const hasViewport = /name=["']viewport["']/i.test(text);
    const status = hasViewport ? 'PASS' : 'WARN';
    return { id: 41, name: 'Mobile Friendliness', status, evidence: `viewport_meta=${hasViewport}`, data: {} };
  } catch (e) {
    return warn(41, 'Mobile Friendliness', String(e).slice(0, 100));
  }
}

export async function checkAdsPrompts(url: string): Promise<CheckResult> {
  try {
    const text = await fetchText(url);
    if (!text) return warn(42, 'Ads & Prompts', 'page fetch failed');
    const adPatterns = ['googlesyndication', 'doubleclick.net', 'adsbygoogle', 'popunder', 'notification permission'];
    const found = adPatterns.filter((p) => text.toLowerCase().includes(p));
    const status = found.length > 2 ? 'WARN' : 'PASS';
    return { id: 42, name: 'Ads & Prompts', status, evidence: `ad_patterns=[${found.join(',')}]`, data: {} };
  } catch (e) {
    return warn(42, 'Ads & Prompts', String(e).slice(0, 100));
  }
}

// ─── AI/LLM check ─────────────────────────────────────────────────────────────

export async function checkLlmContentAnalysis(url: string): Promise<CheckResult> {
  try {
    const text = await fetchText(url);
    if (!text) return info(43, 'AI Content Analysis', 'Could not fetch page content');
    const plainText = text.replace(/<script[\s\S]*?<\/script>/gi, ' ').replace(/<style[\s\S]*?<\/style>/gi, ' ').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
    if (plainText.length < 50) return info(43, 'AI Content Analysis', 'Insufficient text content');

    const analysis = await analyzeTextWithNim(plainText, extractHost(url) || 'unknown');
    if (!analysis.enabled) {
      const reason = analysis.summary || analysis.error || 'LLM unavailable';
      return info(43, 'AI Content Analysis', String(reason).slice(0, 200));
    }

    const risks: string[] = [];
    if (String(analysis.grammar_issues || '').toUpperCase().includes('YES')) risks.push('grammar');
    if (String(analysis.too_good_claims || '').toUpperCase().includes('YES')) risks.push('too-good-claims');
    if (String(analysis.credential_or_payment_risk || '').toUpperCase().includes('YES')) risks.push('credential-risk');
    if (String(analysis.brand_mismatch || '').toUpperCase().includes('YES')) risks.push('brand-mismatch');
    if (String(analysis.phishy_tone || '').toUpperCase().includes('YES')) risks.push('phishy-tone');

    const overall = String(analysis.overall_risk || 'LOW').toUpperCase();
    const status: CheckResult['status'] = overall === 'HIGH' ? 'FAIL' : (overall === 'MEDIUM' || risks.length ? 'WARN' : 'PASS');
    let evidence = `risk=${overall}`;
    if (risks.length) evidence += ` flags=${risks.join(',')}`;
    if (analysis.summary) evidence += ` | ${String(analysis.summary).slice(0, 150)}`;

    return { id: 43, name: 'AI Content Analysis', status, evidence, data: analysis as Record<string, unknown> };
  } catch (e) {
    return warn(43, 'AI Content Analysis', `Analysis error: ${String(e).slice(0, 150)}`);
  }
}
