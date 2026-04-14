import type { CheckResult } from './checks';
import * as C from './checks';
import type { ScanMode } from '@/types';

type CheckFn = (url: string) => Promise<CheckResult | CheckResult[]>;

const CHECK_STEPS: Array<{ label: string; fn: CheckFn }> = [
  { label: 'Domain Name Legitimacy', fn: C.checkDomainLegitimacy },
  { label: 'Top-Level Domain (TLD)', fn: C.checkTld },
  { label: 'WHOIS and Domain Age', fn: C.checkWhoisAge },
  { label: 'DNS / Email Records', fn: C.checkDnsEmailRecords },
  { label: 'Registrar Details Transparency', fn: C.checkRegistrarTransparency },
  { label: 'Domain Expiry', fn: C.checkDomainExpiry },
  { label: 'Previous Domain Ownership', fn: C.checkPreviousOwnership },
  { label: 'Domain Transfer History', fn: C.checkDomainTransfers },
  { label: 'SSL Validity', fn: C.checkSslValidity },
  { label: 'HTTPS Presence', fn: C.checkHttpsPresence },
  { label: 'Certificate Issuer', fn: C.checkCertificateIssuer },
  { label: 'Security Headers', fn: C.checkSecurityHeaders },
  { label: 'IP Reputation', fn: C.checkIpReputation },
  { label: 'Server Geolocation', fn: C.checkServerGeolocation },
  { label: 'Hosting Provider', fn: C.checkHostingProvider },
  { label: 'Page Load Speed', fn: C.checkPageLoadSpeed },
  { label: 'Mozilla Observatory', fn: C.checkMozillaObservatory },
  { label: 'Content Quality', fn: C.checkContentQuality },
  { label: 'Spelling Errors', fn: C.checkSpellingErrors },
  { label: 'Brand Consistency', fn: C.checkBrandConsistency },
  { label: 'Contact Information', fn: C.checkContactInfo },
  { label: 'About / Privacy', fn: C.checkAboutPrivacy },
  { label: 'Too-Good Offers', fn: C.checkTooGoodOffers },
  { label: 'Logos & Images', fn: C.checkLogoImages },
  { label: 'Broken Links', fn: C.checkBrokenLinks },
  { label: 'Security Blacklists', fn: C.checkSecurityBlacklists },
  { label: 'Google Safe Browsing', fn: C.checkGoogleSafeBrowsing },
  { label: 'Search Visibility', fn: C.checkSearchVisibility },
  { label: 'Social Mentions', fn: C.checkSocialMentions },
  { label: 'Wayback Machine', fn: C.checkWayback },
  { label: 'News & Reviews', fn: C.checkNewsReviews },
  { label: 'Blacklists & Email Filters', fn: C.checkBlacklistsEmailFilters },
  { label: 'Community Feedback', fn: C.checkUserCommunityFeedback },
  { label: 'Business Directories', fn: C.checkBusinessDirectories },
  { label: 'Redirect Behaviour', fn: C.checkRedirects },
  { label: 'Popups & Downloads', fn: C.checkPopupsDownloads },
  { label: 'Suspicious Requests', fn: C.checkSuspiciousRequests },
  { label: 'URL Length', fn: C.checkUrlLength },
  { label: 'Homoglyph Detection', fn: C.checkHomoglyph },
  { label: 'Email Links', fn: C.checkEmailLinks },
  { label: 'Mobile Friendliness', fn: C.checkMobileFriendly },
  { label: 'Ads & Prompts', fn: C.checkAdsPrompts },
  { label: 'AI Content Analysis', fn: C.checkLlmContentAnalysis },
];

const CORE_SCAN_LABELS = new Set([
  'Domain Name Legitimacy',
  'Top-Level Domain (TLD)',
  'WHOIS and Domain Age',
  'DNS / Email Records',
  'Registrar Details Transparency',
  'Domain Expiry',
  'SSL Validity',
  'HTTPS Presence',
  'Certificate Issuer',
  'Security Headers',
  'IP Reputation',
  'Server Geolocation',
  'Hosting Provider',
  'Mozilla Observatory',
  'Content Quality',
  'Contact Information',
  'About / Privacy',
  'Security Blacklists',
  'Google Safe Browsing',
  'Redirect Behaviour',
  'Suspicious Requests',
  'URL Length',
  'Homoglyph Detection',
]);

const STEP_TIMEOUT_MS = 6000;
const MAX_CONCURRENCY = 8;

export function totalSteps(): number {
  return CHECK_STEPS.length;
}

const SECTION_RULES: Array<{ section: string; patterns: string[] }> = [
  { section: 'Domain Intelligence', patterns: ['domain', 'whois', 'tld', 'registrar', 'transfer'] },
  { section: 'Security Posture', patterns: ['ssl', 'https', 'certificate', 'ip reputation', 'hosting', 'security', 'observatory'] },
  { section: 'Reputation & Trust', patterns: ['blacklist', 'safe browsing', 'reputation', 'wayback'] },
  { section: 'Behavioural Signals', patterns: ['redirect', 'suspicious', 'url length', 'homoglyph', 'popup', 'ads', 'mobile', 'email link'] },
  { section: 'Content', patterns: ['content', 'spelling', 'brand', 'contact', 'about', 'privacy', 'offer', 'logo', 'broken', 'image'] },
  { section: 'AI Observations', patterns: ['ai', 'content analysis'] },
];

function lookupSection(name: string): string {
  const lower = (name || '').toLowerCase();
  for (const rule of SECTION_RULES) {
    if (rule.patterns.some((p) => lower.includes(p))) return rule.section;
  }
  return 'Additional Checks';
}

function statusToRisk(status: string): string {
  const map: Record<string, string> = { PASS: 'LOW', INFO: 'LOW', WARN: 'MEDIUM', FAIL: 'HIGH', SKIP: 'LOW' };
  return map[(status || '').toUpperCase()] || 'MEDIUM';
}

const STATUS_STYLES: Record<string, { badge: string; icon: string }> = {
  PASS: { badge: 'success', icon: 'verified' },
  WARN: { badge: 'warning', icon: 'report' },
  FAIL: { badge: 'danger', icon: 'dangerous' },
  INFO: { badge: 'info', icon: 'info' },
  SKIP: { badge: 'secondary', icon: 'upcoming' },
};

export interface PreparedResult {
  id: number;
  name: string;
  status: string;
  badge: string;
  icon: string;
  evidence: string;
  details: string;
  data: Record<string, unknown>;
  summary: string;
  risk_level: string;
  section: string;
}

function prepareResult(r: CheckResult): PreparedResult {
  const style = STATUS_STYLES[r.status] || { badge: 'secondary', icon: 'adjust' };
  const section = lookupSection(r.name);
  const risk_level = statusToRisk(r.status);
  let details = '';
  if (r.data && Object.keys(r.data).length) {
    try { details = JSON.stringify(r.data, null, 2); } catch { details = String(r.data); }
  }
  return {
    id: r.id,
    name: r.name,
    status: r.status,
    badge: style.badge,
    icon: style.icon,
    evidence: r.evidence || '',
    details,
    data: r.data || {},
    summary: r.evidence || `Status reported as ${r.status}`,
    risk_level,
    section,
  };
}

function groupBySection(results: PreparedResult[]): Array<{ name: string; checks: PreparedResult[] }> {
  const sections = new Map<string, PreparedResult[]>();
  for (const r of results) {
    if (!sections.has(r.section)) sections.set(r.section, []);
    sections.get(r.section)!.push(r);
  }
  return Array.from(sections.entries()).map(([name, checks]) => ({ name, checks }));
}

function selectSteps(scanMode: ScanMode): Array<{ label: string; fn: CheckFn }> {
  if (scanMode === 'deep' || scanMode === 'sandbox') return CHECK_STEPS;
  return CHECK_STEPS.filter((step) => CORE_SCAN_LABELS.has(step.label));
}

async function runStep(step: { label: string; fn: CheckFn }, url: string): Promise<PreparedResult[]> {
  try {
    const raw = await Promise.race([
      step.fn(url),
      new Promise<CheckResult>((_, reject) =>
        setTimeout(() => reject(new Error(`timeout after ${STEP_TIMEOUT_MS}ms`)), STEP_TIMEOUT_MS)
      ),
    ]);
    const list = Array.isArray(raw) ? raw : [raw];
    return list.map(prepareResult);
  } catch (e) {
    return [{
      id: 999,
      name: step.label,
      status: 'FAIL',
      badge: 'danger',
      icon: 'dangerous',
      evidence: `check crashed: ${String(e).slice(0, 200)}`,
      details: '',
      data: { error: String(e) },
      summary: `check crashed: ${String(e).slice(0, 100)}`,
      risk_level: 'HIGH',
      section: lookupSection(step.label),
    }];
  }
}

export async function runAll(url: string, scanMode: ScanMode = 'scan'): Promise<{
  results: PreparedResult[];
  grouped_results: Array<{ name: string; checks: PreparedResult[] }>;
  counts: Record<string, number>;
}> {
  const steps = selectSteps(scanMode);
  const buckets: PreparedResult[][] = new Array(steps.length);
  const counts: Record<string, number> = { PASS: 0, WARN: 0, FAIL: 0, INFO: 0, SKIP: 0 };

  let cursor = 0;
  const workers = Array.from({ length: Math.min(MAX_CONCURRENCY, steps.length) }, async () => {
    while (cursor < steps.length) {
      const index = cursor++;
      buckets[index] = await runStep(steps[index], url);
    }
  });
  await Promise.all(workers);

  const allResults = buckets.flat();
  for (const prepared of allResults) {
    counts[prepared.status] = (counts[prepared.status] || 0) + 1;
  }

  return {
    results: allResults,
    grouped_results: groupBySection(allResults),
    counts,
  };
}
