/**
 * Persistence layer – TypeScript port of Python webapp/persistence.py
 */
import { getDb } from './db';
import type { PreparedResult } from './runner';

const IP_PATTERN = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;

const COUNTRY_COORDS: Record<string, [number, number]> = {
  US: [37.09, -95.71], CA: [56.13, -106.35], MX: [23.63, -102.55], BR: [-14.24, -51.93],
  GB: [55.38, -3.44], FR: [46.23, 2.21], DE: [51.17, 10.45], NL: [52.13, 5.29],
  RU: [61.52, 105.32], IN: [20.59, 78.96], CN: [35.86, 104.20], JP: [36.20, 138.25],
  KR: [35.91, 127.77], SG: [1.35, 103.82], AU: [-25.27, 133.78], ZA: [-30.56, 22.94],
  AE: [23.42, 53.85], SA: [23.89, 45.08], TR: [38.96, 35.24],
};

const CRITICAL_IOC_KEYWORDS = ['blacklist', 'safe browsing', 'ssl', 'https', 'ip reputation'];

function severityFromCheck(name: string, status: string): string {
  const s = (status || '').toUpperCase();
  const n = (name || '').toLowerCase();
  const isCritical = CRITICAL_IOC_KEYWORDS.some((k) => n.includes(k));
  if (s === 'FAIL') return isCritical ? 'CRITICAL' : 'HIGH';
  if (s === 'WARN') return isCritical ? 'HIGH' : 'MEDIUM';
  if (s === 'INFO') return 'LOW';
  return 'LOW';
}

function domainFromUrl(url: string): string {
  try { return new URL(url).hostname.toLowerCase(); } catch { return ''; }
}

interface Ioc {
  indicator: string;
  indicator_type: string;
  severity: string;
  source_check: string;
  country: string;
  created_at: string;
}

function extractIocs(targetUrl: string, checks: PreparedResult[], createdAt: string): Ioc[] {
  const iocs: Ioc[] = [];
  const seen = new Set<string>();

  function addIoc(indicator: string, type: string, severity: string, source: string, country: string): void {
    const text = (indicator || '').trim();
    if (!text) return;
    const key = `${text.toLowerCase()}|${type.toUpperCase()}|${severity.toUpperCase()}|${source.toLowerCase()}|${country.toUpperCase()}`;
    if (seen.has(key)) return;
    seen.add(key);
    iocs.push({ indicator: text, indicator_type: type.toUpperCase(), severity: severity.toUpperCase(), source_check: source, country: country.toUpperCase(), created_at: createdAt });
  }

  const domain = domainFromUrl(targetUrl);
  if (domain) addIoc(domain, 'DOMAIN', 'LOW', 'Target URL', '');

  for (const check of checks) {
    const name = check.name || '';
    const status = check.status || 'WARN';
    const evidence = check.evidence || '';
    const lower = name.toLowerCase();
    const severity = severityFromCheck(name, status);

    if ((status === 'FAIL' || status === 'WARN') && (lower.includes('blacklist') || lower.includes('safe browsing'))) {
      addIoc(targetUrl, 'URL', status === 'FAIL' ? 'CRITICAL' : 'HIGH', name, '');
    }

    const blob = `${evidence} ${JSON.stringify(check.data || {})}`;
    const ips = blob.match(IP_PATTERN) || [];
    for (const ip of ips) addIoc(ip, 'IP', severity, name, '');

    if ((status === 'FAIL' || status === 'WARN') && lower.includes('homoglyph') && domain) {
      addIoc(domain, 'DOMAIN', 'HIGH', name, '');
    }
  }

  return iocs;
}

interface ScanInput {
  target_url: string;
  scan_mode: string;
  prepared_results: PreparedResult[];
  counts: Record<string, number>;
  risk_score: number;
  risk_level: string;
  verdict: string;
  threat_report: Record<string, unknown> | null;
  duration_ms: number;
  created_at: string;
}

export function persistScan(input: ScanInput): { scan_id: number; ioc_count: number } {
  const db = getDb();
  const ts = input.created_at || new Date().toISOString();
  const aiVerdict = (input.threat_report?.verdict as string)?.toUpperCase() || null;
  const aiSummary = (input.threat_report?.executive_summary as string) || null;
  const threatReportJson = input.threat_report ? JSON.stringify(input.threat_report) : null;
  const iocs = extractIocs(input.target_url, input.prepared_results, ts);

  const insertScan = db.prepare(`
    INSERT INTO scans (target_url, scan_mode, risk_score, risk_level, verdict, total_checks,
      pass_count, warn_count, fail_count, info_count, skip_count,
      ai_verdict, ai_summary, threat_report_json, duration_ms, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const insertCheck = db.prepare(`
    INSERT INTO scan_checks (scan_id, check_id, name, status, risk_level, section, evidence, details, data_json, summary)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const insertIoc = db.prepare(`
    INSERT INTO iocs (scan_id, indicator, indicator_type, severity, source_check, country, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `);

  const run = db.transaction(() => {
    const result = insertScan.run(
      input.target_url, input.scan_mode, input.risk_score, input.risk_level, input.verdict,
      Object.values(input.counts).reduce((a, b) => a + b, 0),
      input.counts['PASS'] || 0, input.counts['WARN'] || 0, input.counts['FAIL'] || 0,
      input.counts['INFO'] || 0, input.counts['SKIP'] || 0,
      aiVerdict, aiSummary, threatReportJson, input.duration_ms, ts,
    );
    const scanId = Number(result.lastInsertRowid);

    for (const check of input.prepared_results) {
      insertCheck.run(
        scanId, check.id, check.name, check.status, check.risk_level,
        check.section, check.evidence, check.details,
        JSON.stringify(check.data || {}), check.summary,
      );
    }

    for (const ioc of iocs) {
      insertIoc.run(scanId, ioc.indicator, ioc.indicator_type, ioc.severity, ioc.source_check, ioc.country, ioc.created_at);
    }

    return scanId;
  });

  const scanId = run() as number;
  return { scan_id: scanId, ioc_count: iocs.length };
}

// ─── Query helpers ─────────────────────────────────────────────────────────────

function rangeSince(rangeValue: string): string {
  const now = Date.now();
  const window = (rangeValue || '24h').toLowerCase();
  if (window === '7d') return new Date(now - 7 * 86400000).toISOString();
  if (window === '30d') return new Date(now - 30 * 86400000).toISOString();
  return new Date(now - 86400000).toISOString();
}

function buildPage(total: number, page: number, pageSize: number) {
  return { total, page, page_size: pageSize, total_pages: Math.max(1, Math.ceil(total / pageSize)) };
}

export function getDashboardOverview(rangeValue = '24h') {
  const db = getDb();
  const since = rangeSince(rangeValue);
  const rows = db.prepare(`
    SELECT id, target_url, risk_score, risk_level, verdict, created_at
    FROM scans WHERE created_at >= ? ORDER BY created_at DESC
  `).all(since) as Array<Record<string, unknown>>;

  let malicious = 0, suspicious = 0, safe = 0;
  const distribution: Record<string, number> = { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
  const activity: Map<string, { total: number; malicious: number; safe: number }> = new Map();
  const bucketByHour = (rangeValue || '24h').toLowerCase() === '24h';

  for (const row of rows) {
    const level = String(row.risk_level || '').toUpperCase();
    distribution[level] = (distribution[level] || 0) + 1;
    if (level === 'HIGH' || level === 'CRITICAL') malicious++;
    else if (level === 'MEDIUM') suspicious++;
    else safe++;

    const dt = new Date(String(row.created_at));
    const bucket = bucketByHour
      ? `${dt.toISOString().slice(0, 13)}:00`
      : dt.toISOString().slice(0, 10);
    if (!activity.has(bucket)) activity.set(bucket, { total: 0, malicious: 0, safe: 0 });
    const b = activity.get(bucket)!;
    b.total++;
    if (level === 'HIGH' || level === 'CRITICAL') b.malicious++;
    if (level === 'LOW') b.safe++;
  }

  return {
    range: rangeValue,
    totals: { total_scans: rows.length, malicious_urls: malicious, suspicious_domains: suspicious, safe_urls: safe },
    threat_distribution: Object.entries(distribution).map(([label, value]) => ({ label, value })),
    scan_activity: Array.from(activity.entries()).sort((a, b) => a[0].localeCompare(b[0])).map(([bucket, counts]) => ({ bucket, ...counts })),
    recent_scans: rows.slice(0, 10).map((r) => ({ id: r.id, target_url: r.target_url, risk_score: r.risk_score, risk_level: r.risk_level, verdict: r.verdict, created_at: r.created_at })),
  };
}

const VALID_SCAN_SORT = new Map([
  ['created_at', 'created_at'], ['risk_score', 'risk_score'], ['target_url', 'target_url'], ['verdict', 'verdict'],
]);

export function listScans(params: {
  page?: number; page_size?: number; q?: string; risk?: string; status?: string;
  sort_by?: string; sort_order?: string;
}) {
  const db = getDb();
  const page = Math.max(1, params.page || 1);
  const pageSize = Math.min(200, Math.max(1, params.page_size || 20));
  const offset = (page - 1) * pageSize;

  const where: string[] = ['1=1'];
  const args: unknown[] = [];

  if (params.q?.trim()) { where.push('target_url LIKE ?'); args.push(`%${params.q.trim()}%`); }
  if (params.risk?.trim()) {
    const values = params.risk.split(',').map((v) => v.trim().toUpperCase()).filter(Boolean);
    if (values.length) { where.push(`risk_level IN (${values.map(() => '?').join(',')})`); args.push(...values); }
  }
  if (params.status?.trim()) {
    const values = params.status.split(',').map((v) => v.trim().toUpperCase()).filter(Boolean);
    if (values.length) { where.push(`verdict IN (${values.map(() => '?').join(',')})`); args.push(...values); }
  }

  const orderField = VALID_SCAN_SORT.get(params.sort_by || 'created_at') || 'created_at';
  const direction = (params.sort_order || 'desc').toLowerCase() === 'asc' ? 'ASC' : 'DESC';
  const whereSQL = where.join(' AND ');

  const total = (db.prepare(`SELECT COUNT(*) as c FROM scans WHERE ${whereSQL}`).get(...args) as { c: number }).c;
  const rows = db.prepare(`SELECT * FROM scans WHERE ${whereSQL} ORDER BY ${orderField} ${direction} LIMIT ? OFFSET ?`).all(...args, pageSize, offset) as Array<Record<string, unknown>>;

  return { items: rows, ...buildPage(total, page, pageSize) };
}

export function getScan(scanId: number) {
  const db = getDb();
  const scan = db.prepare('SELECT * FROM scans WHERE id = ?').get(scanId) as Record<string, unknown> | undefined;
  if (!scan) return null;

  const checks = db.prepare(`
    SELECT check_id, name, status, risk_level, section, evidence, details, data_json, summary
    FROM scan_checks WHERE scan_id = ? ORDER BY check_id ASC, id ASC
  `).all(scanId) as Array<Record<string, unknown>>;

  const iocs = db.prepare(`
    SELECT id, indicator, indicator_type, severity, source_check, country, created_at
    FROM iocs WHERE scan_id = ? ORDER BY id DESC
  `).all(scanId) as Array<Record<string, unknown>>;

  return {
    ...scan,
    summary_cards: [
      { status: 'PASS', count: scan.pass_count }, { status: 'WARN', count: scan.warn_count },
      { status: 'FAIL', count: scan.fail_count }, { status: 'INFO', count: scan.info_count },
      { status: 'SKIP', count: scan.skip_count },
    ],
    checks: checks.map((c) => ({ ...c, data: JSON.parse(String(c.data_json || '{}')) })),
    iocs,
  };
}

export function getScanReport(scanId: number) {
  const scanRaw = getScan(scanId);
  if (!scanRaw) return null;
  const scan = scanRaw as Record<string, unknown>;

  const grouped = new Map<string, unknown[]>();
  for (const check of (scan['checks'] as Array<Record<string, unknown>>) || []) {
    const section = String(check['section'] || 'Additional Checks');
    if (!grouped.has(section)) grouped.set(section, []);
    grouped.get(section)!.push(check);
  }

  let threatReport: Record<string, unknown> | null = null;
  if (scan['threat_report_json']) {
    try { threatReport = JSON.parse(String(scan['threat_report_json'])); } catch { /* ignore */ }
  }

  const recommendations: string[] = [];
  if (threatReport && Array.isArray(threatReport.recommendations)) {
    recommendations.push(...(threatReport.recommendations as string[]));
  }
  if (!recommendations.length) {
    if (scan['risk_level'] === 'HIGH' || scan['risk_level'] === 'CRITICAL') {
      recommendations.push('Block or sandbox this URL before end-user access.', 'Add related indicators to watchlists.', 'Escalate to incident response for containment.');
    } else if (scan['risk_level'] === 'MEDIUM') {
      recommendations.push('Review suspicious findings before allowing unrestricted access.', 'Monitor this domain for behavior changes.');
    } else {
      recommendations.push('No high-risk indicators detected. Continue routine monitoring.');
    }
  }

  return {
    scan,
    scan_summary: {
      target_url: scan['target_url'], scan_mode: scan['scan_mode'], risk_score: scan['risk_score'],
      risk_level: scan['risk_level'], verdict: scan['verdict'], created_at: scan['created_at'],
      duration_ms: scan['duration_ms'], total_checks: scan['total_checks'],
    },
    indicators_of_compromise: scan['iocs'],
    domain_intelligence: grouped.get('Domain Intelligence') || [],
    risk_assessment: {
      pass_count: scan['pass_count'], warn_count: scan['warn_count'], fail_count: scan['fail_count'],
      info_count: scan['info_count'], skip_count: scan['skip_count'], risk_score: scan['risk_score'], risk_level: scan['risk_level'],
    },
    recommendations,
    grouped_checks: Array.from(grouped.entries()).map(([name, checks]) => ({ name, checks })),
    threat_report: threatReport,
  };
}

const VALID_IOC_SORT = new Map([
  ['created_at', 'i.created_at'], ['severity', 'i.severity'], ['indicator', 'i.indicator'], ['indicator_type', 'i.indicator_type'],
]);

export function listIocs(params: {
  page?: number; page_size?: number; q?: string; indicator_type?: string; severity?: string;
  sort_by?: string; sort_order?: string;
}) {
  const db = getDb();
  const page = Math.max(1, params.page || 1);
  const pageSize = Math.min(200, Math.max(1, params.page_size || 20));
  const offset = (page - 1) * pageSize;

  const where: string[] = ['1=1'];
  const args: unknown[] = [];

  if (params.q?.trim()) { where.push('i.indicator LIKE ?'); args.push(`%${params.q.trim()}%`); }
  if (params.indicator_type?.trim()) {
    const values = params.indicator_type.split(',').map((v) => v.trim().toUpperCase()).filter(Boolean);
    if (values.length) { where.push(`i.indicator_type IN (${values.map(() => '?').join(',')})`); args.push(...values); }
  }
  if (params.severity?.trim()) {
    const values = params.severity.split(',').map((v) => v.trim().toUpperCase()).filter(Boolean);
    if (values.length) { where.push(`i.severity IN (${values.map(() => '?').join(',')})`); args.push(...values); }
  }

  const orderField = VALID_IOC_SORT.get(params.sort_by || 'created_at') || 'i.created_at';
  const direction = (params.sort_order || 'desc').toLowerCase() === 'asc' ? 'ASC' : 'DESC';
  const whereSQL = where.join(' AND ');

  const total = (db.prepare(`SELECT COUNT(*) as c FROM iocs i WHERE ${whereSQL}`).get(...args) as { c: number }).c;
  const rows = db.prepare(`
    SELECT i.*, s.target_url, s.risk_level, s.risk_score
    FROM iocs i JOIN scans s ON s.id = i.scan_id
    WHERE ${whereSQL} ORDER BY ${orderField} ${direction} LIMIT ? OFFSET ?
  `).all(...args, pageSize, offset) as Array<Record<string, unknown>>;

  return { items: rows, ...buildPage(total, page, pageSize) };
}

export function getThreatMap(rangeValue = '24h') {
  const db = getDb();
  const since = rangeSince(rangeValue);
  const rows = db.prepare(`
    SELECT country, severity, COUNT(*) AS count FROM iocs
    WHERE created_at >= ? AND country IS NOT NULL AND country != ''
    GROUP BY country, severity
  `).all(since) as Array<{ country: string; severity: string; count: number }>;

  const agg = new Map<string, { count: number; critical: number; high: number; medium: number; low: number }>();
  for (const row of rows) {
    const c = (row.country || '').toUpperCase();
    if (!c) continue;
    if (!agg.has(c)) agg.set(c, { count: 0, critical: 0, high: 0, medium: 0, low: 0 });
    const a = agg.get(c)!;
    a.count += row.count;
    const sev = (row.severity || '').toLowerCase() as 'critical' | 'high' | 'medium' | 'low';
    if (sev in a) (a as Record<string, number>)[sev] += row.count;
  }

  const points = [];
  for (const [country, counts] of Array.from(agg.entries())) {
    const coords = COUNTRY_COORDS[country];
    if (!coords) continue;
    points.push({ country, lat: coords[0], lng: coords[1], ...counts });
  }

  return { range: rangeValue, points: points.sort((a, b) => b.count - a.count) };
}

export function getTopMaliciousDomains(limit = 20) {
  const db = getDb();
  const l = Math.min(200, Math.max(1, limit));
  const rows = db.prepare(`
    SELECT indicator AS domain, COUNT(*) AS hits, MAX(created_at) AS last_seen
    FROM iocs WHERE indicator_type = 'DOMAIN' AND severity IN ('HIGH', 'CRITICAL')
    GROUP BY indicator ORDER BY hits DESC, last_seen DESC LIMIT ?
  `).all(l) as Array<Record<string, unknown>>;
  return { items: rows };
}

export function getIpReputation(limit = 20) {
  const db = getDb();
  const l = Math.min(200, Math.max(1, limit));
  const rows = db.prepare(`
    SELECT indicator AS ip, COUNT(*) AS sightings, MAX(created_at) AS last_seen,
      SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) AS critical_hits,
      SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) AS high_hits,
      SUM(CASE WHEN severity = 'MEDIUM' THEN 1 ELSE 0 END) AS medium_hits
    FROM iocs WHERE indicator_type = 'IP'
    GROUP BY indicator ORDER BY critical_hits DESC, high_hits DESC, sightings DESC LIMIT ?
  `).all(l) as Array<Record<string, unknown>>;
  return { items: rows };
}
