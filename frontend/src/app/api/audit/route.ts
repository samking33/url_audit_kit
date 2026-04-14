import { NextRequest, NextResponse } from 'next/server';
import { runAll } from '@/lib/audit/runner';
import { computeRisk } from '@/lib/audit/risk';
import { persistScan } from '@/lib/audit/persistence';
import { analyzeResultsWithNim } from '@/lib/audit/ai';

export const runtime = 'nodejs';
export const maxDuration = 120;

export async function POST(req: NextRequest): Promise<NextResponse> {
  let url = '';
  let scanMode = 'scan';

  const contentType = req.headers.get('content-type') || '';
  if (contentType.includes('multipart/form-data') || contentType.includes('application/x-www-form-urlencoded')) {
    const formData = await req.formData().catch(() => null);
    if (formData) {
      url = String(formData.get('url') || '').trim();
      scanMode = String(formData.get('scan_mode') || 'scan').trim().toLowerCase();
    }
  } else {
    const body = await req.json().catch(() => ({})) as Record<string, string>;
    url = String(body.url || '').trim();
    scanMode = String(body.scan_mode || 'scan').trim().toLowerCase();
  }

  if (!url) {
    return NextResponse.json({ error: 'Please enter a URL to audit.' }, { status: 400 });
  }
  if (!['scan', 'deep', 'sandbox'].includes(scanMode)) scanMode = 'scan';

  const startedAt = Date.now();

  try {
    const { results, grouped_results, counts } = await runAll(url);
    const analysis = await analyzeResultsWithNim(results);
    const threatReport = analysis.enabled ? analysis.threat_report || null : null;
    const metadata = analysis.enabled ? analysis.metadata || null : null;
    const analysisError = analysis.enabled ? null : (analysis.error || null);
    const riskMeta = computeRisk(results);
    const createdAt = new Date().toISOString();
    const durationMs = Date.now() - startedAt;

    const { scan_id, ioc_count } = persistScan({
      target_url: url,
      scan_mode: scanMode,
      prepared_results: results,
      counts,
      risk_score: riskMeta.risk_score,
      risk_level: riskMeta.risk_level,
      verdict: riskMeta.verdict,
      threat_report: threatReport,
      duration_ms: durationMs,
      created_at: createdAt,
    });

    const summaryCards = ['PASS', 'WARN', 'FAIL', 'INFO', 'SKIP'].map((status) => ({
      status,
      count: counts[status] || 0,
      badge: { PASS: 'success', WARN: 'warning', FAIL: 'danger', INFO: 'info', SKIP: 'secondary' }[status],
      icon: { PASS: 'verified', WARN: 'report', FAIL: 'dangerous', INFO: 'info', SKIP: 'upcoming' }[status],
    }));

    return NextResponse.json({
      results,
      grouped_results,
      summary_cards: summaryCards,
      target_url: url,
      total_checks: results.length,
      ai_threat_report: threatReport,
      ai_metadata: metadata,
      ai_error: analysisError,
      scan_id,
      scan_mode: scanMode,
      risk_score: riskMeta.risk_score,
      risk_level: riskMeta.risk_level,
      verdict: riskMeta.verdict,
      duration_ms: durationMs,
      created_at: createdAt,
      ioc_count,
    });
  } catch (e) {
    return NextResponse.json({ error: `Failed to audit URL: ${String(e)}` }, { status: 500 });
  }
}
