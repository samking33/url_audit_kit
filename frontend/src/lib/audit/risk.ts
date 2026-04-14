import type { CheckResult } from './checks';

const STATUS_POINTS: Record<string, number> = {
  PASS: 0,
  INFO: 1,
  WARN: 4,
  FAIL: 8,
  SKIP: 0,
};

const CRITICAL_FAIL_BONUS = 12;

const CRITICAL_CHECK_KEYWORDS = ['ssl', 'https', 'blacklist', 'virus total', 'virustotal', 'safe browsing', 'ip reputation', 'certificate issuer'];

function isCriticalCheck(name: string): boolean {
  const lower = (name || '').toLowerCase();
  return CRITICAL_CHECK_KEYWORDS.some((k) => lower.includes(k));
}

export function riskLevelFromScore(score: number): string {
  if (score >= 75) return 'CRITICAL';
  if (score >= 50) return 'HIGH';
  if (score >= 25) return 'MEDIUM';
  return 'LOW';
}

export function verdictFromRiskLevel(riskLevel: string): string {
  const level = (riskLevel || '').toUpperCase();
  if (level === 'HIGH' || level === 'CRITICAL') return 'MALICIOUS';
  if (level === 'MEDIUM') return 'SUSPICIOUS';
  return 'BENIGN';
}

export function computeRisk(checks: Array<{ name: string; status: string }>): {
  risk_score: number;
  risk_level: string;
  verdict: string;
  points: number;
  max_points: number;
  critical_failures: string[];
} {
  let totalPoints = 0;
  let maxPoints = 0;
  const criticalFailures: string[] = [];

  for (const check of checks) {
    const status = (check.status || 'WARN').toUpperCase();
    const name = check.name || '';
    const critical = isCriticalCheck(name);

    const basePoints = STATUS_POINTS[status] ?? STATUS_POINTS['WARN'];
    const critBonus = critical && status === 'FAIL' ? CRITICAL_FAIL_BONUS : 0;

    totalPoints += basePoints + critBonus;
    maxPoints += STATUS_POINTS['FAIL'] + (critical ? CRITICAL_FAIL_BONUS : 0);

    if (critBonus) criticalFailures.push(name);
  }

  const normalizedScore = Math.round((totalPoints / Math.max(maxPoints, 1)) * 100);
  const riskScore = Math.max(0, Math.min(100, normalizedScore));
  const riskLevel = riskLevelFromScore(riskScore);
  const verdict = verdictFromRiskLevel(riskLevel);

  return { risk_score: riskScore, risk_level: riskLevel, verdict, points: totalPoints, max_points: maxPoints, critical_failures: criticalFailures };
}
