export type CheckStatus = 'PASS' | 'WARN' | 'FAIL' | 'INFO';
export type RiskLevel = 'LOW' | 'MODERATE' | 'HIGH';
export type Verdict = 'BENIGN' | 'SUSPICIOUS' | 'MALICIOUS';

export interface CheckResult {
  id: number;
  name: string;
  status: CheckStatus;
  evidence: string;
  details?: string;
  data?: Record<string, any>;
  summary?: string;
  risk_level?: RiskLevel;
  section?: string;
}

export interface ThreatReport {
  executive_summary: string;
  key_findings: string[];
  verdict: Verdict;
  verdict_rationale: string;
  recommendations: string[];
}

export interface AIMetadata {
  generator: string;
  model: string;
  timestamp: string;
}

export interface AuditResponse {
  results: CheckResult[];
  summary_cards: SummaryCard[];
  target_url: string;
  input_url?: string;
  normalized_url?: string;
  resolved_url?: string;
  total_checks: number;
  ai_threat_report?: ThreatReport;
  ai_metadata?: AIMetadata;
  ai_error?: string;
  grouped_results?: GroupedResult[];
}

export interface SummaryCard {
  status: CheckStatus;
  count: number;
}

export interface GroupedResult {
  name: string;
  checks: CheckResult[];
}

export interface WebSocketMessage {
  type: 'start' | 'progress' | 'complete' | 'error';
  step?: number;
  total?: number;
  percent?: number;
  label?: string;
  message?: string;
}
