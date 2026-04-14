import type {
  AuditResponse,
  DashboardOverview,
  IOCRecord,
  PagedResponse,
  ScanMode,
  ScanRecord,
  ThreatMapPoint,
} from '@/types';

export interface RunAuditOptions {
  url: string;
  scanMode: ScanMode;
  onProgress?: (percent: number, label: string) => void;
}

async function fetchJSON<T>(path: string): Promise<T> {
  const response = await fetch(path, { method: 'GET', cache: 'no-store' });
  if (!response.ok) throw new Error(`Request failed (${response.status})`);
  return response.json();
}

export async function runAudit(options: RunAuditOptions): Promise<AuditResponse> {
  const formData = new FormData();
  formData.append('url', options.url);
  formData.append('scan_mode', options.scanMode);

  // Simulate progress animation while waiting for the server
  let pct = 0;
  const progressTimer = setInterval(() => {
    if (pct < 90) {
      pct = Math.min(90, pct + Math.random() * 4 + 1);
      options.onProgress?.(Math.round(pct), 'Analyzing...');
    }
  }, 800);

  try {
    const response = await fetch('/api/audit', { method: 'POST', body: formData });
    clearInterval(progressTimer);
    if (!response.ok) throw new Error(`Audit failed (${response.status})`);
    options.onProgress?.(100, 'Complete');
    return (await response.json()) as AuditResponse;
  } catch (e) {
    clearInterval(progressTimer);
    throw e;
  }
}

export async function getDashboardOverview(range: string): Promise<DashboardOverview> {
  return fetchJSON<DashboardOverview>(`/api/dashboard/overview?range=${encodeURIComponent(range)}`);
}

export async function getScans(params: {
  page: number; pageSize: number; q: string; risk: string;
  status: string; sortBy: string; sortOrder: 'asc' | 'desc';
}): Promise<PagedResponse<ScanRecord>> {
  const searchParams = new URLSearchParams({
    page: String(params.page),
    page_size: String(params.pageSize),
    q: params.q,
    risk: params.risk,
    status: params.status,
    sort_by: params.sortBy,
    sort_order: params.sortOrder,
  });
  return fetchJSON<PagedResponse<ScanRecord>>(`/api/scans?${searchParams}`);
}

export async function getScan(scanId: number): Promise<ScanRecord & { checks: unknown[]; iocs: IOCRecord[] }> {
  return fetchJSON(`/api/scans/${scanId}`);
}

export async function getScanReport(scanId: number): Promise<unknown> {
  return fetchJSON(`/api/scans/${scanId}/report`);
}

export async function getIOCs(params: {
  page: number; pageSize: number; q: string; type: string; severity: string;
  sortBy: string; sortOrder: 'asc' | 'desc';
}): Promise<PagedResponse<IOCRecord>> {
  const searchParams = new URLSearchParams({
    page: String(params.page),
    page_size: String(params.pageSize),
    q: params.q,
    type: params.type,
    severity: params.severity,
    sort_by: params.sortBy,
    sort_order: params.sortOrder,
  });
  return fetchJSON<PagedResponse<IOCRecord>>(`/api/iocs?${searchParams}`);
}

export async function getThreatMap(range: string): Promise<{ points: ThreatMapPoint[] }> {
  return fetchJSON(`/api/threat-intelligence/map?range=${encodeURIComponent(range)}`);
}

export async function getThreatDomains(limit = 20): Promise<{ items: Array<{ domain: string; hits: number; last_seen: string }> }> {
  return fetchJSON(`/api/threat-intelligence/domains?limit=${limit}`);
}

export async function getThreatIpReputation(limit = 20): Promise<{ items: Array<{ ip: string; sightings: number; critical_hits: number; high_hits: number; medium_hits: number; last_seen: string }> }> {
  return fetchJSON(`/api/threat-intelligence/ip-reputation?limit=${limit}`);
}
