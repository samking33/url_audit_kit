'use client';

import { FormEvent, useMemo, useState } from 'react';

import { auditURL, createWebSocket } from '@/lib/api';
import type { AuditResponse, GroupedResult, WebSocketMessage } from '@/types';

const STATUS_ORDER = ['PASS', 'WARN', 'FAIL', 'INFO'] as const;

function toGroups(data: AuditResponse | null): GroupedResult[] {
  if (!data) {
    return [];
  }
  if (Array.isArray(data.grouped_results) && data.grouped_results.length > 0) {
    return data.grouped_results;
  }

  const grouped = new Map<string, GroupedResult>();
  for (const result of data.results || []) {
    const section = result.section || 'Additional Checks';
    if (!grouped.has(section)) {
      grouped.set(section, { name: section, checks: [] });
    }
    grouped.get(section)!.checks.push(result);
  }
  return Array.from(grouped.values());
}

function parseError(err: unknown): string {
  if (typeof err === 'string') {
    return err;
  }
  if (err && typeof err === 'object') {
    const maybe = err as {
      code?: string;
      message?: string;
      response?: { data?: { error?: string } };
    };
    const apiError = maybe.response?.data?.error;
    if (apiError) {
      return apiError;
    }
    const maybeMessage = maybe.message;
    if (maybe.code === 'ECONNABORTED' || maybeMessage?.toLowerCase().includes('timeout')) {
      return 'Audit is still running. Timeout removed for new requests. Please run the scan again.';
    }
    if (maybeMessage) {
      return maybeMessage;
    }
  }
  return 'Audit request failed.';
}

export default function HomePage() {
  const [url, setUrl] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [progressLabel, setProgressLabel] = useState('Idle');
  const [error, setError] = useState<string | null>(null);
  const [audit, setAudit] = useState<AuditResponse | null>(null);
  const [entered, setEntered] = useState(false);
  const [launching, setLaunching] = useState(false);

  const groupedResults = useMemo(() => toGroups(audit), [audit]);
  const summaryMap = useMemo(() => {
    const map = new Map<string, number>();
    for (const card of audit?.summary_cards || []) {
      map.set(card.status, card.count);
    }
    return map;
  }, [audit]);

  const handleEnterDashboard = () => {
    if (entered || launching) {
      return;
    }
    setLaunching(true);
    window.setTimeout(() => {
      setEntered(true);
      setLaunching(false);
    }, 980);
  };

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const target = url.trim();
    if (!target) {
      setError('Enter a URL to audit.');
      return;
    }

    setError(null);
    setAudit(null);
    setIsScanning(true);
    setProgress(0);
    setProgressLabel('Preparing audit');

    const jobId =
      typeof crypto !== 'undefined' && 'randomUUID' in crypto
        ? crypto.randomUUID()
        : `job-${Date.now()}`;

    let socket: WebSocket | null = null;
    try {
      socket = createWebSocket(jobId);
      socket.onmessage = (messageEvent) => {
        try {
          const payload = JSON.parse(messageEvent.data) as WebSocketMessage;
          if (payload.label) {
            setProgressLabel(payload.label);
          }
          if (typeof payload.percent === 'number') {
            setProgress(payload.percent);
          }
          if (payload.type === 'error' && payload.message) {
            setError(payload.message);
          }
        } catch {
          // Ignore malformed websocket payloads.
        }
      };
      socket.onerror = () => {
        setProgressLabel('Live progress unavailable. Running audit...');
      };

      const result = await auditURL(target, jobId);
      setAudit(result);
      setProgress(100);
      setProgressLabel('Audit complete');
    } catch (err) {
      setError(parseError(err));
    } finally {
      if (socket) {
        socket.close();
      }
      setIsScanning(false);
    }
  };

  return (
    <main className="neo-page">
      {!entered && (
        <section className={`launch-screen ${launching ? 'is-launching' : ''}`}>
          <div className="launch-panel neo-panel">
            <p className="launch-kicker">URL AUDIT KIT</p>
            <h1>Open Security Dashboard</h1>
            <p className="launch-subtitle">
              Click the globe to launch the main dashboard.
            </p>
            <button
              type="button"
              className={`launch-button ${launching ? 'is-launching' : ''}`}
              onClick={handleEnterDashboard}
              disabled={launching}
              aria-label="Launch URL Audit Kit dashboard"
            >
              <span className={`launch-globe ${launching ? 'is-spinning' : ''}`} aria-hidden="true">
                <span className="globe-line globe-line-h" />
                <span className="globe-line globe-line-h globe-line-h2" />
                <span className="globe-line globe-line-v" />
                <span className="globe-line globe-line-v globe-line-v2" />
                <span className="globe-core" />
              </span>
              <span className="launch-cta">{launching ? 'Launching...' : 'Enter Dashboard'}</span>
            </button>
          </div>
        </section>
      )}

      {entered && (
        <div className="dashboard-stage">
          <div className="neo-backdrop" aria-hidden="true" />
          <div className="neo-orb neo-orb-a" aria-hidden="true" />
          <div className="neo-orb neo-orb-b" aria-hidden="true" />
          <div className="neo-zig" aria-hidden="true" />

          <header className="neo-hero neo-panel">
            <p className="neo-kicker">Security Analysis Platform</p>
            <h1>URL AUDIT KIT</h1>
            <p className="neo-subtitle">
              Fast 41-check URL intelligence scanner with AI-assisted verdicting and actionable evidence.
            </p>
            <div className="neo-hero-chips">
              <span>41 Checks</span>
              <span>Live Progress</span>
              <span>AI Threat Report</span>
              <span>No Database Needed</span>
            </div>
          </header>

          <section className="neo-panel neo-about">
            <article>
              <h2>What This Tool Does</h2>
              <p>
                URL AUDIT KIT inspects domain intelligence, security posture, content integrity, reputation,
                and behavioral signals, then compiles a single threat report.
              </p>
            </article>
            <article>
              <h2>How It Works</h2>
              <p>
                Submit a URL, track progress live, and review per-check evidence plus an AI generated executive
                summary, findings, recommendations, and verdict.
              </p>
            </article>
            <article>
              <h2>Who It Helps</h2>
              <p>
                SOC analysts, incident responders, and security teams triaging suspicious links quickly before
                user impact.
              </p>
            </article>
          </section>

          <section className="neo-panel neo-form-panel">
            <form onSubmit={handleSubmit} className="neo-form">
              <label htmlFor="url-input">Target URL</label>
              <div className="neo-form-row">
                <input
                  id="url-input"
                  type="url"
                  value={url}
                  onChange={(event) => setUrl(event.target.value)}
                  placeholder="https://example.com/login"
                  required
                />
                <button type="submit" disabled={isScanning}>
                  {isScanning ? 'Scanning...' : 'Run Audit'}
                </button>
              </div>
            </form>

            <div className="neo-progress-shell">
              <div className="neo-progress-meta">
                <span>{progressLabel}</span>
                <strong>{progress}%</strong>
              </div>
              <div className="neo-progress-track">
                <div className="neo-progress-fill" style={{ width: `${progress}%` }} />
              </div>
            </div>
          </section>

          {error && (
            <section className="neo-panel neo-alert">
              <h2>Audit Error</h2>
              <p>{error}</p>
            </section>
          )}

          {audit && (
            <>
              <section className="neo-panel neo-target-meta">
                <p>
                  <strong>Input:</strong> {audit.input_url || audit.target_url}
                </p>
                <p>
                  <strong>Normalized:</strong> {audit.normalized_url || audit.target_url}
                </p>
                <p>
                  <strong>Resolved:</strong> {audit.resolved_url || audit.target_url}
                </p>
              </section>

              <section className="neo-summary-grid">
                {STATUS_ORDER.map((status) => (
                  <article key={status} className={`neo-panel neo-card neo-${status.toLowerCase()}`}>
                    <p className="neo-card-title">{status}</p>
                    <p className="neo-card-value">{summaryMap.get(status) || 0}</p>
                  </article>
                ))}
              </section>

              {audit.ai_threat_report && (
                <section className="neo-panel neo-report">
                  <h2>AI Threat Report</h2>
                  <p className="neo-report-summary">{audit.ai_threat_report.executive_summary}</p>
                  <div className="neo-report-grid">
                    <div>
                      <h3>Key Findings</h3>
                      <ul>
                        {(audit.ai_threat_report.key_findings || []).map((item) => (
                          <li key={item}>{item}</li>
                        ))}
                      </ul>
                    </div>
                    <div>
                      <h3>Recommendations</h3>
                      <ul>
                        {(audit.ai_threat_report.recommendations || []).map((item) => (
                          <li key={item}>{item}</li>
                        ))}
                      </ul>
                    </div>
                  </div>
                  <p className="neo-verdict">
                    Verdict: <strong>{audit.ai_threat_report.verdict}</strong>
                  </p>
                  <p>{audit.ai_threat_report.verdict_rationale}</p>
                  {audit.ai_metadata && (
                    <p className="neo-meta">
                      {audit.ai_metadata.generator} · {audit.ai_metadata.model} · {audit.ai_metadata.timestamp}
                    </p>
                  )}
                </section>
              )}

              <section className="neo-groups">
                {groupedResults.map((group, groupIndex) => (
                  <article
                    key={group.name}
                    className="neo-panel neo-group"
                    style={{ animationDelay: `${groupIndex * 0.08}s` }}
                  >
                    <h2>{group.name}</h2>
                    <div className="neo-check-list">
                      {group.checks.map((check) => (
                        <details key={`${group.name}-${check.id}-${check.name}`} className="neo-check-item">
                          <summary>
                            <span className={`neo-pill neo-${check.status.toLowerCase()}`}>{check.status}</span>
                            <span>{check.name}</span>
                          </summary>
                          <p>{check.summary || check.evidence || 'No evidence provided.'}</p>
                          {check.evidence && (
                            <p>
                              <strong>Evidence:</strong> {check.evidence}
                            </p>
                          )}
                          {check.details && (
                            <pre>{check.details}</pre>
                          )}
                        </details>
                      ))}
                    </div>
                  </article>
                ))}
              </section>
            </>
          )}
        </div>
      )}
    </main>
  );
}
