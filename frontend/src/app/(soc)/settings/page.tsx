'use client';

import { useEffect, useState } from 'react';
import { getDashboardOverview } from '@/lib/api';

export default function SettingsPage() {
  const [status, setStatus] = useState('Checking API health...');

  useEffect(() => {
    getDashboardOverview('24h')
      .then(() => setStatus('Operational'))
      .catch(() => setStatus('Degraded'));
  }, []);

  return (
    <div className="page-grid">
      <section className="page-heading">
        <div>
          <h1>Settings</h1>
        </div>
      </section>

      <section className="report-grid">
        <article className="panel">
          <h2>System Health</h2>
          <ul className="details-list">
            <li>
              <span>API Runtime</span>
              <span>{status}</span>
            </li>
            <li>
              <span>Frontend Runtime</span>
              <span>Operational</span>
            </li>
            <li>
              <span>Persistence</span>
              <span>SQLite</span>
            </li>
          </ul>
        </article>

        <article className="panel">
          <h2>Endpoint Configuration</h2>
          <ul className="details-list">
            <li>
              <span>API Routes</span>
              <code>/api/* → Next.js route handlers</code>
            </li>
            <li>
              <span>Deployment Mode</span>
              <code>Single Node.js application</code>
            </li>
            <li>
              <span>Frontend URL</span>
              <code>{typeof window !== 'undefined' ? window.location.origin : 'http://localhost:3000'}</code>
            </li>
          </ul>
        </article>
      </section>

      <section className="panel">
        <h2>SOC Theme Profile</h2>
        <p>
          Dark cybersecurity theme is enforced as the default enterprise profile. Accent colors and contrast values
          are optimized for prolonged SOC workflows.
        </p>
      </section>
    </div>
  );
}
