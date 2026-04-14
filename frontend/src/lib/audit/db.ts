/**
 * SQLite database layer using better-sqlite3.
 * Schema mirrors the Python webapp/persistence.py exactly.
 */
import Database from 'better-sqlite3';
import * as path from 'path';
import * as fs from 'fs';

function dbPath(): string {
  const env = process.env.URL_AUDIT_DB_PATH?.trim();
  if (env) return env;
  // Default: <project-root>/data/url_audit.db
  // process.cwd() when running from root package.json wrapper is project root
  const dir = path.join(process.cwd(), 'data');
  return path.join(dir, 'url_audit.db');
}

let _db: Database.Database | null = null;

export function getDb(): Database.Database {
  if (_db) return _db;
  const p = dbPath();
  fs.mkdirSync(path.dirname(p), { recursive: true });
  _db = new Database(p);
  _db.pragma('foreign_keys = ON');
  _db.pragma('journal_mode = WAL');
  initSchema(_db);
  return _db;
}

function initSchema(db: Database.Database): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS scans (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      target_url TEXT NOT NULL,
      scan_mode TEXT NOT NULL DEFAULT 'scan',
      risk_score INTEGER NOT NULL,
      risk_level TEXT NOT NULL,
      verdict TEXT NOT NULL,
      total_checks INTEGER NOT NULL,
      pass_count INTEGER NOT NULL DEFAULT 0,
      warn_count INTEGER NOT NULL DEFAULT 0,
      fail_count INTEGER NOT NULL DEFAULT 0,
      info_count INTEGER NOT NULL DEFAULT 0,
      skip_count INTEGER NOT NULL DEFAULT 0,
      ai_verdict TEXT,
      ai_summary TEXT,
      threat_report_json TEXT,
      duration_ms INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS scan_checks (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      scan_id INTEGER NOT NULL,
      check_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      status TEXT NOT NULL,
      risk_level TEXT,
      section TEXT,
      evidence TEXT,
      details TEXT,
      data_json TEXT,
      summary TEXT,
      FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS iocs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      scan_id INTEGER NOT NULL,
      indicator TEXT NOT NULL,
      indicator_type TEXT NOT NULL,
      severity TEXT NOT NULL,
      source_check TEXT NOT NULL,
      country TEXT,
      created_at TEXT NOT NULL,
      FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at);
    CREATE INDEX IF NOT EXISTS idx_scans_risk_level ON scans(risk_level);
    CREATE INDEX IF NOT EXISTS idx_scans_verdict ON scans(verdict);
    CREATE INDEX IF NOT EXISTS idx_scan_checks_scan_id ON scan_checks(scan_id);
    CREATE INDEX IF NOT EXISTS idx_iocs_scan_id ON iocs(scan_id);
    CREATE INDEX IF NOT EXISTS idx_iocs_severity ON iocs(severity);
    CREATE INDEX IF NOT EXISTS idx_iocs_country ON iocs(country);
  `);
}
