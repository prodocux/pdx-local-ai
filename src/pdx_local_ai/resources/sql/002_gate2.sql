PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS reconciliation_run (
  reconciliation_run_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  source_root_id TEXT NOT NULL REFERENCES source_root(source_root_id),
  status TEXT NOT NULL CHECK (status IN ('running','succeeded','failed')),
  resumed_count INTEGER NOT NULL DEFAULT 0 CHECK (resumed_count >= 0),
  stale_retry_limit INTEGER NOT NULL CHECK (stale_retry_limit >= 0),
  missing_retention_runs INTEGER NOT NULL CHECK (missing_retention_runs >= 1),
  result_json TEXT,
  failure_code TEXT,
  started_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  completed_at TEXT
);

CREATE TABLE IF NOT EXISTS file_maintenance (
  file_record_id TEXT PRIMARY KEY REFERENCES file_record(file_record_id),
  consecutive_missing_runs INTEGER NOT NULL DEFAULT 0
    CHECK (consecutive_missing_runs >= 0),
  first_missing_at TEXT,
  last_seen_run_id TEXT REFERENCES reconciliation_run(reconciliation_run_id),
  deleted_at TEXT
);

CREATE INDEX IF NOT EXISTS reconciliation_run_root_status
  ON reconciliation_run(source_root_id, status, updated_at);

CREATE UNIQUE INDEX IF NOT EXISTS reconciliation_one_running_per_root
  ON reconciliation_run(source_root_id) WHERE status = 'running';
