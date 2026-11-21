PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS source_root_coverage (
  workspace_id TEXT NOT NULL,
  source_root_id TEXT NOT NULL REFERENCES source_root(source_root_id),
  last_scan_completed_at TEXT,
  last_scan_succeeded_at TEXT,
  last_full_coverage_at TEXT,
  unsupported_count INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (workspace_id, source_root_id)
);

CREATE INDEX IF NOT EXISTS source_root_coverage_root_idx
  ON source_root_coverage(source_root_id);
