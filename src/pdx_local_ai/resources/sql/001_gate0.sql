PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS source_root (
  source_root_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  canonical_path TEXT NOT NULL,
  enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
  config_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE (workspace_id, canonical_path)
);

CREATE TABLE IF NOT EXISTS file_record (
  file_record_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  source_root_id TEXT NOT NULL REFERENCES source_root(source_root_id),
  relative_path TEXT NOT NULL,
  media_type TEXT NOT NULL,
  catalog_status TEXT NOT NULL CHECK (catalog_status IN ('active', 'missing', 'deleted')),
  volume_identity TEXT,
  file_identity TEXT,
  current_source_version_id TEXT,
  last_reconciled_at TEXT NOT NULL,
  UNIQUE (source_root_id, relative_path)
);

CREATE TABLE IF NOT EXISTS index_attempt (
  index_attempt_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  source_root_id TEXT NOT NULL,
  file_record_id TEXT,
  relative_path TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending','running','succeeded','retryable_failed','terminal_failed','stale')),
  attempt_number INTEGER NOT NULL CHECK (attempt_number >= 1),
  observed_source_version_id TEXT,
  failure_code TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS source_version (
  source_version_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  source_root_id TEXT NOT NULL,
  file_record_id TEXT NOT NULL REFERENCES file_record(file_record_id),
  source_sha256 TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  observed_mtime_ns INTEGER NOT NULL,
  volume_identity TEXT,
  file_identity TEXT,
  processing_status TEXT NOT NULL CHECK (processing_status IN ('indexed','unsupported','failed')),
  coverage_disposition TEXT NOT NULL CHECK (coverage_disposition IN ('complete','partial_known','partial_unknown','not_evaluated')),
  unknown_remainder INTEGER NOT NULL CHECK (unknown_remainder IN (0, 1)),
  disclosure_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  CHECK ((coverage_disposition = 'partial_unknown' AND unknown_remainder = 1)
      OR (coverage_disposition != 'partial_unknown' AND unknown_remainder = 0)),
  UNIQUE (file_record_id, source_sha256)
);

CREATE TABLE IF NOT EXISTS projection (
  projection_id TEXT PRIMARY KEY,
  source_version_id TEXT NOT NULL UNIQUE REFERENCES source_version(source_version_id),
  source_sha256 TEXT NOT NULL,
  parser_contract_name TEXT NOT NULL,
  parser_contract_version TEXT NOT NULL,
  kernel_version TEXT NOT NULL,
  block_count INTEGER NOT NULL,
  kernel_output_sha256 TEXT NOT NULL,
  provenance_json TEXT NOT NULL,
  provenance_digest TEXT NOT NULL,
  published_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS block_instance (
  block_instance_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  source_version_id TEXT NOT NULL REFERENCES source_version(source_version_id),
  projection_id TEXT NOT NULL REFERENCES projection(projection_id),
  ordinal INTEGER NOT NULL,
  block_type TEXT NOT NULL,
  text TEXT NOT NULL,
  text_sha256 TEXT NOT NULL,
  locator_kind TEXT NOT NULL,
  locator_value TEXT NOT NULL,
  UNIQUE (projection_id, ordinal)
);

CREATE VIRTUAL TABLE IF NOT EXISTS block_fts USING fts5(
  block_instance_id UNINDEXED,
  text,
  tokenize = 'unicode61'
);

CREATE TABLE IF NOT EXISTS file_acl (
  workspace_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  file_record_id TEXT NOT NULL REFERENCES file_record(file_record_id),
  can_read INTEGER NOT NULL CHECK (can_read IN (0, 1)),
  PRIMARY KEY (workspace_id, principal_id, file_record_id)
);

CREATE TABLE IF NOT EXISTS citation (
  citation_id TEXT PRIMARY KEY,
  query_id TEXT NOT NULL,
  workspace_id TEXT NOT NULL,
  source_root_id TEXT NOT NULL,
  file_record_id TEXT NOT NULL,
  source_version_id TEXT NOT NULL,
  source_sha256 TEXT NOT NULL,
  projection_id TEXT NOT NULL,
  parser_contract_name TEXT NOT NULL,
  parser_contract_version TEXT NOT NULL,
  block_instance_id TEXT NOT NULL,
  locator_kind TEXT NOT NULL,
  locator_value TEXT NOT NULL,
  quote_start INTEGER NOT NULL,
  quote_end INTEGER NOT NULL,
  quote_normalization TEXT NOT NULL,
  quoted_text_sha256 TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS retrieval_receipt (
  receipt_id TEXT PRIMARY KEY,
  query_id TEXT NOT NULL,
  workspace_id TEXT NOT NULL,
  receipt_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);
