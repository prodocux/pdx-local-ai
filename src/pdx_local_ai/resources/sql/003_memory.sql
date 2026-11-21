CREATE TABLE IF NOT EXISTS memory_record (
  memory_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  memory_kind TEXT NOT NULL CHECK (memory_kind IN ('fact','preference','decision','task','note')),
  content TEXT NOT NULL,
  content_sha256 TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('active','superseded','retracted')),
  confidence REAL NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
  salience REAL NOT NULL CHECK (salience >= 0 AND salience <= 1),
  source_citation_id TEXT NOT NULL REFERENCES citation(citation_id),
  supersedes_memory_id TEXT REFERENCES memory_record(memory_id),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS memory_scope_status
ON memory_record(workspace_id, principal_id, status, updated_at);

CREATE VIRTUAL TABLE IF NOT EXISTS memory_fts USING fts5(
  memory_id UNINDEXED,
  content,
  tokenize = 'unicode61'
);

CREATE TABLE IF NOT EXISTS memory_embedding (
  memory_id TEXT PRIMARY KEY REFERENCES memory_record(memory_id),
  adapter_id TEXT NOT NULL,
  dimensions INTEGER NOT NULL CHECK (dimensions > 0),
  vector_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS memory_event (
  event_id TEXT PRIMARY KEY,
  memory_id TEXT NOT NULL REFERENCES memory_record(memory_id),
  workspace_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  event_type TEXT NOT NULL CHECK (event_type IN ('created','superseded','retracted')),
  event_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS memory_recall_receipt (
  receipt_id TEXT PRIMARY KEY,
  query_id TEXT NOT NULL,
  workspace_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  receipt_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS block_embedding (
  block_instance_id TEXT PRIMARY KEY REFERENCES block_instance(block_instance_id),
  source_version_id TEXT NOT NULL,
  adapter_id TEXT NOT NULL,
  dimensions INTEGER NOT NULL CHECK (dimensions > 0),
  vector_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS block_embedding_adapter
ON block_embedding(adapter_id, source_version_id);
