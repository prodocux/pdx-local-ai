CREATE TABLE IF NOT EXISTS layered_session (
  workspace_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('open','closed')),
  created_at TEXT NOT NULL,
  closed_at TEXT,
  PRIMARY KEY (workspace_id, principal_id, session_id)
);

CREATE TABLE IF NOT EXISTS session_memory_item (
  session_item_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  content TEXT NOT NULL,
  content_sha256 TEXT NOT NULL,
  provenance_category TEXT NOT NULL CHECK (provenance_category IN ('user_stated','document_grounded','model_proposed')),
  verification_status TEXT NOT NULL CHECK (verification_status IN ('unverified','user_asserted','citation_verified')),
  source_citation_id TEXT REFERENCES citation(citation_id),
  state TEXT NOT NULL CHECK (state IN ('captured','promoted','expired','discarded')),
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  FOREIGN KEY (workspace_id, principal_id, session_id)
    REFERENCES layered_session(workspace_id, principal_id, session_id)
);

CREATE INDEX IF NOT EXISTS session_memory_recall_scope
ON session_memory_item(workspace_id, principal_id, session_id, state, expires_at);

CREATE TABLE IF NOT EXISTS working_memory (
  working_memory_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  scope_id TEXT NOT NULL,
  content TEXT NOT NULL,
  content_sha256 TEXT NOT NULL,
  provenance_category TEXT NOT NULL CHECK (provenance_category IN ('user_stated','document_grounded','model_proposed')),
  verification_status TEXT NOT NULL CHECK (verification_status IN ('unverified','user_asserted','citation_verified')),
  source_citation_id TEXT REFERENCES citation(citation_id),
  source_session_item_id TEXT NOT NULL UNIQUE REFERENCES session_memory_item(session_item_id),
  state TEXT NOT NULL CHECK (state IN ('active','expired','retracted')),
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS working_memory_recall_scope
ON working_memory(workspace_id, principal_id, scope_id, state, expires_at);

CREATE TABLE IF NOT EXISTS memory_promotion_receipt (
  promotion_receipt_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  request_fingerprint TEXT NOT NULL,
  session_item_id TEXT NOT NULL REFERENCES session_memory_item(session_item_id),
  working_memory_id TEXT NOT NULL REFERENCES working_memory(working_memory_id),
  receipt_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE(workspace_id, principal_id, idempotency_key)
);

CREATE TABLE IF NOT EXISTS layered_recall_receipt (
  receipt_id TEXT PRIMARY KEY,
  query_id TEXT NOT NULL,
  workspace_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  receipt_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);
