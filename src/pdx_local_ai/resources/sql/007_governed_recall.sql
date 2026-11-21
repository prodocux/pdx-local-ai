CREATE VIRTUAL TABLE IF NOT EXISTS governed_l2_fts USING fts5(
  content_contract_version UNINDEXED,
  target_id UNINDEXED,
  content,
  tokenize = 'unicode61'
);

CREATE VIRTUAL TABLE IF NOT EXISTS governed_l3_fts USING fts5(
  canonical_knowledge_id UNINDEXED,
  version_id UNINDEXED,
  content,
  tokenize = 'unicode61'
);

-- Migration reapplication deliberately rebuilds the independent replicas.
-- Source tables remain authoritative and insert triggers cover later writes.
DELETE FROM governed_l2_fts;
INSERT INTO governed_l2_fts(content_contract_version,target_id,content)
SELECT 'pdx_local_memory_record_v1',memory_id,content FROM memory_record;
INSERT INTO governed_l2_fts(content_contract_version,target_id,content)
SELECT 'pdx_local_memory_record_v2',memory_id,content FROM memory_record_v2;

DELETE FROM governed_l3_fts;
INSERT INTO governed_l3_fts(canonical_knowledge_id,version_id,content)
SELECT canonical_knowledge_id,version_id,content FROM canonical_knowledge_version;

CREATE TRIGGER IF NOT EXISTS governed_l2_v1_fts_insert
AFTER INSERT ON memory_record
BEGIN
  INSERT INTO governed_l2_fts(content_contract_version,target_id,content)
  VALUES ('pdx_local_memory_record_v1',NEW.memory_id,NEW.content);
END;

CREATE TRIGGER IF NOT EXISTS governed_l2_v2_fts_insert
AFTER INSERT ON memory_record_v2
BEGIN
  INSERT INTO governed_l2_fts(content_contract_version,target_id,content)
  VALUES ('pdx_local_memory_record_v2',NEW.memory_id,NEW.content);
END;

CREATE TRIGGER IF NOT EXISTS governed_l3_fts_insert
AFTER INSERT ON canonical_knowledge_version
BEGIN
  INSERT INTO governed_l3_fts(canonical_knowledge_id,version_id,content)
  VALUES (NEW.canonical_knowledge_id,NEW.version_id,NEW.content);
END;

CREATE TABLE IF NOT EXISTS governed_recall_receipt (
  receipt_id TEXT PRIMARY KEY,
  query_id TEXT NOT NULL,
  workspace_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  requested_layer TEXT NOT NULL CHECK (requested_layer IN ('l2','l3')),
  receipt_json TEXT NOT NULL CHECK (json_valid(receipt_json)),
  receipt_sha256 TEXT NOT NULL CHECK (
    length(receipt_sha256)=64 AND receipt_sha256 NOT GLOB '*[^0-9a-f]*'
  ),
  created_at TEXT NOT NULL,
  UNIQUE (workspace_id, principal_id, query_id)
);

CREATE TRIGGER IF NOT EXISTS governed_recall_receipt_update_forbidden
BEFORE UPDATE ON governed_recall_receipt
BEGIN SELECT RAISE(ABORT, 'governed recall receipt is append-only'); END;

CREATE TRIGGER IF NOT EXISTS governed_recall_receipt_delete_forbidden
BEFORE DELETE ON governed_recall_receipt
BEGIN SELECT RAISE(ABORT, 'governed recall receipt is append-only'); END;
