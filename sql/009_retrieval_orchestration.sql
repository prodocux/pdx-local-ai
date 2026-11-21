CREATE TABLE IF NOT EXISTS retrieval_stage_receipt (
  stage_receipt_id TEXT PRIMARY KEY NOT NULL,
  workspace_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  request_id TEXT NOT NULL,
  query_id TEXT NOT NULL,
  stage TEXT NOT NULL,
  disposition TEXT NOT NULL,
  envelope TEXT NOT NULL CHECK (json_valid(envelope)),
  envelope_sha256 TEXT NOT NULL CHECK (
    length(envelope_sha256) = 64 AND envelope_sha256 NOT GLOB '*[^0-9a-f]*'
  ),
  created_at TEXT NOT NULL,
  UNIQUE (workspace_id, principal_id, request_id, query_id, stage)
);

CREATE TRIGGER IF NOT EXISTS retrieval_stage_receipt_update_forbidden
BEFORE UPDATE ON retrieval_stage_receipt
BEGIN SELECT RAISE(ABORT, 'stage receipt is append-only'); END;

CREATE TRIGGER IF NOT EXISTS retrieval_stage_receipt_delete_forbidden
BEFORE DELETE ON retrieval_stage_receipt
BEGIN SELECT RAISE(ABORT, 'stage receipt is append-only'); END;

CREATE TABLE IF NOT EXISTS retrieval_orchestration_receipt (
  receipt_id TEXT PRIMARY KEY NOT NULL,
  workspace_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  request_id TEXT NOT NULL,
  query_id TEXT NOT NULL,
  envelope TEXT NOT NULL CHECK (json_valid(envelope)),
  envelope_sha256 TEXT NOT NULL CHECK (
    length(envelope_sha256) = 64 AND envelope_sha256 NOT GLOB '*[^0-9a-f]*'
  ),
  created_at TEXT NOT NULL,
  UNIQUE (workspace_id, principal_id, query_id),
  UNIQUE (workspace_id, principal_id, request_id)
);

CREATE TRIGGER IF NOT EXISTS retrieval_orchestration_receipt_update_forbidden
BEFORE UPDATE ON retrieval_orchestration_receipt
BEGIN SELECT RAISE(ABORT, 'orchestration receipt is append-only'); END;

CREATE TRIGGER IF NOT EXISTS retrieval_orchestration_receipt_delete_forbidden
BEFORE DELETE ON retrieval_orchestration_receipt
BEGIN SELECT RAISE(ABORT, 'orchestration receipt is append-only'); END;

CREATE TABLE IF NOT EXISTS retrieval_orchestration_stage_link (
  receipt_id TEXT NOT NULL REFERENCES retrieval_orchestration_receipt(receipt_id),
  stage_receipt_id TEXT NOT NULL REFERENCES retrieval_stage_receipt(stage_receipt_id),
  stage_ordinal INTEGER NOT NULL CHECK (stage_ordinal >= 0),
  envelope_sha256 TEXT NOT NULL,
  PRIMARY KEY (receipt_id, stage_receipt_id),
  UNIQUE (receipt_id, stage_ordinal)
);

CREATE TRIGGER IF NOT EXISTS retrieval_orchestration_stage_link_scope
BEFORE INSERT ON retrieval_orchestration_stage_link
BEGIN
  SELECT RAISE(ABORT, 'stage link scope')
  WHERE NOT EXISTS (
    SELECT 1
    FROM retrieval_stage_receipt s
    JOIN retrieval_orchestration_receipt r ON r.receipt_id = NEW.receipt_id
    WHERE s.stage_receipt_id = NEW.stage_receipt_id
      AND s.workspace_id = r.workspace_id
      AND s.principal_id = r.principal_id
      AND s.request_id = r.request_id
      AND s.query_id = r.query_id
      AND s.envelope_sha256 = NEW.envelope_sha256
  );
END;

CREATE TRIGGER IF NOT EXISTS retrieval_orchestration_stage_link_update_forbidden
BEFORE UPDATE ON retrieval_orchestration_stage_link
BEGIN SELECT RAISE(ABORT, 'stage link is append-only'); END;

CREATE TRIGGER IF NOT EXISTS retrieval_orchestration_stage_link_delete_forbidden
BEFORE DELETE ON retrieval_orchestration_stage_link
BEGIN SELECT RAISE(ABORT, 'stage link is append-only'); END;

CREATE TABLE IF NOT EXISTS retrieval_orchestration_query_id (
  workspace_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  query_id TEXT NOT NULL,
  receipt_id TEXT NOT NULL REFERENCES retrieval_orchestration_receipt(receipt_id),
  PRIMARY KEY (workspace_id, principal_id, query_id)
);

CREATE TRIGGER IF NOT EXISTS retrieval_orchestration_query_id_binding
BEFORE INSERT ON retrieval_orchestration_query_id
BEGIN
  SELECT RAISE(ABORT, 'consumed query id binding')
  WHERE NOT EXISTS (
    SELECT 1 FROM retrieval_orchestration_receipt r
    WHERE r.receipt_id = NEW.receipt_id
      AND r.workspace_id = NEW.workspace_id
      AND r.principal_id = NEW.principal_id
      AND r.query_id = NEW.query_id
      AND json_array_length(r.envelope, '$.stage_receipt_ids')
        = json_array_length(r.envelope, '$.stage_receipt_sha256s')
      AND json_array_length(r.envelope, '$.stage_receipt_ids') = (
        SELECT COUNT(*) FROM retrieval_orchestration_stage_link l
        WHERE l.receipt_id = r.receipt_id
      )
      AND NOT EXISTS (
        SELECT 1
        FROM retrieval_orchestration_stage_link l
        WHERE l.receipt_id = r.receipt_id
          AND (
            json_extract(r.envelope, '$.stage_receipt_ids[' || l.stage_ordinal || ']')
              IS NOT l.stage_receipt_id
            OR json_extract(r.envelope, '$.stage_receipt_sha256s[' || l.stage_ordinal || ']')
              IS NOT l.envelope_sha256
          )
      )
  );
END;

CREATE TRIGGER IF NOT EXISTS retrieval_orchestration_query_id_update_forbidden
BEFORE UPDATE ON retrieval_orchestration_query_id
BEGIN SELECT RAISE(ABORT, 'consumed query id is append-only'); END;

CREATE TRIGGER IF NOT EXISTS retrieval_orchestration_query_id_delete_forbidden
BEFORE DELETE ON retrieval_orchestration_query_id
BEGIN SELECT RAISE(ABORT, 'consumed query id is append-only'); END;
