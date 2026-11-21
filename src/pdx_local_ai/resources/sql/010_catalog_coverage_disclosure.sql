CREATE TABLE IF NOT EXISTS catalog_coverage_disclosure (
  disclosure_id TEXT PRIMARY KEY NOT NULL,
  catalog_receipt_id TEXT NOT NULL UNIQUE REFERENCES retrieval_receipt(receipt_id),
  catalog_query_id TEXT NOT NULL,
  workspace_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  source_root_id TEXT NOT NULL,
  catalog_receipt_sha256 TEXT NOT NULL CHECK (
    length(catalog_receipt_sha256) = 64 AND catalog_receipt_sha256 NOT GLOB '*[^0-9a-f]*'
  ),
  disclosure_json TEXT NOT NULL CHECK (json_valid(disclosure_json)),
  disclosure_sha256 TEXT NOT NULL CHECK (
    length(disclosure_sha256) = 64 AND disclosure_sha256 NOT GLOB '*[^0-9a-f]*'
  ),
  created_at TEXT NOT NULL,
  UNIQUE (workspace_id, catalog_query_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS catalog_coverage_disclosure_one_receipt
  ON catalog_coverage_disclosure(catalog_receipt_id);

CREATE TRIGGER IF NOT EXISTS catalog_coverage_disclosure_update_forbidden
BEFORE UPDATE ON catalog_coverage_disclosure
BEGIN
  SELECT RAISE(ABORT, 'catalog coverage disclosure is append-only');
END;

CREATE TRIGGER IF NOT EXISTS catalog_coverage_disclosure_delete_forbidden
BEFORE DELETE ON catalog_coverage_disclosure
BEGIN
  SELECT RAISE(ABORT, 'catalog coverage disclosure is append-only');
END;

CREATE TRIGGER IF NOT EXISTS catalog_coverage_disclosure_insert_binding
BEFORE INSERT ON catalog_coverage_disclosure
WHEN json_extract(NEW.disclosure_json, '$.catalog_receipt_id') IS NOT NEW.catalog_receipt_id
  OR json_extract(NEW.disclosure_json, '$.catalog_query_id') IS NOT NEW.catalog_query_id
  OR json_extract(NEW.disclosure_json, '$.workspace_id') IS NOT NEW.workspace_id
  OR json_extract(NEW.disclosure_json, '$.principal_id') IS NOT NEW.principal_id
  OR json_extract(NEW.disclosure_json, '$.source_root_id') IS NOT NEW.source_root_id
  OR json_extract(NEW.disclosure_json, '$.catalog_receipt_sha256') IS NOT NEW.catalog_receipt_sha256
  OR NOT EXISTS (
    SELECT 1 FROM retrieval_receipt
    WHERE receipt_id = NEW.catalog_receipt_id
      AND query_id = NEW.catalog_query_id
      AND workspace_id = NEW.workspace_id
  )
BEGIN
  SELECT RAISE(ABORT, 'catalog coverage disclosure binding mismatch');
END;
