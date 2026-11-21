-- Gate 5A-0 text intake storage. Not part of Catalog SQL_FILES.

CREATE TABLE IF NOT EXISTS source_projection_owner (
  source_version_id TEXT PRIMARY KEY REFERENCES source_version(source_version_id),
  owner TEXT NOT NULL CHECK (owner IN ('prodocux', 'pdx-local-ai')),
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS text_projection (
  projection_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  source_root_id TEXT NOT NULL,
  file_record_id TEXT NOT NULL REFERENCES file_record(file_record_id),
  source_version_id TEXT NOT NULL UNIQUE REFERENCES source_version(source_version_id),
  source_sha256 TEXT NOT NULL,
  parser_contract_name TEXT NOT NULL CHECK (parser_contract_name = 'pdx_local_text_decoder'),
  parser_contract_version TEXT NOT NULL CHECK (parser_contract_version = '1'),
  distribution TEXT NOT NULL CHECK (distribution = 'pdx-local-ai'),
  distribution_version TEXT NOT NULL CHECK (distribution_version = 'pdx_local_text_projection_v1'),
  decoder_profile TEXT NOT NULL CHECK (decoder_profile IN ('utf-8', 'utf-8-bom', 'utf-16-le-bom', 'utf-16-be-bom')),
  normalization_profile TEXT NOT NULL CHECK (normalization_profile = 'pdx_local_text_normalization_nfc_v1'),
  block_count INTEGER NOT NULL CHECK (block_count >= 0),
  locator_contract_version TEXT NOT NULL CHECK (locator_contract_version = 'text_line_codepoint_v1'),
  published_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS text_block_instance (
  block_instance_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  projection_id TEXT NOT NULL REFERENCES text_projection(projection_id),
  source_version_id TEXT NOT NULL,
  ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
  text TEXT NOT NULL,
  text_sha256 TEXT NOT NULL,
  UNIQUE (projection_id, ordinal)
);

CREATE VIRTUAL TABLE IF NOT EXISTS text_block_fts USING fts5(
  block_instance_id UNINDEXED,
  text,
  tokenize = 'unicode61'
);

CREATE TABLE IF NOT EXISTS text_fts_binding (
  block_instance_id TEXT PRIMARY KEY REFERENCES text_block_instance(block_instance_id),
  projection_id TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS text_source_range (
  block_instance_id TEXT PRIMARY KEY REFERENCES text_block_instance(block_instance_id),
  locator_contract TEXT NOT NULL CHECK (locator_contract = 'text_line_codepoint_v1'),
  workspace_id TEXT NOT NULL,
  projection_id TEXT NOT NULL,
  line_start INTEGER NOT NULL CHECK (line_start >= 1),
  line_end_exclusive INTEGER NOT NULL CHECK (line_end_exclusive > line_start),
  source_codepoint_start INTEGER NOT NULL CHECK (source_codepoint_start >= 0),
  source_codepoint_end_exclusive INTEGER NOT NULL CHECK (source_codepoint_end_exclusive >= source_codepoint_start)
);

CREATE TABLE IF NOT EXISTS text_coverage_disclosure (
  disclosure_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  source_root_id TEXT NOT NULL,
  file_record_id TEXT NOT NULL,
  source_version_id TEXT NOT NULL,
  projection_id TEXT NOT NULL UNIQUE REFERENCES text_projection(projection_id),
  coverage_disposition TEXT NOT NULL CHECK (coverage_disposition IN ('complete', 'partial_known', 'partial_unknown')),
  unknown_remainder INTEGER NOT NULL CHECK (unknown_remainder IN (0, 1)),
  encoding TEXT NOT NULL CHECK (encoding IN ('utf-8', 'utf-8-bom', 'utf-16-le-bom', 'utf-16-be-bom')),
  bom_removed INTEGER NOT NULL CHECK (bom_removed IN (0, 1)),
  normalization_profile TEXT NOT NULL CHECK (normalization_profile = 'pdx_local_text_normalization_nfc_v1'),
  CHECK ((coverage_disposition = 'partial_unknown' AND unknown_remainder = 1)
      OR (coverage_disposition != 'partial_unknown' AND unknown_remainder = 0))
);

CREATE TABLE IF NOT EXISTS text_coverage_limit (
  disclosure_id TEXT NOT NULL REFERENCES text_coverage_disclosure(disclosure_id),
  limit_name TEXT NOT NULL CHECK (limit_name IN ('source_bytes', 'characters', 'lines', 'blocks', 'line_length')),
  observed_count INTEGER NOT NULL CHECK (observed_count >= 0),
  known_total INTEGER CHECK (known_total IS NULL OR known_total >= 0),
  omitted_start INTEGER CHECK (omitted_start IS NULL OR omitted_start >= 0),
  omitted_end_exclusive INTEGER CHECK (omitted_end_exclusive IS NULL OR omitted_end_exclusive >= 0),
  truncation_reason TEXT,
  coordinate_space TEXT NOT NULL CHECK (coordinate_space IN ('byte', 'code_point', 'line')),
  boundary TEXT CHECK (boundary IS NULL OR boundary IN ('safe_decode', 'split_code_unit', 'split_crlf')),
  line_end_reached INTEGER CHECK (line_end_reached IS NULL OR line_end_reached IN (0, 1)),
  PRIMARY KEY (disclosure_id, limit_name)
);

CREATE TABLE IF NOT EXISTS text_projection_publication (
  publication_id TEXT PRIMARY KEY,
  projection_id TEXT NOT NULL UNIQUE REFERENCES text_projection(projection_id),
  disclosure_id TEXT NOT NULL,
  source_version_id TEXT NOT NULL,
  published_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS secret_denylist_audit (
  audit_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  source_root_id TEXT NOT NULL,
  matched_rule_id TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE VIEW IF NOT EXISTS text_file_final_extension AS
WITH RECURSIVE
components(file_record_id, rest, part) AS (
  SELECT file_record_id, replace(relative_path, '\', '/') || '/', ''
  FROM file_record
  UNION ALL
  SELECT file_record_id, substr(rest, instr(rest, '/') + 1), substr(rest, 1, instr(rest, '/') - 1)
  FROM components
  WHERE rest <> ''
),
trimmed(file_record_id, name) AS (
  SELECT file_record_id, part FROM components WHERE rest = ''
  UNION ALL
  SELECT file_record_id, substr(name, 1, length(name) - 1)
  FROM trimmed
  WHERE name LIKE '% ' OR name LIKE '%.'
),
stable(file_record_id, name) AS (
  SELECT file_record_id, name FROM trimmed
  WHERE name NOT LIKE '% ' AND name NOT LIKE '%.'
),
dots(file_record_id, name, pos) AS (
  SELECT file_record_id, name, instr(name, '.') FROM stable
  UNION ALL
  SELECT file_record_id, name, pos + instr(substr(name, pos + 1), '.')
  FROM dots
  WHERE instr(substr(name, pos + 1), '.') > 0
)
SELECT file_record_id,
       CASE
         WHEN name = '' OR max(pos) = 0 OR max(pos) = 1 THEN ''
         ELSE lower(substr(name, max(pos) + 1))
       END AS final_extension
FROM dots
GROUP BY file_record_id, name;

CREATE VIEW IF NOT EXISTS text_coverage_limit_known AS
SELECT disclosure_id, limit_name,
       CASE
         WHEN known_total > observed_count
          AND omitted_start = observed_count
          AND omitted_end_exclusive = known_total
          AND (
            (limit_name = 'source_bytes' AND coordinate_space = 'byte' AND boundary = 'safe_decode')
            OR (limit_name = 'line_length' AND coordinate_space = 'code_point' AND line_end_reached = 1)
          )
         THEN 1 ELSE 0
       END AS known_mapping
FROM text_coverage_limit;

CREATE VIEW IF NOT EXISTS text_fts_drift AS
SELECT block_instance_id, 'ledger_missing_fts' AS drift
FROM text_fts_binding b
WHERE (
  SELECT count(*) FROM text_block_fts f WHERE f.block_instance_id = b.block_instance_id
) = 0
UNION ALL
SELECT f.block_instance_id, 'fts_missing_ledger'
FROM text_block_fts f
WHERE NOT EXISTS (
  SELECT 1 FROM text_fts_binding b WHERE b.block_instance_id = f.block_instance_id
)
UNION ALL
SELECT block_instance_id, 'fts_duplicate_row' AS drift
FROM text_block_fts
GROUP BY block_instance_id
HAVING count(*) > 1
UNION ALL
SELECT f.block_instance_id, 'fts_text_mismatch' AS drift
FROM text_block_fts f
JOIN text_block_instance b ON b.block_instance_id = f.block_instance_id
WHERE f.text IS NOT b.text;

CREATE VIEW IF NOT EXISTS text_projection_candidate AS
SELECT tp.projection_id, tp.source_version_id, tp.file_record_id
FROM text_projection tp
JOIN text_projection_publication pub ON pub.projection_id = tp.projection_id;

CREATE TRIGGER IF NOT EXISTS text_projection_claim_owner
BEFORE INSERT ON text_projection
BEGIN
  SELECT RAISE(ABORT, 'text projection requires indexed source')
  WHERE NOT EXISTS (
    SELECT 1 FROM source_version
    WHERE source_version_id = NEW.source_version_id AND processing_status = 'indexed'
  );
  SELECT RAISE(ABORT, 'text projection source identity mismatch')
  WHERE NOT EXISTS (
    SELECT 1
    FROM source_version sv
    JOIN file_record fr ON fr.file_record_id = sv.file_record_id
    WHERE sv.source_version_id = NEW.source_version_id
      AND sv.workspace_id = NEW.workspace_id
      AND sv.source_root_id = NEW.source_root_id
      AND sv.file_record_id = NEW.file_record_id
      AND fr.workspace_id = sv.workspace_id
      AND fr.source_root_id = sv.source_root_id
      AND sv.source_sha256 = NEW.source_sha256
  );
  SELECT RAISE(ABORT, 'text projection cannot own csv')
  WHERE (
    SELECT final_extension FROM text_file_final_extension
    WHERE file_record_id = NEW.file_record_id
  ) = 'csv';
  SELECT RAISE(ABORT, 'source version owner is kernel')
  WHERE EXISTS (
    SELECT 1 FROM source_projection_owner
    WHERE source_version_id = NEW.source_version_id AND owner = 'prodocux'
  );
  INSERT INTO source_projection_owner(source_version_id, owner, created_at)
  SELECT NEW.source_version_id, 'pdx-local-ai', NEW.published_at
  WHERE NOT EXISTS (
    SELECT 1 FROM source_projection_owner WHERE source_version_id = NEW.source_version_id
  );
END;

CREATE TRIGGER IF NOT EXISTS projection_claim_owner
BEFORE INSERT ON projection
BEGIN
  SELECT RAISE(ABORT, 'source version owner is local text')
  WHERE EXISTS (
    SELECT 1 FROM source_projection_owner
    WHERE source_version_id = NEW.source_version_id AND owner = 'pdx-local-ai'
  );
  INSERT INTO source_projection_owner(source_version_id, owner, created_at)
  SELECT NEW.source_version_id, 'prodocux', NEW.published_at
  WHERE NOT EXISTS (
    SELECT 1 FROM source_projection_owner WHERE source_version_id = NEW.source_version_id
  );
END;

CREATE TRIGGER IF NOT EXISTS text_block_instance_index
AFTER INSERT ON text_block_instance
BEGIN
  INSERT INTO text_block_fts(block_instance_id, text) VALUES (NEW.block_instance_id, NEW.text);
  INSERT INTO text_fts_binding(block_instance_id, projection_id, created_at)
  VALUES (NEW.block_instance_id, NEW.projection_id, (SELECT published_at FROM text_projection WHERE projection_id = NEW.projection_id));
END;

CREATE TRIGGER IF NOT EXISTS text_projection_publication_guard
BEFORE INSERT ON text_projection_publication
BEGIN
  SELECT RAISE(ABORT, 'text publication source is not indexed')
  WHERE NOT EXISTS (
    SELECT 1 FROM text_projection tp
    JOIN source_version sv ON sv.source_version_id = tp.source_version_id
    WHERE tp.projection_id = NEW.projection_id
      AND tp.source_version_id = NEW.source_version_id
      AND sv.processing_status = 'indexed'
  );
  SELECT RAISE(ABORT, 'text publication identity mismatch')
  WHERE NOT EXISTS (
    SELECT 1 FROM text_projection tp
    JOIN source_version sv ON sv.source_version_id = tp.source_version_id
    JOIN text_coverage_disclosure d ON d.disclosure_id = NEW.disclosure_id
    WHERE tp.projection_id = NEW.projection_id
      AND tp.workspace_id = sv.workspace_id
      AND tp.source_root_id = sv.source_root_id
      AND tp.file_record_id = sv.file_record_id
      AND tp.source_sha256 = sv.source_sha256
      AND d.projection_id = tp.projection_id
      AND d.workspace_id = tp.workspace_id
      AND d.source_root_id = tp.source_root_id
      AND d.file_record_id = tp.file_record_id
      AND d.source_version_id = tp.source_version_id
      AND d.encoding = tp.decoder_profile
      AND d.normalization_profile = tp.normalization_profile
  );
  SELECT RAISE(ABORT, 'text publication block identity mismatch')
  WHERE EXISTS (
    SELECT 1
    FROM text_block_instance b
    JOIN text_projection tp ON tp.projection_id = b.projection_id
    WHERE b.projection_id = NEW.projection_id
      AND (
        b.workspace_id != tp.workspace_id
        OR b.source_version_id != tp.source_version_id
      )
  );
  SELECT RAISE(ABORT, 'text publication range identity mismatch')
  WHERE EXISTS (
    SELECT 1
    FROM text_block_instance b
    JOIN text_source_range r ON r.block_instance_id = b.block_instance_id
    WHERE b.projection_id = NEW.projection_id
      AND (
        r.workspace_id != b.workspace_id
        OR r.projection_id != b.projection_id
      )
  );
  SELECT RAISE(ABORT, 'text publication block count mismatch')
  WHERE (
    SELECT block_count FROM text_projection WHERE projection_id = NEW.projection_id
  ) != (
    SELECT count(*) FROM text_block_instance WHERE projection_id = NEW.projection_id
  )
  OR (
    SELECT count(*) FROM text_block_instance WHERE projection_id = NEW.projection_id
  ) != (
    SELECT count(*) FROM text_source_range WHERE projection_id = NEW.projection_id
  );
  SELECT RAISE(ABORT, 'text publication range missing')
  WHERE EXISTS (
    SELECT 1 FROM text_block_instance b
    WHERE b.projection_id = NEW.projection_id
      AND NOT EXISTS (
        SELECT 1 FROM text_source_range r WHERE r.block_instance_id = b.block_instance_id
      )
  );
  SELECT RAISE(ABORT, 'text publication fts mismatch')
  WHERE EXISTS (
    SELECT 1
    FROM text_block_instance b
    JOIN text_fts_drift d ON d.block_instance_id = b.block_instance_id
    WHERE b.projection_id = NEW.projection_id
  )
  OR EXISTS (
    SELECT block_instance_id FROM text_block_instance WHERE projection_id = NEW.projection_id
    EXCEPT
    SELECT block_instance_id FROM text_fts_binding WHERE projection_id = NEW.projection_id
  )
  OR EXISTS (
    SELECT block_instance_id FROM text_fts_binding WHERE projection_id = NEW.projection_id
    EXCEPT
    SELECT block_instance_id FROM text_block_instance WHERE projection_id = NEW.projection_id
  );
  SELECT RAISE(ABORT, 'text publication owner is not local')
  WHERE NOT EXISTS (
    SELECT 1 FROM text_projection tp
    JOIN source_projection_owner o ON o.source_version_id = tp.source_version_id
    WHERE tp.projection_id = NEW.projection_id AND o.owner = 'pdx-local-ai'
  )
  OR EXISTS (
    SELECT 1 FROM text_projection tp
    JOIN projection p ON p.source_version_id = tp.source_version_id
    WHERE tp.projection_id = NEW.projection_id
  );
  SELECT RAISE(ABORT, 'text publication disposition mismatch')
  WHERE NOT EXISTS (
    SELECT 1 FROM text_coverage_disclosure d
    JOIN source_version sv ON sv.source_version_id = d.source_version_id
    WHERE d.disclosure_id = NEW.disclosure_id
      AND d.projection_id = NEW.projection_id
      AND d.coverage_disposition = sv.coverage_disposition
      AND d.unknown_remainder = sv.unknown_remainder
  );
  SELECT RAISE(ABORT, 'text publication disclosure reference mismatch')
  WHERE NOT EXISTS (
    SELECT 1 FROM source_version sv
    JOIN text_projection tp ON tp.source_version_id = sv.source_version_id
    WHERE tp.projection_id = NEW.projection_id
      AND json_valid(sv.disclosure_json)
      AND (SELECT count(*) FROM json_each(sv.disclosure_json)) = 2
      AND json_extract(sv.disclosure_json, '$.schema_version') = 'pdx_local_text_coverage_ref_v1'
      AND json_extract(sv.disclosure_json, '$.text_disclosure_id') = NEW.disclosure_id
  );
  SELECT RAISE(ABORT, 'text publication bom mismatch')
  WHERE EXISTS (
    SELECT 1 FROM text_coverage_disclosure d
    WHERE d.disclosure_id = NEW.disclosure_id
      AND (
        (d.encoding = 'utf-8' AND d.bom_removed != 0)
        OR (d.encoding IN ('utf-8-bom', 'utf-16-le-bom', 'utf-16-be-bom') AND d.bom_removed != 1)
      )
  );
  SELECT RAISE(ABORT, 'text publication complete is truncated')
  WHERE EXISTS (
    SELECT 1 FROM text_coverage_disclosure d
    WHERE d.disclosure_id = NEW.disclosure_id
      AND d.coverage_disposition = 'complete'
      AND (
        d.unknown_remainder != 0
        OR EXISTS (SELECT 1 FROM text_coverage_limit l WHERE l.disclosure_id = d.disclosure_id)
      )
  );
  SELECT RAISE(ABORT, 'text publication partial_known mapping is incomplete')
  WHERE EXISTS (
    SELECT 1 FROM text_coverage_disclosure d
    WHERE d.disclosure_id = NEW.disclosure_id
      AND d.coverage_disposition = 'partial_known'
      AND (
        d.unknown_remainder != 0
        OR NOT EXISTS (SELECT 1 FROM text_coverage_limit l WHERE l.disclosure_id = d.disclosure_id)
        OR EXISTS (
          SELECT 1 FROM text_coverage_limit_known k
          WHERE k.disclosure_id = d.disclosure_id AND k.known_mapping = 0
        )
      )
  );
  SELECT RAISE(ABORT, 'text publication partial_unknown has no unknown limit')
  WHERE EXISTS (
    SELECT 1 FROM text_coverage_disclosure d
    WHERE d.disclosure_id = NEW.disclosure_id
      AND d.coverage_disposition = 'partial_unknown'
      AND (
        d.unknown_remainder != 1
        OR NOT EXISTS (
          SELECT 1 FROM text_coverage_limit_known k
          WHERE k.disclosure_id = d.disclosure_id AND k.known_mapping = 0
        )
      )
  );
END;

CREATE TRIGGER IF NOT EXISTS source_projection_owner_update_forbidden
BEFORE UPDATE ON source_projection_owner
BEGIN
  SELECT RAISE(ABORT, 'source projection owner is append-only');
END;
CREATE TRIGGER IF NOT EXISTS source_projection_owner_delete_forbidden
BEFORE DELETE ON source_projection_owner
BEGIN
  SELECT RAISE(ABORT, 'source projection owner is append-only');
END;
CREATE TRIGGER IF NOT EXISTS text_projection_update_forbidden
BEFORE UPDATE ON text_projection
BEGIN
  SELECT RAISE(ABORT, 'text projection is immutable');
END;
CREATE TRIGGER IF NOT EXISTS text_projection_delete_forbidden
BEFORE DELETE ON text_projection
BEGIN
  SELECT RAISE(ABORT, 'text projection is immutable');
END;
CREATE TRIGGER IF NOT EXISTS text_block_instance_update_forbidden
BEFORE UPDATE ON text_block_instance
BEGIN
  SELECT RAISE(ABORT, 'text block is immutable');
END;
CREATE TRIGGER IF NOT EXISTS text_block_instance_delete_forbidden
BEFORE DELETE ON text_block_instance
BEGIN
  SELECT RAISE(ABORT, 'text block is immutable');
END;
CREATE TRIGGER IF NOT EXISTS text_fts_binding_update_forbidden
BEFORE UPDATE ON text_fts_binding
BEGIN
  SELECT RAISE(ABORT, 'text fts binding is append-only');
END;
CREATE TRIGGER IF NOT EXISTS text_fts_binding_delete_forbidden
BEFORE DELETE ON text_fts_binding
BEGIN
  SELECT RAISE(ABORT, 'text fts binding is append-only');
END;
CREATE TRIGGER IF NOT EXISTS text_source_range_update_forbidden
BEFORE UPDATE ON text_source_range
BEGIN
  SELECT RAISE(ABORT, 'text source range is append-only');
END;
CREATE TRIGGER IF NOT EXISTS text_source_range_delete_forbidden
BEFORE DELETE ON text_source_range
BEGIN
  SELECT RAISE(ABORT, 'text source range is append-only');
END;
CREATE TRIGGER IF NOT EXISTS text_coverage_disclosure_update_forbidden
BEFORE UPDATE ON text_coverage_disclosure
BEGIN
  SELECT RAISE(ABORT, 'text coverage disclosure is append-only');
END;
CREATE TRIGGER IF NOT EXISTS text_coverage_disclosure_delete_forbidden
BEFORE DELETE ON text_coverage_disclosure
BEGIN
  SELECT RAISE(ABORT, 'text coverage disclosure is append-only');
END;
CREATE TRIGGER IF NOT EXISTS text_coverage_limit_update_forbidden
BEFORE UPDATE ON text_coverage_limit
BEGIN
  SELECT RAISE(ABORT, 'text coverage limit is append-only');
END;
CREATE TRIGGER IF NOT EXISTS text_coverage_limit_delete_forbidden
BEFORE DELETE ON text_coverage_limit
BEGIN
  SELECT RAISE(ABORT, 'text coverage limit is append-only');
END;
CREATE TRIGGER IF NOT EXISTS text_projection_publication_update_forbidden
BEFORE UPDATE ON text_projection_publication
BEGIN
  SELECT RAISE(ABORT, 'text projection publication is append-only');
END;
CREATE TRIGGER IF NOT EXISTS text_projection_publication_delete_forbidden
BEFORE DELETE ON text_projection_publication
BEGIN
  SELECT RAISE(ABORT, 'text projection publication is append-only');
END;
CREATE TRIGGER IF NOT EXISTS secret_denylist_audit_update_forbidden
BEFORE UPDATE ON secret_denylist_audit
BEGIN
  SELECT RAISE(ABORT, 'secret denylist audit is append-only');
END;
CREATE TRIGGER IF NOT EXISTS secret_denylist_audit_delete_forbidden
BEFORE DELETE ON secret_denylist_audit
BEGIN
  SELECT RAISE(ABORT, 'secret denylist audit is append-only');
END;

INSERT INTO source_projection_owner(source_version_id, owner, created_at)
SELECT p.source_version_id, 'prodocux', p.published_at
FROM projection AS p
WHERE NOT EXISTS (
  SELECT 1 FROM source_projection_owner AS o WHERE o.source_version_id = p.source_version_id
);
