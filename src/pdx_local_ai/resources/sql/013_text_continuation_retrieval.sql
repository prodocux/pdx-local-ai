-- Gate 5A-2 text continuation retrieval storage. Additive schema.
-- 13 tables (8 primary + 5 FTS shadow), 1 drift view, 27 integrity triggers.

-- 1. Continuation Generation Projection Identity
CREATE TABLE text_continuation_projection (
    projection_id TEXT PRIMARY KEY,
    generation_id TEXT NOT NULL UNIQUE REFERENCES text_range_generation(generation_id),
    workspace_id TEXT NOT NULL,
    source_version_id TEXT NOT NULL,
    source_sha256 TEXT NOT NULL,
    block_count INTEGER NOT NULL,
    final_manifest_digest TEXT NOT NULL,
    created_at_unix_ms INTEGER NOT NULL,
    CHECK (length(projection_id) = 36),
    CHECK (block_count > 0),
    CHECK (created_at_unix_ms > 0)
);

-- 2. Generation Continuation Block Instance Ledger
CREATE TABLE text_continuation_block_instance (
    block_instance_id TEXT PRIMARY KEY,
    projection_id TEXT NOT NULL REFERENCES text_continuation_projection(projection_id),
    generation_id TEXT NOT NULL REFERENCES text_range_generation(generation_id),
    range_artifact_id TEXT NOT NULL REFERENCES text_range_artifact(range_artifact_id),
    range_ordinal INTEGER NOT NULL,
    block_ordinal INTEGER NOT NULL,
    text TEXT NOT NULL,
    byte_count INTEGER NOT NULL,
    codepoint_count INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    created_at_unix_ms INTEGER NOT NULL,
    UNIQUE (generation_id, range_ordinal, block_ordinal),
    CHECK (range_ordinal >= 0 AND block_ordinal >= 0),
    CHECK (byte_count > 0 AND codepoint_count > 0),
    CHECK (length(sha256) = 64),
    CHECK (created_at_unix_ms > 0)
);

-- 3. Source Locators (Line and Code-Point Spans)
CREATE TABLE text_continuation_source_range (
    block_instance_id TEXT PRIMARY KEY REFERENCES text_continuation_block_instance(block_instance_id),
    projection_id TEXT NOT NULL REFERENCES text_continuation_projection(projection_id),
    line_start INTEGER NOT NULL,
    line_end_exclusive INTEGER NOT NULL,
    source_codepoint_start INTEGER NOT NULL,
    source_codepoint_end_exclusive INTEGER NOT NULL,
    created_at_unix_ms INTEGER NOT NULL,
    CHECK (line_end_exclusive > line_start),
    CHECK (source_codepoint_end_exclusive >= source_codepoint_start),
    CHECK (created_at_unix_ms > 0)
);

-- 4. FTS In-Ledger Binding Marker
CREATE TABLE text_continuation_fts_binding (
    block_instance_id TEXT PRIMARY KEY REFERENCES text_continuation_block_instance(block_instance_id),
    projection_id TEXT NOT NULL REFERENCES text_continuation_projection(projection_id),
    generation_id TEXT NOT NULL REFERENCES text_range_generation(generation_id),
    created_at_unix_ms INTEGER NOT NULL,
    CHECK (created_at_unix_ms > 0)
);

-- 5. Continuation Virtual Full-Text Search Table
CREATE VIRTUAL TABLE text_continuation_block_fts USING fts5(
    block_instance_id UNINDEXED,
    text
);

-- 6. Sliced Materialization Receipt Ledger
CREATE TABLE text_continuation_slice_receipt (
    generation_id TEXT NOT NULL REFERENCES text_range_generation(generation_id),
    range_ordinal INTEGER NOT NULL,
    range_artifact_id TEXT NOT NULL REFERENCES text_range_artifact(range_artifact_id),
    slice_block_count INTEGER NOT NULL,
    covered_source_bytes INTEGER NOT NULL,
    materialized_text_bytes INTEGER NOT NULL,
    slice_manifest_digest TEXT NOT NULL,
    created_at_unix_ms INTEGER NOT NULL,
    PRIMARY KEY (generation_id, range_ordinal),
    CHECK (range_ordinal >= 0),
    CHECK (slice_block_count > 0),
    CHECK (covered_source_bytes > 0),
    CHECK (materialized_text_bytes > 0),
    CHECK (created_at_unix_ms > 0)
);

-- 7. Atomic Running Generation Accumulator
CREATE TABLE text_continuation_generation_accumulator (
    generation_id TEXT PRIMARY KEY REFERENCES text_range_generation(generation_id),
    completed_ranges INTEGER NOT NULL,
    accumulated_blocks INTEGER NOT NULL,
    accumulated_source_bytes INTEGER NOT NULL,
    accumulated_text_bytes INTEGER NOT NULL,
    last_range_ordinal INTEGER NOT NULL,
    last_slice_manifest_digest TEXT NOT NULL,
    updated_at_unix_ms INTEGER NOT NULL,
    CHECK (completed_ranges > 0),
    CHECK (accumulated_blocks > 0),
    CHECK (accumulated_source_bytes > 0),
    CHECK (accumulated_text_bytes > 0),
    CHECK (last_range_ordinal >= 0),
    CHECK (updated_at_unix_ms > 0)
);

-- 8. Generation Materialization Completion Marker
CREATE TABLE text_continuation_materialization_marker (
    projection_id TEXT PRIMARY KEY REFERENCES text_continuation_projection(projection_id),
    generation_id TEXT NOT NULL UNIQUE REFERENCES text_range_generation(generation_id),
    total_ranges INTEGER NOT NULL,
    total_blocks INTEGER NOT NULL,
    total_source_bytes INTEGER NOT NULL,
    total_materialized_bytes INTEGER NOT NULL,
    final_manifest_digest TEXT NOT NULL,
    materialized_at_unix_ms INTEGER NOT NULL,
    CHECK (total_ranges > 0),
    CHECK (total_blocks > 0),
    CHECK (total_source_bytes > 0),
    CHECK (total_materialized_bytes > 0),
    CHECK (length(final_manifest_digest) = 64),
    CHECK (materialized_at_unix_ms > 0)
);

-- Drift View (NULL-safe text comparison & duplicate row verification)
CREATE VIEW text_continuation_fts_drift AS
-- 1. Ledger block missing from FTS
SELECT b.block_instance_id, 'ledger_missing_fts' AS drift_type
FROM text_continuation_block_instance b
WHERE NOT EXISTS (
    SELECT 1 FROM text_continuation_block_fts f
    WHERE f.block_instance_id = b.block_instance_id
)
UNION ALL
-- 2. FTS entry missing from block ledger
SELECT f.block_instance_id, 'fts_missing_ledger' AS drift_type
FROM text_continuation_block_fts f
WHERE NOT EXISTS (
    SELECT 1 FROM text_continuation_block_instance b
    WHERE b.block_instance_id = f.block_instance_id
)
UNION ALL
-- 3. Duplicate FTS rows for the same block instance
SELECT f.block_instance_id, 'fts_duplicate_row' AS drift_type
FROM text_continuation_block_fts f
GROUP BY f.block_instance_id
HAVING count(*) > 1
UNION ALL
-- 4. Block missing binding marker
SELECT b.block_instance_id, 'fts_missing_binding' AS drift_type
FROM text_continuation_block_instance b
WHERE NOT EXISTS (
    SELECT 1 FROM text_continuation_fts_binding bd
    WHERE bd.block_instance_id = b.block_instance_id
)
UNION ALL
-- 5. Text mismatch between ledger and FTS (NULL-safe comparison)
SELECT b.block_instance_id, 'fts_text_mismatch' AS drift_type
FROM text_continuation_block_instance b
JOIN text_continuation_block_fts f ON f.block_instance_id = b.block_instance_id
WHERE b.text IS NOT f.text
UNION ALL
-- 6. Block missing source locators
SELECT b.block_instance_id, 'source_range_missing' AS drift_type
FROM text_continuation_block_instance b
WHERE NOT EXISTS (
    SELECT 1 FROM text_continuation_source_range r
    WHERE r.block_instance_id = b.block_instance_id
);

-- Triggers on Projection
CREATE TRIGGER trg_continuation_projection_protect_update
BEFORE UPDATE ON text_continuation_projection
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'continuation projections are immutable: update prohibited');
END;

CREATE TRIGGER trg_continuation_projection_protect_delete
BEFORE DELETE ON text_continuation_projection
FOR EACH ROW
WHEN EXISTS (
    SELECT 1 FROM text_continuation_slice_receipt r
    WHERE r.generation_id = OLD.generation_id
) OR EXISTS (
    SELECT 1 FROM text_continuation_materialization_marker m
    WHERE m.generation_id = OLD.generation_id
)
BEGIN
    SELECT RAISE(ABORT, 'generation ledger is active or sealed: projection deletion prohibited');
END;

CREATE TRIGGER trg_continuation_projection_verify_generation_identity
BEFORE INSERT ON text_continuation_projection
FOR EACH ROW
WHEN NOT EXISTS (
    SELECT 1 FROM text_range_generation g
    WHERE g.generation_id = NEW.generation_id
      AND g.workspace_id = NEW.workspace_id
      AND g.source_version_id = NEW.source_version_id
      AND g.source_sha256 = NEW.source_sha256
      AND g.final_manifest_digest = NEW.final_manifest_digest
)
BEGIN
    SELECT RAISE(ABORT, 'projection source identity mismatch: workspace, source version, source sha256, or final manifest digest does not match generation');
END;

-- Automatic FTS Sync Triggers
CREATE TRIGGER trg_continuation_block_after_insert_sync_fts
AFTER INSERT ON text_continuation_block_instance
FOR EACH ROW
BEGIN
    INSERT INTO text_continuation_block_fts (block_instance_id, text)
    VALUES (NEW.block_instance_id, NEW.text);

    INSERT INTO text_continuation_fts_binding (block_instance_id, projection_id, generation_id, created_at_unix_ms)
    VALUES (NEW.block_instance_id, NEW.projection_id, NEW.generation_id, NEW.created_at_unix_ms);
END;

CREATE TRIGGER trg_continuation_block_before_delete_sync_fts
BEFORE DELETE ON text_continuation_block_instance
FOR EACH ROW
BEGIN
    DELETE FROM text_continuation_block_fts WHERE block_instance_id = OLD.block_instance_id;
    DELETE FROM text_continuation_fts_binding WHERE block_instance_id = OLD.block_instance_id;
END;

-- Per-Slice Mutation Lock Triggers on Blocks (INSERT, UPDATE, DELETE, and Causality)
CREATE TRIGGER trg_continuation_block_protect_sealed_slice
BEFORE INSERT ON text_continuation_block_instance
FOR EACH ROW
WHEN EXISTS (
    SELECT 1 FROM text_continuation_slice_receipt r
    WHERE r.generation_id = NEW.generation_id AND r.range_ordinal = NEW.range_ordinal
) OR EXISTS (
    SELECT 1 FROM text_continuation_materialization_marker m
    WHERE m.generation_id = NEW.generation_id
)
BEGIN
    SELECT RAISE(ABORT, 'slice or generation ledger is sealed: block insertion prohibited');
END;

CREATE TRIGGER trg_continuation_block_protect_update_sealed
BEFORE UPDATE ON text_continuation_block_instance
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'continuation blocks are immutable: update prohibited');
END;

CREATE TRIGGER trg_continuation_block_protect_delete_sealed
BEFORE DELETE ON text_continuation_block_instance
FOR EACH ROW
WHEN EXISTS (
    SELECT 1 FROM text_continuation_slice_receipt r
    WHERE r.generation_id = OLD.generation_id AND r.range_ordinal = OLD.range_ordinal
) OR EXISTS (
    SELECT 1 FROM text_continuation_materialization_marker m
    WHERE m.generation_id = OLD.generation_id
)
BEGIN
    SELECT RAISE(ABORT, 'slice or generation ledger is sealed: block deletion prohibited');
END;

CREATE TRIGGER trg_continuation_block_verify_causality
BEFORE INSERT ON text_continuation_block_instance
FOR EACH ROW
WHEN NOT EXISTS (
    SELECT 1 FROM text_continuation_projection p
    WHERE p.projection_id = NEW.projection_id AND p.generation_id = NEW.generation_id
) OR NOT EXISTS (
    SELECT 1 FROM text_range_generation_member m
    WHERE m.generation_id = NEW.generation_id
      AND m.range_ordinal = NEW.range_ordinal
      AND m.range_artifact_id = NEW.range_artifact_id
)
BEGIN
    SELECT RAISE(ABORT, 'block causality error: projection or member artifact mismatch');
END;

-- Per-Slice Mutation Lock Triggers on Source Ranges (INSERT, UPDATE, DELETE, and Causality)
CREATE TRIGGER trg_continuation_source_range_protect_insert_sealed
BEFORE INSERT ON text_continuation_source_range
FOR EACH ROW
WHEN EXISTS (
    SELECT 1 FROM text_continuation_block_instance b
    JOIN text_continuation_slice_receipt r
      ON r.generation_id = b.generation_id AND r.range_ordinal = b.range_ordinal
    WHERE b.block_instance_id = NEW.block_instance_id
) OR EXISTS (
    SELECT 1 FROM text_continuation_block_instance b
    JOIN text_continuation_materialization_marker m
      ON m.generation_id = b.generation_id
    WHERE b.block_instance_id = NEW.block_instance_id
)
BEGIN
    SELECT RAISE(ABORT, 'slice or generation ledger is sealed: source range insertion prohibited');
END;

CREATE TRIGGER trg_continuation_source_range_protect_update
BEFORE UPDATE ON text_continuation_source_range
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'continuation source ranges are immutable: update prohibited');
END;

CREATE TRIGGER trg_continuation_source_range_protect_delete_sealed
BEFORE DELETE ON text_continuation_source_range
FOR EACH ROW
WHEN EXISTS (
    SELECT 1 FROM text_continuation_block_instance b
    JOIN text_continuation_slice_receipt r
      ON r.generation_id = b.generation_id AND r.range_ordinal = b.range_ordinal
    WHERE b.block_instance_id = OLD.block_instance_id
) OR EXISTS (
    SELECT 1 FROM text_continuation_block_instance b
    JOIN text_continuation_materialization_marker m
      ON m.generation_id = b.generation_id
    WHERE b.block_instance_id = OLD.block_instance_id
)
BEGIN
    SELECT RAISE(ABORT, 'slice or generation ledger is sealed: source range deletion prohibited');
END;

CREATE TRIGGER trg_continuation_source_range_verify_causality
BEFORE INSERT ON text_continuation_source_range
FOR EACH ROW
WHEN NOT EXISTS (
    SELECT 1 FROM text_continuation_block_instance b
    WHERE b.block_instance_id = NEW.block_instance_id
      AND b.projection_id = NEW.projection_id
)
BEGIN
    SELECT RAISE(ABORT, 'source range causality error: block or projection mismatch');
END;

-- Per-Slice Mutation Lock Triggers on FTS Bindings (UPDATE, DELETE, and Causality)
CREATE TRIGGER trg_continuation_fts_binding_protect_update
BEFORE UPDATE ON text_continuation_fts_binding
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'continuation fts bindings are immutable: update prohibited');
END;

CREATE TRIGGER trg_continuation_fts_binding_protect_delete_sealed
BEFORE DELETE ON text_continuation_fts_binding
FOR EACH ROW
WHEN EXISTS (
    SELECT 1 FROM text_continuation_block_instance b
    JOIN text_continuation_slice_receipt r
      ON r.generation_id = b.generation_id AND r.range_ordinal = b.range_ordinal
    WHERE b.block_instance_id = OLD.block_instance_id
) OR EXISTS (
    SELECT 1 FROM text_continuation_block_instance b
    JOIN text_continuation_materialization_marker m
      ON m.generation_id = b.generation_id
    WHERE b.block_instance_id = OLD.block_instance_id
)
BEGIN
    SELECT RAISE(ABORT, 'slice or generation ledger is sealed: fts binding deletion prohibited');
END;

CREATE TRIGGER trg_continuation_fts_binding_verify_causality
BEFORE INSERT ON text_continuation_fts_binding
FOR EACH ROW
WHEN NOT EXISTS (
    SELECT 1 FROM text_continuation_block_instance b
    WHERE b.block_instance_id = NEW.block_instance_id
      AND b.projection_id = NEW.projection_id
      AND b.generation_id = NEW.generation_id
)
BEGIN
    SELECT RAISE(ABORT, 'fts binding causality error: block, projection, or generation mismatch');
END;

-- Slice Receipt Validation Triggers with Per-Record Text, Locator, and Causality Checks
CREATE TRIGGER trg_receipt_validate_member
BEFORE INSERT ON text_continuation_slice_receipt
FOR EACH ROW
WHEN NOT EXISTS (
    SELECT 1 FROM text_range_generation_member m
    JOIN text_range_artifact a ON a.range_artifact_id = m.range_artifact_id
    WHERE m.generation_id = NEW.generation_id
      AND m.range_ordinal = NEW.range_ordinal
      AND m.range_artifact_id = NEW.range_artifact_id
      AND m.manifest_digest = NEW.slice_manifest_digest
      AND (m.range_end_exclusive - m.range_start) = NEW.covered_source_bytes
      AND json_array_length(a.recomputed_records) = NEW.slice_block_count
) OR NEW.slice_block_count <= 0
  OR (
    SELECT count(*) FROM text_continuation_block_instance b
    WHERE b.generation_id = NEW.generation_id AND b.range_ordinal = NEW.range_ordinal
) != NEW.slice_block_count
  OR (
    SELECT coalesce(sum(b.byte_count), 0) FROM text_continuation_block_instance b
    WHERE b.generation_id = NEW.generation_id AND b.range_ordinal = NEW.range_ordinal
) != NEW.materialized_text_bytes
  OR (
    SELECT count(*) FROM text_continuation_source_range r
    JOIN text_continuation_block_instance b ON b.block_instance_id = r.block_instance_id
    WHERE b.generation_id = NEW.generation_id AND b.range_ordinal = NEW.range_ordinal
) != NEW.slice_block_count
  OR (
    SELECT count(*) FROM text_continuation_fts_binding bd
    JOIN text_continuation_block_instance b ON b.block_instance_id = bd.block_instance_id
    WHERE b.generation_id = NEW.generation_id AND b.range_ordinal = NEW.range_ordinal
) != NEW.slice_block_count
  OR EXISTS (
    SELECT 1 FROM text_continuation_block_instance b
    JOIN text_continuation_projection p ON p.projection_id = b.projection_id
    WHERE b.generation_id = NEW.generation_id AND b.range_ordinal = NEW.range_ordinal
      AND p.generation_id != NEW.generation_id
)
  OR EXISTS (
    SELECT 1 FROM text_continuation_block_instance b
    WHERE b.generation_id = NEW.generation_id AND b.range_ordinal = NEW.range_ordinal
      AND b.range_artifact_id != NEW.range_artifact_id
)
  OR EXISTS (
    SELECT 1 FROM text_continuation_source_range r
    JOIN text_continuation_block_instance b ON b.block_instance_id = r.block_instance_id
    WHERE b.generation_id = NEW.generation_id AND b.range_ordinal = NEW.range_ordinal
      AND r.projection_id != b.projection_id
)
  OR EXISTS (
    SELECT 1 FROM text_continuation_fts_binding bd
    JOIN text_continuation_block_instance b ON b.block_instance_id = bd.block_instance_id
    WHERE b.generation_id = NEW.generation_id AND b.range_ordinal = NEW.range_ordinal
      AND (bd.projection_id != b.projection_id OR bd.generation_id != b.generation_id)
)
  OR EXISTS (
    SELECT 1 FROM text_range_artifact a
    JOIN json_each(a.recomputed_records) j
    WHERE a.range_artifact_id = NEW.range_artifact_id
      AND NOT EXISTS (
        SELECT 1 FROM text_continuation_block_instance b
        JOIN text_continuation_source_range r ON r.block_instance_id = b.block_instance_id
        WHERE b.generation_id = NEW.generation_id
          AND b.range_ordinal = NEW.range_ordinal
          AND b.block_ordinal = CAST(j.key AS INTEGER)
          AND b.range_artifact_id = NEW.range_artifact_id
          AND b.text = json_extract(j.value, '$.block_text')
          AND r.line_start = CAST(json_extract(j.value, '$.locator.line_start') AS INTEGER)
          AND r.line_end_exclusive = CAST(json_extract(j.value, '$.locator.line_end_exclusive') AS INTEGER)
          AND r.source_codepoint_start = CAST(json_extract(j.value, '$.locator.code_point_start') AS INTEGER)
          AND r.source_codepoint_end_exclusive = CAST(json_extract(j.value, '$.locator.code_point_end_exclusive') AS INTEGER)
      )
)
BEGIN
    SELECT RAISE(ABORT, 'receipt does not match member artifact record or block ledger');
END;

CREATE TRIGGER trg_receipt_immutable_update
BEFORE UPDATE ON text_continuation_slice_receipt
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'slice receipts are immutable: update prohibited');
END;

CREATE TRIGGER trg_receipt_immutable_delete
BEFORE DELETE ON text_continuation_slice_receipt
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'slice receipts are immutable: deletion prohibited');
END;

-- Atomic Accumulator Progression Triggers
CREATE TRIGGER trg_receipt_advance_accumulator_insert
AFTER INSERT ON text_continuation_slice_receipt
FOR EACH ROW
WHEN NEW.range_ordinal = 0
BEGIN
    INSERT INTO text_continuation_generation_accumulator
    VALUES (
        NEW.generation_id,
        1,
        NEW.slice_block_count,
        NEW.covered_source_bytes,
        NEW.materialized_text_bytes,
        0,
        NEW.slice_manifest_digest,
        NEW.created_at_unix_ms
    );
END;

CREATE TRIGGER trg_receipt_advance_accumulator_update
AFTER INSERT ON text_continuation_slice_receipt
FOR EACH ROW
WHEN NEW.range_ordinal > 0
BEGIN
    UPDATE text_continuation_generation_accumulator
    SET completed_ranges = completed_ranges + 1,
        accumulated_blocks = accumulated_blocks + NEW.slice_block_count,
        accumulated_source_bytes = accumulated_source_bytes + NEW.covered_source_bytes,
        accumulated_text_bytes = accumulated_text_bytes + NEW.materialized_text_bytes,
        last_range_ordinal = NEW.range_ordinal,
        last_slice_manifest_digest = NEW.slice_manifest_digest,
        updated_at_unix_ms = NEW.created_at_unix_ms
    WHERE generation_id = NEW.generation_id
      AND last_range_ordinal = NEW.range_ordinal - 1;
END;

-- Accumulator Full-Transition Guard Triggers
CREATE TRIGGER trg_accumulator_protect_manual_update
BEFORE UPDATE ON text_continuation_generation_accumulator
FOR EACH ROW
WHEN NEW.accumulated_source_bytes != (
    SELECT coalesce(sum(r.covered_source_bytes), 0)
    FROM text_continuation_slice_receipt r
    WHERE r.generation_id = NEW.generation_id
) OR NEW.completed_ranges != (
    SELECT count(*)
    FROM text_continuation_slice_receipt r
    WHERE r.generation_id = NEW.generation_id
) OR NEW.accumulated_blocks != (
    SELECT coalesce(sum(r.slice_block_count), 0)
    FROM text_continuation_slice_receipt r
    WHERE r.generation_id = NEW.generation_id
) OR NEW.accumulated_text_bytes != (
    SELECT coalesce(sum(r.materialized_text_bytes), 0)
    FROM text_continuation_slice_receipt r
    WHERE r.generation_id = NEW.generation_id
) OR NEW.last_range_ordinal != (
    SELECT max(r.range_ordinal)
    FROM text_continuation_slice_receipt r
    WHERE r.generation_id = NEW.generation_id
) OR NEW.last_slice_manifest_digest != (
    SELECT r.slice_manifest_digest
    FROM text_continuation_slice_receipt r
    WHERE r.generation_id = NEW.generation_id
      AND r.range_ordinal = NEW.last_range_ordinal
)
BEGIN
    SELECT RAISE(ABORT, 'manual accumulator modification prohibited: values must match receipt sums and transition state');
END;

CREATE TRIGGER trg_accumulator_protect_manual_insert
BEFORE INSERT ON text_continuation_generation_accumulator
FOR EACH ROW
WHEN NEW.completed_ranges != 1 OR NEW.last_range_ordinal != 0
  OR NOT EXISTS (
    SELECT 1 FROM text_continuation_slice_receipt r
    WHERE r.generation_id = NEW.generation_id AND r.range_ordinal = 0
      AND r.covered_source_bytes = NEW.accumulated_source_bytes
      AND r.slice_block_count = NEW.accumulated_blocks
      AND r.materialized_text_bytes = NEW.accumulated_text_bytes
      AND r.slice_manifest_digest = NEW.last_slice_manifest_digest
)
BEGIN
    SELECT RAISE(ABORT, 'manual accumulator insertion prohibited');
END;

CREATE TRIGGER trg_accumulator_protect_delete
BEFORE DELETE ON text_continuation_generation_accumulator
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'accumulator is immutable: deletion prohibited');
END;

-- Materialization Marker Readiness Gate & Immutability Triggers (Matching Projection Identity, Block Content & Causality)
CREATE TRIGGER trg_marker_verify_readiness
BEFORE INSERT ON text_continuation_materialization_marker
FOR EACH ROW
WHEN NOT EXISTS (
    SELECT 1 FROM text_range_generation_seal s
    JOIN text_continuation_generation_accumulator a ON a.generation_id = s.generation_id
    JOIN text_continuation_projection p ON p.projection_id = NEW.projection_id
    WHERE s.generation_id = NEW.generation_id
      AND p.generation_id = NEW.generation_id
      AND p.block_count = NEW.total_blocks
      AND p.final_manifest_digest = NEW.final_manifest_digest
      AND a.completed_ranges = s.total_ranges
      AND a.accumulated_source_bytes = s.total_bytes
      AND a.last_range_ordinal = s.total_ranges - 1
      AND a.last_slice_manifest_digest = s.final_manifest_digest
      AND NEW.total_ranges = s.total_ranges
      AND NEW.total_source_bytes = s.total_bytes
      AND NEW.final_manifest_digest = s.final_manifest_digest
      AND NEW.total_blocks = a.accumulated_blocks
      AND NEW.total_materialized_bytes = a.accumulated_text_bytes
) OR (
    SELECT count(*) FROM text_continuation_block_instance b
    WHERE b.projection_id = NEW.projection_id
) != NEW.total_blocks
  OR (
    SELECT count(*) FROM text_continuation_source_range r
    WHERE r.projection_id = NEW.projection_id
) != NEW.total_blocks
  OR (
    SELECT count(*) FROM text_continuation_fts_binding bd
    WHERE bd.projection_id = NEW.projection_id
) != NEW.total_blocks
  OR (
    SELECT coalesce(sum(b.byte_count), 0) FROM text_continuation_block_instance b
    WHERE b.projection_id = NEW.projection_id
) != NEW.total_materialized_bytes
  OR EXISTS (
    SELECT 1 FROM text_continuation_block_instance b
    WHERE b.generation_id = NEW.generation_id AND b.projection_id != NEW.projection_id
)
  OR EXISTS (
    SELECT 1 FROM text_continuation_source_range r
    JOIN text_continuation_block_instance b ON b.block_instance_id = r.block_instance_id
    WHERE b.generation_id = NEW.generation_id AND r.projection_id != NEW.projection_id
)
  OR EXISTS (
    SELECT 1 FROM text_continuation_fts_binding bd
    WHERE bd.generation_id = NEW.generation_id AND bd.projection_id != NEW.projection_id
)
  OR EXISTS (
    SELECT 1 FROM text_continuation_fts_drift d
    WHERE d.block_instance_id IN (
        SELECT b.block_instance_id FROM text_continuation_block_instance b
        WHERE b.generation_id = NEW.generation_id
    ) OR d.block_instance_id IN (
        SELECT f.block_instance_id FROM text_continuation_block_fts f
        JOIN text_continuation_fts_binding bd ON bd.block_instance_id = f.block_instance_id
        WHERE bd.generation_id = NEW.generation_id
    )
)
BEGIN
    SELECT RAISE(ABORT, 'materialization marker rejected: generation is not ready, projection mismatch, accumulator does not match seal, projection content missing or foreign, or fts drift detected');
END;

CREATE TRIGGER trg_marker_protect_update
BEFORE UPDATE ON text_continuation_materialization_marker
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'materialization marker is immutable: update prohibited');
END;

CREATE TRIGGER trg_marker_protect_delete
BEFORE DELETE ON text_continuation_materialization_marker
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'materialization marker is immutable: deletion prohibited');
END;
