-- Gate 5A-2 text range continuation storage. Additive schema.
-- 8 tables, 2 intent views, 16 integrity triggers + protection triggers.

-- 1. Range Artifact Base Table
CREATE TABLE IF NOT EXISTS text_range_artifact (
  range_artifact_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  file_record_id TEXT NOT NULL REFERENCES file_record(file_record_id),
  source_version_id TEXT NOT NULL REFERENCES source_version(source_version_id),
  source_sha256 TEXT NOT NULL CHECK (length(source_sha256) = 64),
  parser_contract_name TEXT NOT NULL CHECK (parser_contract_name = 'pdx_local_text_decoder'),
  parser_contract_version TEXT NOT NULL CHECK (parser_contract_version = '1'),
  budget_profile_id TEXT NOT NULL CHECK (budget_profile_id = 'pdx_local_text_continuation_budget_v1'),
  snapshot_mode TEXT NOT NULL CHECK (
    snapshot_mode IN (
      'rebuild_controlled_snapshot_and_verify_source_sha256',
      'persistent_immutable_source_artifact'
    )
  ),
  range_ordinal INTEGER NOT NULL CHECK (typeof(range_ordinal) = 'integer' AND range_ordinal >= 0),
  range_start INTEGER NOT NULL CHECK (typeof(range_start) = 'integer' AND range_start >= 0),
  range_end_exclusive INTEGER NOT NULL CHECK (typeof(range_end_exclusive) = 'integer' AND range_end_exclusive > range_start),
  owned_byte_slice_sha256 TEXT NOT NULL CHECK (length(owned_byte_slice_sha256) = 64),
  input_decoder_state TEXT NOT NULL,
  previous_cursor INTEGER NOT NULL CHECK (typeof(previous_cursor) = 'integer' AND previous_cursor >= 0),
  previous_manifest_digest TEXT NOT NULL CHECK (length(previous_manifest_digest) = 64),
  next_decoder_state TEXT NOT NULL,
  next_cursor INTEGER NOT NULL CHECK (typeof(next_cursor) = 'integer' AND next_cursor > previous_cursor),
  manifest_digest TEXT NOT NULL CHECK (length(manifest_digest) = 64),
  recomputed_records TEXT NOT NULL,
  created_at_unix_ms INTEGER NOT NULL CHECK (typeof(created_at_unix_ms) = 'integer' AND created_at_unix_ms > 0),
  CHECK (previous_cursor = range_start),
  CHECK (next_cursor = range_end_exclusive),
  UNIQUE (
    workspace_id,
    file_record_id,
    source_version_id,
    source_sha256,
    parser_contract_name,
    parser_contract_version,
    budget_profile_id,
    snapshot_mode,
    range_ordinal,
    range_start,
    range_end_exclusive
  )
);

-- 2. Range Cursor Table
CREATE TABLE IF NOT EXISTS text_range_cursor (
  workspace_id TEXT NOT NULL,
  file_record_id TEXT NOT NULL REFERENCES file_record(file_record_id),
  source_version_id TEXT NOT NULL REFERENCES source_version(source_version_id),
  source_sha256 TEXT NOT NULL CHECK (length(source_sha256) = 64),
  parser_contract_name TEXT NOT NULL CHECK (parser_contract_name = 'pdx_local_text_decoder'),
  parser_contract_version TEXT NOT NULL CHECK (parser_contract_version = '1'),
  budget_profile_id TEXT NOT NULL CHECK (budget_profile_id = 'pdx_local_text_continuation_budget_v1'),
  snapshot_mode TEXT NOT NULL CHECK (
    snapshot_mode IN (
      'rebuild_controlled_snapshot_and_verify_source_sha256',
      'persistent_immutable_source_artifact'
    )
  ),
  cursor_byte_offset INTEGER NOT NULL CHECK (typeof(cursor_byte_offset) = 'integer' AND cursor_byte_offset >= 0),
  last_range_ordinal INTEGER NOT NULL CHECK (typeof(last_range_ordinal) = 'integer' AND last_range_ordinal >= 0),
  last_range_artifact_id TEXT NOT NULL REFERENCES text_range_artifact(range_artifact_id),
  decoder_profile TEXT NOT NULL CHECK (decoder_profile IN ('utf-8', 'utf-8-bom', 'utf-16-le-bom', 'utf-16-be-bom')),
  manifest_digest TEXT NOT NULL CHECK (length(manifest_digest) = 64),
  decoder_state TEXT NOT NULL,
  terminal_reason TEXT CHECK (terminal_reason IS NULL OR terminal_reason = 'RANGE_UNIT_EXCEEDS_BUDGET'),
  updated_at_unix_ms INTEGER NOT NULL CHECK (typeof(updated_at_unix_ms) = 'integer' AND updated_at_unix_ms > 0),
  PRIMARY KEY (
    workspace_id,
    file_record_id,
    source_version_id,
    source_sha256,
    parser_contract_name,
    parser_contract_version,
    budget_profile_id,
    snapshot_mode
  )
);

-- 3. Range Generation Table
CREATE TABLE IF NOT EXISTS text_range_generation (
  generation_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  file_record_id TEXT NOT NULL REFERENCES file_record(file_record_id),
  source_version_id TEXT NOT NULL REFERENCES source_version(source_version_id),
  source_sha256 TEXT NOT NULL CHECK (length(source_sha256) = 64),
  source_size_bytes INTEGER NOT NULL CHECK (typeof(source_size_bytes) = 'integer' AND source_size_bytes > 0),
  parser_contract_name TEXT NOT NULL CHECK (parser_contract_name = 'pdx_local_text_decoder'),
  parser_contract_version TEXT NOT NULL CHECK (parser_contract_version = '1'),
  budget_profile_id TEXT NOT NULL CHECK (budget_profile_id = 'pdx_local_text_continuation_budget_v1'),
  snapshot_mode TEXT NOT NULL CHECK (
    snapshot_mode IN (
      'rebuild_controlled_snapshot_and_verify_source_sha256',
      'persistent_immutable_source_artifact'
    )
  ),
  total_ranges INTEGER NOT NULL CHECK (typeof(total_ranges) = 'integer' AND total_ranges > 0),
  total_bytes INTEGER NOT NULL CHECK (typeof(total_bytes) = 'integer' AND total_bytes > 0),
  final_manifest_digest TEXT NOT NULL CHECK (length(final_manifest_digest) = 64),
  terminal_reason TEXT CHECK (terminal_reason IS NULL OR terminal_reason = 'RANGE_UNIT_EXCEEDS_BUDGET'),
  created_at_unix_ms INTEGER NOT NULL CHECK (typeof(created_at_unix_ms) = 'integer' AND created_at_unix_ms > 0),
  CHECK (total_bytes = source_size_bytes)
);

-- 4. Generation Member Table
CREATE TABLE IF NOT EXISTS text_range_generation_member (
  generation_id TEXT NOT NULL REFERENCES text_range_generation(generation_id),
  range_ordinal INTEGER NOT NULL CHECK (typeof(range_ordinal) = 'integer' AND range_ordinal >= 0),
  range_artifact_id TEXT NOT NULL REFERENCES text_range_artifact(range_artifact_id),
  range_start INTEGER NOT NULL CHECK (typeof(range_start) = 'integer' AND range_start >= 0),
  range_end_exclusive INTEGER NOT NULL CHECK (typeof(range_end_exclusive) = 'integer' AND range_end_exclusive > range_start),
  manifest_digest TEXT NOT NULL CHECK (length(manifest_digest) = 64),
  PRIMARY KEY (generation_id, range_ordinal),
  UNIQUE (generation_id, range_artifact_id)
);

-- 5. Generation Seal Table
CREATE TABLE IF NOT EXISTS text_range_generation_seal (
  generation_id TEXT PRIMARY KEY REFERENCES text_range_generation(generation_id),
  total_ranges INTEGER NOT NULL CHECK (typeof(total_ranges) = 'integer' AND total_ranges > 0),
  total_bytes INTEGER NOT NULL CHECK (typeof(total_bytes) = 'integer' AND total_bytes > 0),
  source_size_bytes INTEGER NOT NULL CHECK (typeof(source_size_bytes) = 'integer' AND source_size_bytes > 0),
  final_manifest_digest TEXT NOT NULL CHECK (length(final_manifest_digest) = 64),
  sealed_at_unix_ms INTEGER NOT NULL CHECK (typeof(sealed_at_unix_ms) = 'integer' AND sealed_at_unix_ms > 0),
  CHECK (total_bytes = source_size_bytes)
);

-- 6. Freshness Witness Table
CREATE TABLE IF NOT EXISTS text_freshness_witness (
  witness_id TEXT PRIMARY KEY,
  generation_id TEXT NOT NULL REFERENCES text_range_generation(generation_id),
  source_sha256 TEXT NOT NULL CHECK (length(source_sha256) = 64),
  source_size_bytes INTEGER NOT NULL CHECK (typeof(source_size_bytes) = 'integer' AND source_size_bytes > 0),
  snapshot_identity TEXT NOT NULL CHECK (length(snapshot_identity) > 0),
  created_at_unix_ms INTEGER NOT NULL CHECK (typeof(created_at_unix_ms) = 'integer' AND created_at_unix_ms > 0),
  expires_at_unix_ms INTEGER NOT NULL CHECK (typeof(expires_at_unix_ms) = 'integer' AND expires_at_unix_ms > created_at_unix_ms),
  CHECK (expires_at_unix_ms - created_at_unix_ms <= 300000)
);

-- 7. Range Publication Event Table
CREATE TABLE IF NOT EXISTS text_range_publication_event (
  publication_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  file_record_id TEXT NOT NULL REFERENCES file_record(file_record_id),
  source_version_id TEXT NOT NULL REFERENCES source_version(source_version_id),
  generation_id TEXT NOT NULL REFERENCES text_range_generation(generation_id),
  witness_id TEXT NOT NULL UNIQUE REFERENCES text_freshness_witness(witness_id),
  published_at_unix_ms INTEGER NOT NULL CHECK (typeof(published_at_unix_ms) = 'integer' AND published_at_unix_ms > 0)
);

-- 8. Current Published Generation Pointer Table
CREATE TABLE IF NOT EXISTS text_current_published_generation (
  source_version_id TEXT PRIMARY KEY REFERENCES source_version(source_version_id),
  workspace_id TEXT NOT NULL,
  file_record_id TEXT NOT NULL REFERENCES file_record(file_record_id),
  generation_id TEXT NOT NULL REFERENCES text_range_generation(generation_id),
  publication_id TEXT NOT NULL UNIQUE REFERENCES text_range_publication_event(publication_id),
  witness_id TEXT NOT NULL UNIQUE REFERENCES text_freshness_witness(witness_id),
  published_at_unix_ms INTEGER NOT NULL CHECK (typeof(published_at_unix_ms) = 'integer' AND published_at_unix_ms > 0)
);

-- Views
CREATE VIEW IF NOT EXISTS text_freshness_witness_intent AS
SELECT
  witness_id,
  generation_id,
  source_sha256,
  source_size_bytes,
  snapshot_identity,
  60000 AS requested_ttl_ms
FROM text_freshness_witness;

CREATE VIEW IF NOT EXISTS text_range_publication_intent AS
SELECT
  publication_id,
  workspace_id,
  file_record_id,
  source_version_id,
  generation_id,
  witness_id
FROM text_range_publication_event;

-- Triggers

-- 1. text_range_artifact_immutable
CREATE TRIGGER IF NOT EXISTS text_range_artifact_immutable
BEFORE UPDATE ON text_range_artifact
BEGIN
  SELECT RAISE(ABORT, 'text_range_artifact is immutable');
END;

CREATE TRIGGER IF NOT EXISTS text_range_artifact_delete_forbidden
BEFORE DELETE ON text_range_artifact
BEGIN
  SELECT RAISE(ABORT, 'text_range_artifact is immutable');
END;

-- 2. text_range_artifact_verify_identity
CREATE TRIGGER IF NOT EXISTS text_range_artifact_verify_identity
BEFORE INSERT ON text_range_artifact
BEGIN
  SELECT RAISE(ABORT, 'text_range_artifact source_version identity mismatch')
  WHERE NOT EXISTS (
    SELECT 1 FROM source_version sv
    WHERE sv.source_version_id = NEW.source_version_id
      AND sv.workspace_id = NEW.workspace_id
      AND sv.file_record_id = NEW.file_record_id
      AND sv.source_sha256 = NEW.source_sha256
  );

  SELECT RAISE(ABORT, 'text_range_artifact range_end_exclusive exceeds source_version size_bytes')
  WHERE EXISTS (
    SELECT 1 FROM source_version sv
    WHERE sv.source_version_id = NEW.source_version_id
      AND sv.workspace_id = NEW.workspace_id
      AND sv.file_record_id = NEW.file_record_id
      AND sv.source_sha256 = NEW.source_sha256
      AND NEW.range_end_exclusive > sv.size_bytes
  );

  SELECT RAISE(ABORT, 'text_range_artifact ordinal 0 must have previous_cursor 0 and genesis manifest digest')
  WHERE NEW.range_ordinal = 0
    AND (
      NEW.previous_cursor != 0
      OR NEW.previous_manifest_digest != 'f3207ab9220fdd13edba85174ea823e315e421bcde37c4dda94f452ab6f733ae'
    );

  SELECT RAISE(ABORT, 'text_range_artifact predecessor chaining mismatch')
  WHERE NEW.range_ordinal > 0
    AND NOT EXISTS (
      SELECT 1 FROM text_range_artifact prev
      WHERE prev.workspace_id = NEW.workspace_id
        AND prev.file_record_id = NEW.file_record_id
        AND prev.source_version_id = NEW.source_version_id
        AND prev.source_sha256 = NEW.source_sha256
        AND prev.parser_contract_name = NEW.parser_contract_name
        AND prev.parser_contract_version = NEW.parser_contract_version
        AND prev.budget_profile_id = NEW.budget_profile_id
        AND prev.snapshot_mode = NEW.snapshot_mode
        AND prev.range_ordinal = NEW.range_ordinal - 1
        AND prev.next_cursor = NEW.previous_cursor
        AND prev.next_decoder_state = NEW.input_decoder_state
        AND prev.manifest_digest = NEW.previous_manifest_digest
    );
END;

-- 3. text_range_cursor_verify_identity
CREATE TRIGGER IF NOT EXISTS text_range_cursor_verify_identity
BEFORE INSERT ON text_range_cursor
BEGIN
  SELECT RAISE(ABORT, 'text_range_cursor source_version identity mismatch')
  WHERE NOT EXISTS (
    SELECT 1 FROM source_version sv
    WHERE sv.source_version_id = NEW.source_version_id
      AND sv.workspace_id = NEW.workspace_id
      AND sv.file_record_id = NEW.file_record_id
      AND sv.source_sha256 = NEW.source_sha256
  );

  SELECT RAISE(ABORT, 'text_range_cursor referenced artifact mismatch: ordinal, offset, manifest digest, decoder state, snapshot mode, and identity must match')
  WHERE NOT EXISTS (
    SELECT 1 FROM text_range_artifact art
    WHERE art.range_artifact_id = NEW.last_range_artifact_id
      AND art.workspace_id = NEW.workspace_id
      AND art.file_record_id = NEW.file_record_id
      AND art.source_version_id = NEW.source_version_id
      AND art.source_sha256 = NEW.source_sha256
      AND art.parser_contract_name = NEW.parser_contract_name
      AND art.parser_contract_version = NEW.parser_contract_version
      AND art.budget_profile_id = NEW.budget_profile_id
      AND art.snapshot_mode = NEW.snapshot_mode
      AND art.range_ordinal = NEW.last_range_ordinal
      AND art.range_end_exclusive = NEW.cursor_byte_offset
      AND art.manifest_digest = NEW.manifest_digest
      AND art.next_decoder_state = NEW.decoder_state
  );
END;

-- 4. text_range_cursor_transition_guard
CREATE TRIGGER IF NOT EXISTS text_range_cursor_transition_guard
BEFORE UPDATE ON text_range_cursor
BEGIN
  SELECT RAISE(ABORT, 'cursor_identity_drift_rejected: workspace, file, version, sha, parser, or budget cannot be modified')
  WHERE NEW.workspace_id != OLD.workspace_id
     OR NEW.file_record_id != OLD.file_record_id
     OR NEW.source_version_id != OLD.source_version_id
     OR NEW.source_sha256 != OLD.source_sha256
     OR NEW.parser_contract_name != OLD.parser_contract_name
     OR NEW.parser_contract_version != OLD.parser_contract_version
     OR NEW.budget_profile_id != OLD.budget_profile_id;

  SELECT RAISE(ABORT, 'cursor_snapshot_mode_drift_rejected: snapshot_mode cannot be modified')
  WHERE NEW.snapshot_mode != OLD.snapshot_mode;

  SELECT RAISE(ABORT, 'cursor_decoder_profile_drift_rejected: decoder_profile cannot be modified')
  WHERE NEW.decoder_profile != OLD.decoder_profile;

  SELECT RAISE(ABORT, 'cursor updated_at_unix_ms must strictly increase')
  WHERE NEW.updated_at_unix_ms <= OLD.updated_at_unix_ms;

  SELECT RAISE(ABORT, 'cursor_post_terminal_update_rejected: terminal cursor cannot be updated')
  WHERE OLD.terminal_reason IS NOT NULL;

  SELECT RAISE(ABORT, 'invalid cursor terminal_reason')
  WHERE NEW.terminal_reason IS NOT NULL AND NEW.terminal_reason != 'RANGE_UNIT_EXCEEDS_BUDGET';

  SELECT RAISE(ABORT, 'cursor_terminal_tamper_rejected: fields cannot change when setting terminal_reason')
  WHERE NEW.terminal_reason IS NOT NULL
    AND (
      NEW.cursor_byte_offset != OLD.cursor_byte_offset
      OR NEW.last_range_ordinal != OLD.last_range_ordinal
      OR NEW.last_range_artifact_id != OLD.last_range_artifact_id
      OR NEW.manifest_digest != OLD.manifest_digest
      OR NEW.decoder_state != OLD.decoder_state
    );

  SELECT RAISE(ABORT, 'cursor_backward_offset_rejected: cursor_byte_offset must advance forward')
  WHERE NEW.terminal_reason IS NULL
    AND NEW.cursor_byte_offset <= OLD.cursor_byte_offset;

  SELECT RAISE(ABORT, 'cursor_skipped_ordinal_rejected: last_range_ordinal must advance by exactly 1')
  WHERE NEW.terminal_reason IS NULL
    AND NEW.last_range_ordinal != OLD.last_range_ordinal + 1;

  SELECT RAISE(ABORT, 'last_range_artifact_id mismatch or invalid state chaining')
  WHERE NEW.terminal_reason IS NULL
    AND NOT EXISTS (
      SELECT 1 FROM text_range_artifact art
      WHERE art.range_artifact_id = NEW.last_range_artifact_id
        AND art.workspace_id = NEW.workspace_id
        AND art.file_record_id = NEW.file_record_id
        AND art.source_version_id = NEW.source_version_id
        AND art.source_sha256 = NEW.source_sha256
        AND art.parser_contract_name = NEW.parser_contract_name
        AND art.parser_contract_version = NEW.parser_contract_version
        AND art.budget_profile_id = NEW.budget_profile_id
        AND art.snapshot_mode = NEW.snapshot_mode
        AND art.range_ordinal = NEW.last_range_ordinal
        AND art.range_end_exclusive = NEW.cursor_byte_offset
        AND art.manifest_digest = NEW.manifest_digest
        AND art.next_decoder_state = NEW.decoder_state
    );
END;

-- 5. text_range_generation_immutable
CREATE TRIGGER IF NOT EXISTS text_range_generation_immutable
BEFORE UPDATE ON text_range_generation
BEGIN
  SELECT RAISE(ABORT, 'text_range_generation is immutable');
END;

CREATE TRIGGER IF NOT EXISTS text_range_generation_delete_forbidden
BEFORE DELETE ON text_range_generation
BEGIN
  SELECT RAISE(ABORT, 'text_range_generation is immutable');
END;

-- 6. text_range_generation_verify_identity
CREATE TRIGGER IF NOT EXISTS text_range_generation_verify_identity
BEFORE INSERT ON text_range_generation
BEGIN
  SELECT RAISE(ABORT, 'text_range_generation source_version identity mismatch')
  WHERE NOT EXISTS (
    SELECT 1 FROM source_version sv
    WHERE sv.source_version_id = NEW.source_version_id
      AND sv.workspace_id = NEW.workspace_id
      AND sv.file_record_id = NEW.file_record_id
      AND sv.source_sha256 = NEW.source_sha256
  );

  SELECT RAISE(ABORT, 'text_range_generation source_size_bytes mismatch with source_version size_bytes')
  WHERE NOT EXISTS (
    SELECT 1 FROM source_version sv
    WHERE sv.source_version_id = NEW.source_version_id
      AND sv.workspace_id = NEW.workspace_id
      AND sv.file_record_id = NEW.file_record_id
      AND sv.source_sha256 = NEW.source_sha256
      AND sv.size_bytes = NEW.source_size_bytes
  );
END;

-- 7. text_range_generation_member_immutable
CREATE TRIGGER IF NOT EXISTS text_range_generation_member_immutable
BEFORE UPDATE ON text_range_generation_member
BEGIN
  SELECT RAISE(ABORT, 'text_range_generation_member is immutable');
END;

CREATE TRIGGER IF NOT EXISTS text_range_generation_member_delete_forbidden
BEFORE DELETE ON text_range_generation_member
BEGIN
  SELECT RAISE(ABORT, 'text_range_generation_member is immutable');
END;

-- 8. text_range_generation_member_guard
CREATE TRIGGER IF NOT EXISTS text_range_generation_member_guard
BEFORE INSERT ON text_range_generation_member
BEGIN
  SELECT RAISE(ABORT, 'generation_member_insert_post_seal_rejected: generation is already sealed')
  WHERE EXISTS (
    SELECT 1 FROM text_range_generation_seal seal
    WHERE seal.generation_id = NEW.generation_id
  );

  SELECT RAISE(ABORT, 'generation_member_insert_post_publish_rejected: generation is already published')
  WHERE EXISTS (
    SELECT 1 FROM text_range_publication_event pub
    WHERE pub.generation_id = NEW.generation_id
  );

  SELECT RAISE(ABORT, 'generation does not exist')
  WHERE NOT EXISTS (
    SELECT 1 FROM text_range_generation gen
    WHERE gen.generation_id = NEW.generation_id
  );

  SELECT RAISE(ABORT, 'member_ordinal_mismatch_artifact_ordinal_rejected: range_ordinal mismatch')
  WHERE NOT EXISTS (
    SELECT 1 FROM text_range_artifact art
    WHERE art.range_artifact_id = NEW.range_artifact_id
      AND art.range_ordinal = NEW.range_ordinal
  );

  SELECT RAISE(ABORT, 'member_range_interval_mismatch_rejected: range intervals mismatch')
  WHERE NOT EXISTS (
    SELECT 1 FROM text_range_artifact art
    WHERE art.range_artifact_id = NEW.range_artifact_id
      AND art.range_start = NEW.range_start
      AND art.range_end_exclusive = NEW.range_end_exclusive
      AND art.manifest_digest = NEW.manifest_digest
  );

  SELECT RAISE(ABORT, 'member_foreign_snapshot_mode_rejected: snapshot_mode or identity mismatch')
  WHERE NOT EXISTS (
    SELECT 1 FROM text_range_artifact art
    JOIN text_range_generation gen ON gen.generation_id = NEW.generation_id
    WHERE art.range_artifact_id = NEW.range_artifact_id
      AND art.workspace_id = gen.workspace_id
      AND art.file_record_id = gen.file_record_id
      AND art.source_version_id = gen.source_version_id
      AND art.source_sha256 = gen.source_sha256
      AND art.parser_contract_name = gen.parser_contract_name
      AND art.parser_contract_version = gen.parser_contract_version
      AND art.budget_profile_id = gen.budget_profile_id
      AND art.snapshot_mode = gen.snapshot_mode
  );
END;

-- 9. text_range_generation_seal_verify
CREATE TRIGGER IF NOT EXISTS text_range_generation_seal_verify
BEFORE INSERT ON text_range_generation_seal
BEGIN
  SELECT RAISE(ABORT, 'cannot seal generation with terminal_reason or missing generation')
  WHERE NOT EXISTS (
    SELECT 1 FROM text_range_generation gen
    WHERE gen.generation_id = NEW.generation_id
      AND gen.terminal_reason IS NULL
  );

  SELECT RAISE(ABORT, 'seal metrics do not match generation')
  WHERE NOT EXISTS (
    SELECT 1 FROM text_range_generation gen
    WHERE gen.generation_id = NEW.generation_id
      AND gen.total_ranges = NEW.total_ranges
      AND gen.total_bytes = NEW.total_bytes
      AND gen.source_size_bytes = NEW.source_size_bytes
      AND gen.final_manifest_digest = NEW.final_manifest_digest
  );

  SELECT RAISE(ABORT, 'seal_truncated_length_rejected: total_bytes must equal source_size_bytes')
  WHERE NEW.total_bytes != NEW.source_size_bytes;

  SELECT RAISE(ABORT, 'generation member count mismatch')
  WHERE (
    SELECT count(*) FROM text_range_generation_member m
    WHERE m.generation_id = NEW.generation_id
  ) != NEW.total_ranges;

  SELECT RAISE(ABORT, 'generation member ordinal range mismatch')
  WHERE (
    SELECT min(m.range_ordinal) FROM text_range_generation_member m
    WHERE m.generation_id = NEW.generation_id
  ) != 0
  OR (
    SELECT max(m.range_ordinal) FROM text_range_generation_member m
    WHERE m.generation_id = NEW.generation_id
  ) != NEW.total_ranges - 1;

  SELECT RAISE(ABORT, 'generation member 0 must start at 0')
  WHERE (
    SELECT m.range_start FROM text_range_generation_member m
    WHERE m.generation_id = NEW.generation_id AND m.range_ordinal = 0
  ) != 0;

  SELECT RAISE(ABORT, 'generation members must be contiguous without gaps or overlaps')
  WHERE EXISTS (
    SELECT 1
    FROM text_range_generation_member curr
    JOIN text_range_generation_member prev
      ON prev.generation_id = curr.generation_id
     AND prev.range_ordinal = curr.range_ordinal - 1
    WHERE curr.generation_id = NEW.generation_id
      AND curr.range_start != prev.range_end_exclusive
  );

  SELECT RAISE(ABORT, 'seal_last_range_short_of_source_size_rejected: last member range_end_exclusive must equal source_size_bytes')
  WHERE (
    SELECT m.range_end_exclusive FROM text_range_generation_member m
    WHERE m.generation_id = NEW.generation_id AND m.range_ordinal = NEW.total_ranges - 1
  ) != NEW.source_size_bytes;

  SELECT RAISE(ABORT, 'artifact chaining mismatch between consecutive members')
  WHERE EXISTS (
    SELECT 1
    FROM text_range_generation_member curr_m
    JOIN text_range_artifact curr_a ON curr_a.range_artifact_id = curr_m.range_artifact_id
    JOIN text_range_generation_member prev_m
      ON prev_m.generation_id = curr_m.generation_id
     AND prev_m.range_ordinal = curr_m.range_ordinal - 1
    JOIN text_range_artifact prev_a ON prev_a.range_artifact_id = prev_m.range_artifact_id
    WHERE curr_m.generation_id = NEW.generation_id
      AND (
        curr_a.previous_cursor != prev_a.next_cursor
        OR curr_a.input_decoder_state != prev_a.next_decoder_state
        OR curr_a.previous_manifest_digest != prev_a.manifest_digest
      )
  );

  SELECT RAISE(ABORT, 'final member manifest_digest must equal final_manifest_digest')
  WHERE (
    SELECT m.manifest_digest FROM text_range_generation_member m
    WHERE m.generation_id = NEW.generation_id AND m.range_ordinal = NEW.total_ranges - 1
  ) != NEW.final_manifest_digest;
END;

-- 10. text_range_generation_seal_immutable
CREATE TRIGGER IF NOT EXISTS text_range_generation_seal_immutable
BEFORE UPDATE ON text_range_generation_seal
BEGIN
  SELECT RAISE(ABORT, 'text_range_generation_seal is immutable');
END;

CREATE TRIGGER IF NOT EXISTS text_range_generation_seal_delete_forbidden
BEFORE DELETE ON text_range_generation_seal
BEGIN
  SELECT RAISE(ABORT, 'text_range_generation_seal is immutable');
END;

-- 11. text_freshness_witness_intent_insert
CREATE TRIGGER IF NOT EXISTS text_freshness_witness_intent_insert
INSTEAD OF INSERT ON text_freshness_witness_intent
BEGIN
  SELECT RAISE(ABORT, 'intent_view_numeric_looking_text_rejected: requested_ttl_ms must be integer')
  WHERE NEW.requested_ttl_ms IS NOT NULL AND typeof(NEW.requested_ttl_ms) != 'integer';

  SELECT RAISE(ABORT, 'negative_or_zero_witness_ttl_rejected: requested_ttl_ms must be > 0')
  WHERE NEW.requested_ttl_ms IS NOT NULL AND NEW.requested_ttl_ms <= 0;

  SELECT RAISE(ABORT, 'excessive_witness_ttl_rejected: requested_ttl_ms cannot exceed 300000')
  WHERE NEW.requested_ttl_ms IS NOT NULL AND NEW.requested_ttl_ms > 300000;

  SELECT RAISE(ABORT, 'generation not found or terminal')
  WHERE NOT EXISTS (
    SELECT 1 FROM text_range_generation gen
    WHERE gen.generation_id = NEW.generation_id
      AND gen.terminal_reason IS NULL
  );

  SELECT RAISE(ABORT, 'witness source_sha256 does not match generation')
  WHERE NOT EXISTS (
    SELECT 1 FROM text_range_generation gen
    WHERE gen.generation_id = NEW.generation_id
      AND gen.source_sha256 = NEW.source_sha256
  );

  SELECT RAISE(ABORT, 'witness_source_size_mismatch_rejected: witness source_size_bytes does not match generation')
  WHERE NOT EXISTS (
    SELECT 1 FROM text_range_generation gen
    WHERE gen.generation_id = NEW.generation_id
      AND gen.source_size_bytes = NEW.source_size_bytes
  );

  INSERT INTO text_freshness_witness (
    witness_id,
    generation_id,
    source_sha256,
    source_size_bytes,
    snapshot_identity,
    created_at_unix_ms,
    expires_at_unix_ms
  ) VALUES (
    NEW.witness_id,
    NEW.generation_id,
    NEW.source_sha256,
    NEW.source_size_bytes,
    NEW.snapshot_identity,
    CAST((unixepoch('subsec') * 1000) AS INTEGER),
    CAST((unixepoch('subsec') * 1000) AS INTEGER) + coalesce(NEW.requested_ttl_ms, 60000)
  );
END;

-- 12. text_freshness_witness_guard
CREATE TRIGGER IF NOT EXISTS text_freshness_witness_guard
BEFORE INSERT ON text_freshness_witness
BEGIN
  SELECT RAISE(ABORT, 'base_table_clock_mismatch_rejected: created_at_unix_ms must equal database clock')
  WHERE NEW.created_at_unix_ms != CAST((unixepoch('subsec') * 1000) AS INTEGER);

  SELECT RAISE(ABORT, 'expires_at_unix_ms must be greater than created_at_unix_ms')
  WHERE NEW.expires_at_unix_ms <= NEW.created_at_unix_ms;

  SELECT RAISE(ABORT, 'witness TTL exceeds maximum allowed 300000 ms')
  WHERE (NEW.expires_at_unix_ms - NEW.created_at_unix_ms) > 300000;
END;

CREATE TRIGGER IF NOT EXISTS text_freshness_witness_update_forbidden
BEFORE UPDATE ON text_freshness_witness
BEGIN
  SELECT RAISE(ABORT, 'text_freshness_witness is immutable');
END;

CREATE TRIGGER IF NOT EXISTS text_freshness_witness_delete_forbidden
BEFORE DELETE ON text_freshness_witness
BEGIN
  SELECT RAISE(ABORT, 'text_freshness_witness is immutable');
END;

-- 13. text_range_publication_intent_publish
CREATE TRIGGER IF NOT EXISTS text_range_publication_intent_publish
INSTEAD OF INSERT ON text_range_publication_intent
BEGIN
  SELECT RAISE(ABORT, 'generation not found')
  WHERE NOT EXISTS (
    SELECT 1 FROM text_range_generation gen
    WHERE gen.generation_id = NEW.generation_id
  );

  SELECT RAISE(ABORT, 'unsealed_generation_rejected: generation must be sealed before publication')
  WHERE NOT EXISTS (
    SELECT 1 FROM text_range_generation_seal seal
    WHERE seal.generation_id = NEW.generation_id
  );

  SELECT RAISE(ABORT, 'generation identity mismatch with source_version')
  WHERE NOT EXISTS (
    SELECT 1 FROM text_range_generation gen
    JOIN source_version sv ON sv.source_version_id = gen.source_version_id
    WHERE gen.generation_id = NEW.generation_id
      AND gen.workspace_id = NEW.workspace_id
      AND gen.file_record_id = NEW.file_record_id
      AND gen.source_version_id = NEW.source_version_id
      AND sv.workspace_id = NEW.workspace_id
      AND sv.file_record_id = NEW.file_record_id
  );

  SELECT RAISE(ABORT, 'witness does not match generation')
  WHERE NOT EXISTS (
    SELECT 1 FROM text_freshness_witness wit
    JOIN text_range_generation gen ON gen.generation_id = NEW.generation_id
    WHERE wit.witness_id = NEW.witness_id
      AND wit.generation_id = NEW.generation_id
      AND wit.source_sha256 = gen.source_sha256
  );

  SELECT RAISE(ABORT, 'witness_source_size_mismatch_rejected: witness source_size_bytes differs from generation')
  WHERE NOT EXISTS (
    SELECT 1 FROM text_freshness_witness wit
    JOIN text_range_generation gen ON gen.generation_id = NEW.generation_id
    WHERE wit.witness_id = NEW.witness_id
      AND wit.source_size_bytes = gen.source_size_bytes
  );

  SELECT RAISE(ABORT, 'truncated_generation_total_bytes_rejected: generation total_bytes must equal witness source_size_bytes')
  WHERE NOT EXISTS (
    SELECT 1 FROM text_freshness_witness wit
    JOIN text_range_generation gen ON gen.generation_id = NEW.generation_id
    WHERE wit.witness_id = NEW.witness_id
      AND gen.total_bytes = wit.source_size_bytes
  );

  SELECT RAISE(ABORT, 'boundary_expiry_rejected: witness has expired')
  WHERE EXISTS (
    SELECT 1 FROM text_freshness_witness wit
    WHERE wit.witness_id = NEW.witness_id
      AND CAST((unixepoch('subsec') * 1000) AS INTEGER) > wit.expires_at_unix_ms
  );

  SELECT RAISE(ABORT, 'clock anomaly: database clock before witness created_at')
  WHERE EXISTS (
    SELECT 1 FROM text_freshness_witness wit
    WHERE wit.witness_id = NEW.witness_id
      AND CAST((unixepoch('subsec') * 1000) AS INTEGER) < wit.created_at_unix_ms
  );

  SELECT RAISE(ABORT, 'new publication timestamp must be strictly greater than current pointer timestamp')
  WHERE EXISTS (
    SELECT 1 FROM text_current_published_generation cur
    WHERE cur.source_version_id = NEW.source_version_id
      AND CAST((unixepoch('subsec') * 1000) AS INTEGER) <= cur.published_at_unix_ms
  );

  INSERT INTO text_range_publication_event (
    publication_id,
    workspace_id,
    file_record_id,
    source_version_id,
    generation_id,
    witness_id,
    published_at_unix_ms
  ) VALUES (
    NEW.publication_id,
    NEW.workspace_id,
    NEW.file_record_id,
    NEW.source_version_id,
    NEW.generation_id,
    NEW.witness_id,
    CAST((unixepoch('subsec') * 1000) AS INTEGER)
  );
END;

-- 14. text_range_publication_event_guard
CREATE TRIGGER IF NOT EXISTS text_range_publication_event_guard
BEFORE INSERT ON text_range_publication_event
BEGIN
  SELECT RAISE(ABORT, 'base_table_clock_mismatch_rejected: published_at_unix_ms must equal database clock')
  WHERE NEW.published_at_unix_ms != CAST((unixepoch('subsec') * 1000) AS INTEGER);
END;

CREATE TRIGGER IF NOT EXISTS text_range_publication_event_update_forbidden
BEFORE UPDATE ON text_range_publication_event
BEGIN
  SELECT RAISE(ABORT, 'text_range_publication_event is immutable');
END;

CREATE TRIGGER IF NOT EXISTS text_range_publication_event_delete_forbidden
BEFORE DELETE ON text_range_publication_event
BEGIN
  SELECT RAISE(ABORT, 'text_range_publication_event is immutable');
END;

-- 15. text_range_publication_event_publish_pointer
CREATE TRIGGER IF NOT EXISTS text_range_publication_event_publish_pointer
AFTER INSERT ON text_range_publication_event
BEGIN
  INSERT INTO text_current_published_generation (
    source_version_id,
    workspace_id,
    file_record_id,
    generation_id,
    publication_id,
    witness_id,
    published_at_unix_ms
  ) VALUES (
    NEW.source_version_id,
    NEW.workspace_id,
    NEW.file_record_id,
    NEW.generation_id,
    NEW.publication_id,
    NEW.witness_id,
    NEW.published_at_unix_ms
  )
  ON CONFLICT (source_version_id) DO UPDATE SET
    generation_id = excluded.generation_id,
    publication_id = excluded.publication_id,
    witness_id = excluded.witness_id,
    published_at_unix_ms = excluded.published_at_unix_ms
  WHERE excluded.published_at_unix_ms > text_current_published_generation.published_at_unix_ms;
END;

-- 16. text_current_published_generation_guard
CREATE TRIGGER IF NOT EXISTS text_current_published_generation_guard
BEFORE UPDATE ON text_current_published_generation
BEGIN
  SELECT RAISE(ABORT, 'pointer_identity_drift_rejected: source_version_id, workspace_id, and file_record_id are immutable')
  WHERE NEW.source_version_id != OLD.source_version_id
     OR NEW.workspace_id != OLD.workspace_id
     OR NEW.file_record_id != OLD.file_record_id;

  SELECT RAISE(ABORT, 'published_at_unix_ms must strictly monotonically increase')
  WHERE NEW.published_at_unix_ms <= OLD.published_at_unix_ms;
END;

CREATE TRIGGER IF NOT EXISTS text_current_published_generation_delete_forbidden
BEFORE DELETE ON text_current_published_generation
BEGIN
  SELECT RAISE(ABORT, 'direct_current_pointer_delete_rejected: direct DELETE on text_current_published_generation is forbidden');
END;
