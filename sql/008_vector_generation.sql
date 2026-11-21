CREATE TABLE vector_generation (
  generation_id TEXT PRIMARY KEY NOT NULL,
  workspace_id TEXT NOT NULL,
  profile TEXT NOT NULL,
  backend_kind TEXT NOT NULL,
  dimensions INTEGER NOT NULL,
  encoding TEXT NOT NULL,
  normalization TEXT NOT NULL,
  metric TEXT NOT NULL,
  entry_count INTEGER NOT NULL,
  state TEXT NOT NULL,
  is_current INTEGER NOT NULL CHECK ((state = 'active' AND is_current = 1) OR (state IN ('building', 'failed', 'retired') AND is_current = 0)),
  build_manifest_digest TEXT NOT NULL,
  capability_digest TEXT NOT NULL,
  image_sha256 TEXT NOT NULL,
  image_locator TEXT NOT NULL,
  image_byte_size INTEGER NOT NULL,
  purged_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  audit_reconciliation_sha256 TEXT NOT NULL
);
CREATE UNIQUE INDEX vector_generation_one_current
ON vector_generation(workspace_id, profile) WHERE is_current = 1;
CREATE TRIGGER vector_generation_identity_immutable
BEFORE UPDATE OF generation_id, workspace_id, profile, backend_kind, dimensions, encoding, normalization, metric, build_manifest_digest, capability_digest, created_at
ON vector_generation
BEGIN
  SELECT RAISE(ABORT, 'immutable');
END;
CREATE TRIGGER vector_generation_state_machine
BEFORE UPDATE OF state, is_current ON vector_generation
WHEN NOT ((OLD.state = 'building' AND OLD.is_current = 0 AND NEW.state = 'active' AND NEW.is_current = 1) OR (OLD.state = 'building' AND OLD.is_current = 0 AND NEW.state = 'failed' AND NEW.is_current = 0) OR (OLD.state = 'active' AND OLD.is_current = 1 AND NEW.state = 'retired' AND NEW.is_current = 0))
BEGIN
  SELECT RAISE(ABORT, 'state');
END;
