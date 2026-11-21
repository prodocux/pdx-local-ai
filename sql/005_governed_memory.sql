CREATE TABLE IF NOT EXISTS governed_promotion_proposal (
  proposal_id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL,
  workspace_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  target_id TEXT,
  target_contract_version TEXT CHECK (target_contract_version IN ('pdx_local_memory_record_v1','pdx_local_memory_record_v2')),
  proposed_content TEXT NOT NULL,
  proposed_content_sha256 TEXT NOT NULL,
  memory_kind TEXT NOT NULL CHECK (memory_kind IN ('fact','preference','decision','task','note')),
  authority_id TEXT NOT NULL,
  provenance_category TEXT NOT NULL CHECK (provenance_category IN ('document_grounded','user_stated','model_proposed')),
  verification_status TEXT NOT NULL CHECK (verification_status IN ('citation_verified','user_asserted','unverified')),
  proposer_actor_id TEXT NOT NULL,
  proposer_actor_kind TEXT NOT NULL CHECK (proposer_actor_kind IN ('human','model')),
  deterministic_disposition TEXT NOT NULL CHECK (deterministic_disposition IN ('novel','duplicate','unresolved')),
  state TEXT NOT NULL CHECK (state IN ('pending_review','approved','published','rejected','cancelled','stale')),
  request_fingerprint TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  payload_sha256 TEXT NOT NULL,
  created_at TEXT NOT NULL,
  state_updated_at TEXT NOT NULL,
  UNIQUE (proposal_id, workspace_id, principal_id),
  UNIQUE (workspace_id, principal_id, idempotency_key),
  CHECK ((target_id IS NULL AND target_contract_version IS NULL AND deterministic_disposition='novel') OR
         (target_id IS NOT NULL AND target_contract_version IS NOT NULL AND deterministic_disposition IN ('duplicate','unresolved'))),
  CHECK ((provenance_category='document_grounded' AND verification_status='citation_verified') OR
         (provenance_category='user_stated' AND verification_status='user_asserted') OR
         (provenance_category='model_proposed' AND verification_status='unverified'))
);

CREATE TABLE IF NOT EXISTS governed_promotion_source (
  proposal_id TEXT NOT NULL REFERENCES governed_promotion_proposal(proposal_id),
  ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
  working_memory_id TEXT NOT NULL REFERENCES working_memory(working_memory_id),
  content_sha256 TEXT NOT NULL,
  observed_state TEXT NOT NULL CHECK (observed_state='active'),
  expires_at TEXT NOT NULL,
  PRIMARY KEY (proposal_id, ordinal),
  UNIQUE (proposal_id, working_memory_id)
);

CREATE TABLE IF NOT EXISTS governed_promotion_decision (
  decision_id TEXT PRIMARY KEY,
  proposal_id TEXT NOT NULL,
  workspace_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  reviewer_actor_id TEXT NOT NULL,
  actor_kind TEXT NOT NULL CHECK (actor_kind='human'),
  decision TEXT NOT NULL CHECK (decision IN ('approve','reject','cancel')),
  selected_disposition TEXT NOT NULL CHECK (selected_disposition IN ('novel','duplicate','updates','conflicts','unresolved')),
  verification_status TEXT NOT NULL CHECK (verification_status IN ('citation_verified','user_asserted','unverified')),
  proposal_sha256 TEXT NOT NULL,
  decision_fingerprint TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  payload_sha256 TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE (decision_id, workspace_id, principal_id, proposal_id),
  UNIQUE (workspace_id, principal_id, idempotency_key),
  FOREIGN KEY (proposal_id, workspace_id, principal_id)
    REFERENCES governed_promotion_proposal(proposal_id, workspace_id, principal_id)
);

CREATE TABLE IF NOT EXISTS governed_publication_request (
  publication_request_id TEXT PRIMARY KEY,
  proposal_id TEXT NOT NULL,
  decision_id TEXT NOT NULL,
  workspace_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  requesting_actor_id TEXT NOT NULL,
  request_fingerprint TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  payload_sha256 TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE (workspace_id, principal_id, idempotency_key),
  FOREIGN KEY (proposal_id, workspace_id, principal_id)
    REFERENCES governed_promotion_proposal(proposal_id, workspace_id, principal_id),
  FOREIGN KEY (decision_id, workspace_id, principal_id, proposal_id)
    REFERENCES governed_promotion_decision(decision_id, workspace_id, principal_id, proposal_id)
);

CREATE TABLE IF NOT EXISTS memory_record_v2 (
  memory_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  memory_kind TEXT NOT NULL CHECK (memory_kind IN ('fact','preference','decision','task','note')),
  content TEXT NOT NULL,
  content_sha256 TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('active','superseded','retracted')),
  confidence REAL NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
  salience REAL NOT NULL CHECK (salience >= 0 AND salience <= 1),
  source_binding_id TEXT NOT NULL UNIQUE,
  supersedes_contract_version TEXT CHECK (supersedes_contract_version IN ('pdx_local_memory_record_v1','pdx_local_memory_record_v2')),
  supersedes_memory_id TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (memory_id, workspace_id, principal_id),
  CHECK ((supersedes_contract_version IS NULL) = (supersedes_memory_id IS NULL)),
  FOREIGN KEY (source_binding_id) REFERENCES memory_source_binding(source_binding_id)
    DEFERRABLE INITIALLY DEFERRED
);

CREATE INDEX IF NOT EXISTS memory_v2_scope_status
ON memory_record_v2(workspace_id, principal_id, status, updated_at);

CREATE TABLE IF NOT EXISTS memory_source_binding (
  source_binding_id TEXT PRIMARY KEY,
  memory_id TEXT NOT NULL UNIQUE,
  workspace_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  provenance_category TEXT NOT NULL CHECK (provenance_category IN ('document_grounded','user_stated','model_proposed')),
  verification_status TEXT NOT NULL CHECK (verification_status IN ('citation_verified','user_asserted','unverified')),
  authorization_snapshot_sha256 TEXT,
  authority_id TEXT NOT NULL,
  decision_id TEXT NOT NULL,
  publication_receipt_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  CHECK ((provenance_category='document_grounded' AND verification_status='citation_verified' AND authorization_snapshot_sha256 IS NOT NULL) OR
         (provenance_category='user_stated' AND verification_status='user_asserted' AND authorization_snapshot_sha256 IS NULL) OR
         (provenance_category='model_proposed' AND verification_status='unverified' AND authorization_snapshot_sha256 IS NULL)),
  FOREIGN KEY (memory_id, workspace_id, principal_id)
    REFERENCES memory_record_v2(memory_id, workspace_id, principal_id)
    DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (decision_id) REFERENCES governed_promotion_decision(decision_id),
  FOREIGN KEY (publication_receipt_id) REFERENCES governed_publication_receipt_v2(receipt_id)
    DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE IF NOT EXISTS memory_source_binding_working (
  source_binding_id TEXT NOT NULL REFERENCES memory_source_binding(source_binding_id),
  ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
  working_memory_id TEXT NOT NULL REFERENCES working_memory(working_memory_id),
  content_sha256 TEXT NOT NULL,
  observed_state TEXT NOT NULL CHECK (observed_state='active'),
  expires_at TEXT NOT NULL,
  PRIMARY KEY (source_binding_id, ordinal),
  UNIQUE (source_binding_id, working_memory_id)
);

CREATE TABLE IF NOT EXISTS memory_source_binding_citation (
  source_binding_id TEXT NOT NULL REFERENCES memory_source_binding(source_binding_id),
  ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
  citation_id TEXT NOT NULL REFERENCES citation(citation_id),
  PRIMARY KEY (source_binding_id, ordinal),
  UNIQUE (source_binding_id, citation_id)
);

CREATE TABLE IF NOT EXISTS governed_publication_receipt_v2 (
  receipt_id TEXT PRIMARY KEY,
  publication_request_id TEXT NOT NULL,
  proposal_id TEXT NOT NULL,
  decision_id TEXT NOT NULL,
  workspace_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  terminal_result TEXT NOT NULL CHECK (terminal_result IN ('published_new','published_update','duplicate_no_op','stale','rejected','failed')),
  disposition TEXT NOT NULL CHECK (disposition IN ('novel','duplicate','updates')),
  target_memory_id TEXT,
  source_binding_id TEXT,
  superseded_contract_version TEXT CHECK (superseded_contract_version IN ('pdx_local_memory_record_v1','pdx_local_memory_record_v2')),
  superseded_memory_id TEXT,
  proposal_sha256 TEXT NOT NULL,
  decision_sha256 TEXT NOT NULL,
  verification_status TEXT NOT NULL CHECK (verification_status IN ('citation_verified','user_asserted','unverified')),
  publication_fingerprint TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  receipt_json TEXT NOT NULL,
  receipt_sha256 TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE (workspace_id, principal_id, idempotency_key),
  CHECK ((superseded_contract_version IS NULL) = (superseded_memory_id IS NULL)),
  CHECK ((terminal_result='published_new' AND disposition='novel' AND target_memory_id IS NOT NULL AND source_binding_id IS NOT NULL AND superseded_memory_id IS NULL) OR
         (terminal_result='published_update' AND disposition='updates' AND target_memory_id IS NOT NULL AND source_binding_id IS NOT NULL AND superseded_memory_id IS NOT NULL) OR
         (terminal_result='duplicate_no_op' AND disposition='duplicate' AND target_memory_id IS NULL AND source_binding_id IS NULL AND superseded_memory_id IS NULL) OR
         (terminal_result IN ('stale','rejected','failed') AND target_memory_id IS NULL AND source_binding_id IS NULL AND superseded_memory_id IS NULL)),
  FOREIGN KEY (publication_request_id) REFERENCES governed_publication_request(publication_request_id),
  FOREIGN KEY (proposal_id, workspace_id, principal_id)
    REFERENCES governed_promotion_proposal(proposal_id, workspace_id, principal_id),
  FOREIGN KEY (decision_id, workspace_id, principal_id, proposal_id)
    REFERENCES governed_promotion_decision(decision_id, workspace_id, principal_id, proposal_id),
  FOREIGN KEY (target_memory_id, workspace_id, principal_id)
    REFERENCES memory_record_v2(memory_id, workspace_id, principal_id)
    DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (source_binding_id) REFERENCES memory_source_binding(source_binding_id)
    DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE IF NOT EXISTS memory_v2_event (
  event_id TEXT PRIMARY KEY,
  memory_id TEXT NOT NULL REFERENCES memory_record_v2(memory_id),
  workspace_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  event_type TEXT NOT NULL CHECK (event_type IN ('created','superseded','retracted')),
  event_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE VIRTUAL TABLE IF NOT EXISTS memory_v2_fts USING fts5(
  memory_id UNINDEXED,
  content,
  tokenize = 'unicode61'
);

CREATE TRIGGER IF NOT EXISTS governed_proposal_immutable
BEFORE UPDATE ON governed_promotion_proposal
WHEN NEW.proposal_id IS NOT OLD.proposal_id OR NEW.request_id IS NOT OLD.request_id OR
     NEW.workspace_id IS NOT OLD.workspace_id OR NEW.principal_id IS NOT OLD.principal_id OR
     NEW.target_id IS NOT OLD.target_id OR NEW.target_contract_version IS NOT OLD.target_contract_version OR
     NEW.proposed_content IS NOT OLD.proposed_content OR NEW.proposed_content_sha256 IS NOT OLD.proposed_content_sha256 OR
     NEW.memory_kind IS NOT OLD.memory_kind OR NEW.authority_id IS NOT OLD.authority_id OR
     NEW.provenance_category IS NOT OLD.provenance_category OR NEW.verification_status IS NOT OLD.verification_status OR
     NEW.proposer_actor_id IS NOT OLD.proposer_actor_id OR NEW.proposer_actor_kind IS NOT OLD.proposer_actor_kind OR
     NEW.deterministic_disposition IS NOT OLD.deterministic_disposition OR
     NEW.request_fingerprint IS NOT OLD.request_fingerprint OR NEW.idempotency_key IS NOT OLD.idempotency_key OR
     NEW.payload_json IS NOT OLD.payload_json OR NEW.payload_sha256 IS NOT OLD.payload_sha256 OR
     NEW.created_at IS NOT OLD.created_at
BEGIN SELECT RAISE(ABORT, 'governed proposal payload is immutable'); END;

CREATE TRIGGER IF NOT EXISTS governed_proposal_insert_pending
BEFORE INSERT ON governed_promotion_proposal WHEN NEW.state!='pending_review'
BEGIN SELECT RAISE(ABORT, 'new governed proposal must be pending_review'); END;

CREATE TRIGGER IF NOT EXISTS governed_proposal_state_machine
BEFORE UPDATE OF state ON governed_promotion_proposal
WHEN NOT ((OLD.state='pending_review' AND NEW.state IN ('approved','rejected','cancelled','stale')) OR
          (OLD.state='approved' AND NEW.state IN ('published','stale','cancelled')))
BEGIN SELECT RAISE(ABORT, 'invalid governed proposal state transition'); END;

CREATE TRIGGER IF NOT EXISTS governed_proposal_delete_forbidden
BEFORE DELETE ON governed_promotion_proposal
BEGIN SELECT RAISE(ABORT, 'governed proposal is append-only'); END;

CREATE TRIGGER IF NOT EXISTS governed_source_insert_pending
BEFORE INSERT ON governed_promotion_source
WHEN NOT EXISTS (
  SELECT 1 FROM governed_promotion_proposal p
  WHERE p.proposal_id=NEW.proposal_id AND p.state='pending_review'
)
BEGIN SELECT RAISE(ABORT, 'proposal sources are sealed after review'); END;
CREATE TRIGGER IF NOT EXISTS governed_source_update_forbidden
BEFORE UPDATE ON governed_promotion_source
BEGIN SELECT RAISE(ABORT, 'governed proposal source is immutable'); END;
CREATE TRIGGER IF NOT EXISTS governed_source_delete_forbidden
BEFORE DELETE ON governed_promotion_source
BEGIN SELECT RAISE(ABORT, 'governed proposal source is immutable'); END;

CREATE TRIGGER IF NOT EXISTS governed_decision_before_insert
BEFORE INSERT ON governed_promotion_decision
BEGIN
  SELECT CASE
    WHEN NOT EXISTS (
      SELECT 1 FROM governed_promotion_proposal p WHERE p.proposal_id=NEW.proposal_id
      AND p.workspace_id=NEW.workspace_id AND p.principal_id=NEW.principal_id
      AND p.payload_sha256=NEW.proposal_sha256
      AND ((p.deterministic_disposition='novel' AND NEW.selected_disposition='novel') OR
           (p.deterministic_disposition='duplicate' AND NEW.selected_disposition='duplicate') OR
           (p.deterministic_disposition='unresolved' AND NEW.selected_disposition IN ('updates','conflicts','unresolved')))
      AND NOT (NEW.decision='approve' AND NEW.selected_disposition IN ('conflicts','unresolved'))
    ) THEN RAISE(ABORT, 'decision does not match proposal disposition or digest')
    WHEN NEW.decision='approve' AND NOT EXISTS (
      SELECT 1 FROM governed_promotion_proposal p WHERE p.proposal_id=NEW.proposal_id
      AND p.workspace_id=NEW.workspace_id AND p.principal_id=NEW.principal_id
      AND p.state='pending_review' AND p.verification_status=NEW.verification_status
      AND NOT (p.proposer_actor_kind='model' AND p.proposer_actor_id=NEW.reviewer_actor_id)
    ) THEN RAISE(ABORT, 'invalid approval decision')
    WHEN NEW.decision='reject' AND NOT EXISTS (
      SELECT 1 FROM governed_promotion_proposal p WHERE p.proposal_id=NEW.proposal_id
      AND p.workspace_id=NEW.workspace_id AND p.principal_id=NEW.principal_id
      AND p.state='pending_review' AND p.verification_status=NEW.verification_status
    ) THEN RAISE(ABORT, 'invalid rejection decision')
    WHEN NEW.decision='cancel' AND NOT EXISTS (
      SELECT 1 FROM governed_promotion_proposal p WHERE p.proposal_id=NEW.proposal_id
      AND p.workspace_id=NEW.workspace_id AND p.principal_id=NEW.principal_id
      AND p.state IN ('pending_review','approved') AND p.verification_status=NEW.verification_status
    ) THEN RAISE(ABORT, 'invalid cancellation decision')
  END;
END;

CREATE TRIGGER IF NOT EXISTS governed_decision_apply_state
AFTER INSERT ON governed_promotion_decision
BEGIN
  UPDATE governed_promotion_proposal
  SET state=CASE NEW.decision WHEN 'approve' THEN 'approved' WHEN 'reject' THEN 'rejected' ELSE 'cancelled' END,
      state_updated_at=NEW.created_at
  WHERE proposal_id=NEW.proposal_id;
END;

CREATE TRIGGER IF NOT EXISTS governed_decision_update_forbidden
BEFORE UPDATE ON governed_promotion_decision
BEGIN SELECT RAISE(ABORT, 'governed decision is append-only'); END;
CREATE TRIGGER IF NOT EXISTS governed_decision_delete_forbidden
BEFORE DELETE ON governed_promotion_decision
BEGIN SELECT RAISE(ABORT, 'governed decision is append-only'); END;

CREATE TRIGGER IF NOT EXISTS governed_publication_request_update_forbidden
BEFORE UPDATE ON governed_publication_request
BEGIN SELECT RAISE(ABORT, 'governed publication request is append-only'); END;
CREATE TRIGGER IF NOT EXISTS governed_publication_request_delete_forbidden
BEFORE DELETE ON governed_publication_request
BEGIN SELECT RAISE(ABORT, 'governed publication request is append-only'); END;

CREATE TRIGGER IF NOT EXISTS memory_v2_insert_active
BEFORE INSERT ON memory_record_v2 WHEN NEW.status!='active'
BEGIN SELECT RAISE(ABORT, 'new v2 memory must be active'); END;

CREATE TRIGGER IF NOT EXISTS memory_v2_update_guard
BEFORE UPDATE ON memory_record_v2
WHEN NOT (OLD.status='active' AND NEW.status IN ('superseded','retracted')) OR
     NEW.memory_id IS NOT OLD.memory_id OR NEW.workspace_id IS NOT OLD.workspace_id OR
     NEW.principal_id IS NOT OLD.principal_id OR NEW.memory_kind IS NOT OLD.memory_kind OR
     NEW.content IS NOT OLD.content OR NEW.content_sha256 IS NOT OLD.content_sha256 OR
     NEW.confidence IS NOT OLD.confidence OR NEW.salience IS NOT OLD.salience OR
     NEW.source_binding_id IS NOT OLD.source_binding_id OR
     NEW.supersedes_contract_version IS NOT OLD.supersedes_contract_version OR
     NEW.supersedes_memory_id IS NOT OLD.supersedes_memory_id OR NEW.created_at IS NOT OLD.created_at
BEGIN SELECT RAISE(ABORT, 'invalid or mutating v2 memory transition'); END;

CREATE TRIGGER IF NOT EXISTS memory_v2_delete_forbidden
BEFORE DELETE ON memory_record_v2
BEGIN SELECT RAISE(ABORT, 'v2 memory is retained for audit'); END;

CREATE TRIGGER IF NOT EXISTS memory_v1_update_guard
BEFORE UPDATE ON memory_record
WHEN NOT (OLD.status='active' AND NEW.status IN ('superseded','retracted')) OR
     NEW.memory_id IS NOT OLD.memory_id OR NEW.workspace_id IS NOT OLD.workspace_id OR
     NEW.principal_id IS NOT OLD.principal_id OR NEW.memory_kind IS NOT OLD.memory_kind OR
     NEW.content IS NOT OLD.content OR NEW.content_sha256 IS NOT OLD.content_sha256 OR
     NEW.confidence IS NOT OLD.confidence OR NEW.salience IS NOT OLD.salience OR
     NEW.source_citation_id IS NOT OLD.source_citation_id OR
     NEW.supersedes_memory_id IS NOT OLD.supersedes_memory_id OR NEW.created_at IS NOT OLD.created_at
BEGIN SELECT RAISE(ABORT, 'invalid or mutating v1 memory transition'); END;

CREATE TRIGGER IF NOT EXISTS memory_binding_update_forbidden
BEFORE UPDATE ON memory_source_binding
BEGIN SELECT RAISE(ABORT, 'memory source binding is immutable'); END;
CREATE TRIGGER IF NOT EXISTS memory_binding_delete_forbidden
BEFORE DELETE ON memory_source_binding
BEGIN SELECT RAISE(ABORT, 'memory source binding is immutable'); END;
CREATE TRIGGER IF NOT EXISTS memory_binding_working_update_forbidden
BEFORE UPDATE ON memory_source_binding_working
BEGIN SELECT RAISE(ABORT, 'memory source binding source is immutable'); END;
CREATE TRIGGER IF NOT EXISTS memory_binding_working_insert_before_receipt
BEFORE INSERT ON memory_source_binding_working
WHEN EXISTS (
  SELECT 1 FROM memory_source_binding b
  JOIN governed_publication_receipt_v2 r ON r.receipt_id=b.publication_receipt_id
  WHERE b.source_binding_id=NEW.source_binding_id
)
BEGIN SELECT RAISE(ABORT, 'memory source binding sources are sealed'); END;
CREATE TRIGGER IF NOT EXISTS memory_binding_working_delete_forbidden
BEFORE DELETE ON memory_source_binding_working
BEGIN SELECT RAISE(ABORT, 'memory source binding source is immutable'); END;
CREATE TRIGGER IF NOT EXISTS memory_binding_citation_update_forbidden
BEFORE UPDATE ON memory_source_binding_citation
BEGIN SELECT RAISE(ABORT, 'memory source binding citation is immutable'); END;
CREATE TRIGGER IF NOT EXISTS memory_binding_citation_insert_before_receipt
BEFORE INSERT ON memory_source_binding_citation
WHEN EXISTS (
  SELECT 1 FROM memory_source_binding b
  JOIN governed_publication_receipt_v2 r ON r.receipt_id=b.publication_receipt_id
  WHERE b.source_binding_id=NEW.source_binding_id
)
BEGIN SELECT RAISE(ABORT, 'memory source binding citations are sealed'); END;
CREATE TRIGGER IF NOT EXISTS memory_binding_citation_delete_forbidden
BEFORE DELETE ON memory_source_binding_citation
BEGIN SELECT RAISE(ABORT, 'memory source binding citation is immutable'); END;

CREATE TRIGGER IF NOT EXISTS governed_receipt_before_insert
BEFORE INSERT ON governed_publication_receipt_v2
BEGIN
  SELECT CASE
    WHEN NOT EXISTS (
      SELECT 1 FROM governed_promotion_proposal p
      JOIN governed_promotion_decision d
        ON d.decision_id=NEW.decision_id AND d.proposal_id=p.proposal_id
       AND d.workspace_id=p.workspace_id AND d.principal_id=p.principal_id
      WHERE p.proposal_id=NEW.proposal_id AND p.workspace_id=NEW.workspace_id
        AND p.principal_id=NEW.principal_id
        AND p.payload_sha256=NEW.proposal_sha256
        AND d.payload_sha256=NEW.decision_sha256
    ) THEN RAISE(ABORT, 'receipt digest or decision binding does not match stored records')
    WHEN NEW.terminal_result IN ('published_new','published_update') AND NOT EXISTS (
      SELECT 1 FROM memory_source_binding b
      JOIN governed_promotion_proposal p ON p.proposal_id=NEW.proposal_id
      WHERE b.source_binding_id=NEW.source_binding_id
      AND b.memory_id=NEW.target_memory_id
      AND b.workspace_id=NEW.workspace_id AND b.principal_id=NEW.principal_id
      AND b.publication_receipt_id=NEW.receipt_id
      AND b.decision_id=NEW.decision_id
      AND b.provenance_category=p.provenance_category
      AND b.verification_status=p.verification_status
      AND ((b.provenance_category='document_grounded' AND
            (SELECT COUNT(*) FROM memory_source_binding_citation c
             WHERE c.source_binding_id=b.source_binding_id) >= 1) OR
           (b.provenance_category IN ('user_stated','model_proposed') AND
            (SELECT COUNT(*) FROM memory_source_binding_citation c
             WHERE c.source_binding_id=b.source_binding_id) = 0))
    ) THEN RAISE(ABORT, 'receipt target, binding, or citation cardinality is invalid')
    WHEN NEW.terminal_result='published_new' AND NOT EXISTS (
      SELECT 1 FROM memory_record_v2 m
      WHERE m.memory_id=NEW.target_memory_id
        AND m.supersedes_contract_version IS NULL AND m.supersedes_memory_id IS NULL
    ) THEN RAISE(ABORT, 'published_new content cannot supersede a predecessor')
    WHEN NEW.terminal_result='published_update' AND NOT EXISTS (
      SELECT 1 FROM governed_promotion_proposal p
      JOIN memory_record_v2 m ON m.memory_id=NEW.target_memory_id
      WHERE p.proposal_id=NEW.proposal_id
        AND p.target_id=NEW.superseded_memory_id
        AND p.target_contract_version=NEW.superseded_contract_version
        AND m.supersedes_memory_id=NEW.superseded_memory_id
        AND m.supersedes_contract_version=NEW.superseded_contract_version
        AND NEW.target_memory_id<>NEW.superseded_memory_id
    ) THEN RAISE(ABORT, 'published_update predecessor does not match proposal and content')
    WHEN NEW.terminal_result='published_update' AND NEW.superseded_contract_version='pdx_local_memory_record_v1'
     AND NOT EXISTS (
       SELECT 1 FROM memory_record m WHERE m.memory_id=NEW.superseded_memory_id
       AND m.workspace_id=NEW.workspace_id AND m.principal_id=NEW.principal_id
       AND m.status='active'
     ) THEN RAISE(ABORT, 'v1 predecessor is not active in publication scope')
    WHEN NEW.terminal_result='published_update' AND NEW.superseded_contract_version='pdx_local_memory_record_v2'
     AND NOT EXISTS (
       SELECT 1 FROM memory_record_v2 m WHERE m.memory_id=NEW.superseded_memory_id
       AND m.workspace_id=NEW.workspace_id AND m.principal_id=NEW.principal_id
       AND m.status='active'
     ) THEN RAISE(ABORT, 'v2 predecessor is not active in publication scope')
    WHEN NEW.terminal_result IN ('published_new','published_update','duplicate_no_op','stale','failed')
     AND NOT EXISTS (
       SELECT 1 FROM governed_promotion_proposal p JOIN governed_promotion_decision d
       ON d.decision_id=NEW.decision_id AND d.proposal_id=p.proposal_id
       WHERE p.proposal_id=NEW.proposal_id AND p.workspace_id=NEW.workspace_id
       AND p.principal_id=NEW.principal_id AND p.state='approved'
       AND d.decision='approve' AND d.verification_status=NEW.verification_status
     ) THEN RAISE(ABORT, 'publication requires matching approved proposal')
    WHEN NEW.terminal_result='rejected' AND NOT EXISTS (
       SELECT 1 FROM governed_promotion_proposal p JOIN governed_promotion_decision d
       ON d.decision_id=NEW.decision_id AND d.proposal_id=p.proposal_id
       WHERE p.proposal_id=NEW.proposal_id AND p.workspace_id=NEW.workspace_id
       AND p.principal_id=NEW.principal_id AND p.state='rejected' AND d.decision='reject'
     ) THEN RAISE(ABORT, 'rejected receipt requires matching rejection')
  END;
END;

CREATE TRIGGER IF NOT EXISTS governed_receipt_apply_state
AFTER INSERT ON governed_publication_receipt_v2
WHEN NEW.terminal_result IN ('published_new','published_update','duplicate_no_op','stale')
BEGIN
  UPDATE governed_promotion_proposal
  SET state=CASE WHEN NEW.terminal_result='stale' THEN 'stale' ELSE 'published' END,
      state_updated_at=NEW.created_at
  WHERE proposal_id=NEW.proposal_id;
END;

CREATE TRIGGER IF NOT EXISTS governed_receipt_supersede_v1
AFTER INSERT ON governed_publication_receipt_v2
WHEN NEW.terminal_result='published_update'
 AND NEW.superseded_contract_version='pdx_local_memory_record_v1'
BEGIN
  UPDATE memory_record SET status='superseded',updated_at=NEW.created_at
  WHERE memory_id=NEW.superseded_memory_id AND workspace_id=NEW.workspace_id
    AND principal_id=NEW.principal_id AND status='active';
END;

CREATE TRIGGER IF NOT EXISTS governed_receipt_supersede_v2
AFTER INSERT ON governed_publication_receipt_v2
WHEN NEW.terminal_result='published_update'
 AND NEW.superseded_contract_version='pdx_local_memory_record_v2'
BEGIN
  UPDATE memory_record_v2 SET status='superseded',updated_at=NEW.created_at
  WHERE memory_id=NEW.superseded_memory_id AND workspace_id=NEW.workspace_id
    AND principal_id=NEW.principal_id AND status='active';
END;

CREATE TRIGGER IF NOT EXISTS governed_receipt_update_forbidden
BEFORE UPDATE ON governed_publication_receipt_v2
BEGIN SELECT RAISE(ABORT, 'governed receipt is append-only'); END;
CREATE TRIGGER IF NOT EXISTS governed_receipt_delete_forbidden
BEFORE DELETE ON governed_publication_receipt_v2
BEGIN SELECT RAISE(ABORT, 'governed receipt is append-only'); END;

CREATE TRIGGER IF NOT EXISTS memory_v2_event_update_forbidden
BEFORE UPDATE ON memory_v2_event
BEGIN SELECT RAISE(ABORT, 'memory v2 event is append-only'); END;
CREATE TRIGGER IF NOT EXISTS memory_v2_event_delete_forbidden
BEFORE DELETE ON memory_v2_event
BEGIN SELECT RAISE(ABORT, 'memory v2 event is append-only'); END;

CREATE TRIGGER IF NOT EXISTS memory_v2_fts_insert
AFTER INSERT ON memory_record_v2
BEGIN INSERT INTO memory_v2_fts(memory_id,content) VALUES (NEW.memory_id,NEW.content); END;

CREATE TRIGGER IF NOT EXISTS memory_v2_fts_terminal
AFTER UPDATE OF status ON memory_record_v2 WHEN NEW.status IN ('superseded','retracted')
BEGIN DELETE FROM memory_v2_fts WHERE memory_id=NEW.memory_id; END;
