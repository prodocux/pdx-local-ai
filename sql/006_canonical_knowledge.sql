CREATE TABLE IF NOT EXISTS workspace_reviewer_grant_namespace (
  grant_id TEXT NOT NULL,
  namespace TEXT NOT NULL,
  PRIMARY KEY (grant_id, namespace),
  FOREIGN KEY (grant_id) REFERENCES workspace_reviewer_grant(grant_id)
    DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE IF NOT EXISTS workspace_reviewer_grant (
  grant_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  reviewer_actor_id TEXT NOT NULL,
  reviewer_actor_kind TEXT NOT NULL CHECK (reviewer_actor_kind='human'),
  workspace_authority_id TEXT NOT NULL,
  authorized_namespaces_json TEXT NOT NULL CHECK (json_valid(authorized_namespaces_json)),
  status TEXT NOT NULL CHECK (status IN ('active','revoked')),
  issuer_actor_id TEXT NOT NULL,
  payload_json TEXT NOT NULL CHECK (json_valid(payload_json)),
  payload_sha256 TEXT NOT NULL,
  issued_at TEXT NOT NULL,
  revoked_at TEXT,
  UNIQUE (grant_id, workspace_id, reviewer_actor_id, workspace_authority_id),
  CHECK ((status='active' AND revoked_at IS NULL) OR
         (status='revoked' AND revoked_at IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS l3_promotion_proposal (
  proposal_id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL,
  workspace_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  target_id TEXT,
  proposed_content TEXT NOT NULL,
  proposed_content_sha256 TEXT NOT NULL,
  workspace_authority_id TEXT NOT NULL,
  canonical_namespace TEXT NOT NULL,
  subject_key TEXT NOT NULL,
  provenance_category TEXT NOT NULL CHECK (provenance_category='document_grounded'),
  verification_status TEXT NOT NULL CHECK (verification_status='citation_verified'),
  proposer_actor_id TEXT NOT NULL,
  proposer_actor_kind TEXT NOT NULL CHECK (proposer_actor_kind IN ('human','model')),
  deterministic_disposition TEXT NOT NULL CHECK (deterministic_disposition IN ('novel','duplicate','unresolved')),
  state TEXT NOT NULL CHECK (state IN ('pending_review','approved','published','rejected','cancelled','stale')),
  request_fingerprint TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  payload_json TEXT NOT NULL CHECK (json_valid(payload_json)),
  payload_sha256 TEXT NOT NULL,
  created_at TEXT NOT NULL,
  state_updated_at TEXT NOT NULL,
  UNIQUE (proposal_id, workspace_id, principal_id),
  UNIQUE (workspace_id, principal_id, idempotency_key),
  CHECK ((target_id IS NULL AND deterministic_disposition='novel') OR
         (target_id IS NOT NULL AND deterministic_disposition IN ('duplicate','unresolved')))
);

CREATE TABLE IF NOT EXISTS l3_promotion_source (
  proposal_id TEXT PRIMARY KEY REFERENCES l3_promotion_proposal(proposal_id),
  working_memory_id TEXT NOT NULL REFERENCES working_memory(working_memory_id),
  content_sha256 TEXT NOT NULL,
  observed_state TEXT NOT NULL CHECK (observed_state='active'),
  expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS l3_promotion_citation (
  proposal_id TEXT NOT NULL REFERENCES l3_promotion_proposal(proposal_id),
  ordinal INTEGER NOT NULL CHECK (ordinal>=0),
  citation_id TEXT NOT NULL REFERENCES citation(citation_id),
  PRIMARY KEY (proposal_id, ordinal),
  UNIQUE (proposal_id, citation_id)
);

CREATE TABLE IF NOT EXISTS l3_target_binding (
  binding_id TEXT PRIMARY KEY,
  proposal_id TEXT NOT NULL UNIQUE REFERENCES l3_promotion_proposal(proposal_id),
  proposal_sha256 TEXT NOT NULL,
  workspace_id TEXT NOT NULL,
  workspace_authority_id TEXT NOT NULL,
  canonical_namespace TEXT NOT NULL,
  subject_key TEXT NOT NULL,
  deterministic_disposition TEXT NOT NULL CHECK (deterministic_disposition IN ('novel','duplicate','unresolved')),
  canonical_knowledge_id TEXT,
  current_version_id TEXT,
  current_version_number INTEGER CHECK (current_version_number>=1),
  current_content_sha256 TEXT,
  source_working_memory_id TEXT NOT NULL REFERENCES working_memory(working_memory_id),
  source_content_sha256 TEXT NOT NULL,
  authorization_snapshot_sha256 TEXT NOT NULL,
  payload_json TEXT NOT NULL CHECK (json_valid(payload_json)),
  payload_sha256 TEXT NOT NULL,
  created_at TEXT NOT NULL,
  CHECK ((deterministic_disposition='novel' AND canonical_knowledge_id IS NULL AND
          current_version_id IS NULL AND current_version_number IS NULL AND current_content_sha256 IS NULL) OR
         (deterministic_disposition IN ('duplicate','unresolved') AND canonical_knowledge_id IS NOT NULL AND
          current_version_id IS NOT NULL AND current_version_number IS NOT NULL AND current_content_sha256 IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS l3_target_binding_citation (
  binding_id TEXT NOT NULL REFERENCES l3_target_binding(binding_id),
  ordinal INTEGER NOT NULL CHECK (ordinal>=0),
  citation_id TEXT NOT NULL REFERENCES citation(citation_id),
  PRIMARY KEY (binding_id, ordinal),
  UNIQUE (binding_id, citation_id)
);

CREATE TABLE IF NOT EXISTS l3_promotion_decision (
  decision_id TEXT PRIMARY KEY,
  proposal_id TEXT NOT NULL,
  workspace_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  reviewer_actor_id TEXT NOT NULL,
  actor_kind TEXT NOT NULL CHECK (actor_kind='human'),
  decision TEXT NOT NULL CHECK (decision IN ('approve','reject','cancel')),
  selected_disposition TEXT NOT NULL CHECK (selected_disposition IN ('novel','duplicate','updates','conflicts','unresolved')),
  verification_status TEXT NOT NULL CHECK (verification_status='citation_verified'),
  proposal_sha256 TEXT NOT NULL,
  workspace_reviewer_grant_id TEXT NOT NULL,
  workspace_reviewer_grant_sha256 TEXT NOT NULL,
  decision_fingerprint TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  payload_json TEXT NOT NULL CHECK (json_valid(payload_json)),
  payload_sha256 TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE (decision_id, workspace_id, principal_id, proposal_id),
  UNIQUE (workspace_id, principal_id, idempotency_key),
  FOREIGN KEY (proposal_id, workspace_id, principal_id)
    REFERENCES l3_promotion_proposal(proposal_id, workspace_id, principal_id)
);

CREATE TABLE IF NOT EXISTS l3_publication_request (
  publication_request_id TEXT PRIMARY KEY,
  proposal_id TEXT NOT NULL,
  decision_id TEXT NOT NULL,
  workspace_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  requesting_actor_id TEXT NOT NULL,
  request_fingerprint TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  payload_json TEXT NOT NULL CHECK (json_valid(payload_json)),
  payload_sha256 TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE (workspace_id, principal_id, idempotency_key),
  FOREIGN KEY (proposal_id, workspace_id, principal_id)
    REFERENCES l3_promotion_proposal(proposal_id, workspace_id, principal_id),
  FOREIGN KEY (decision_id, workspace_id, principal_id, proposal_id)
    REFERENCES l3_promotion_decision(decision_id, workspace_id, principal_id, proposal_id)
);

CREATE TABLE IF NOT EXISTS canonical_knowledge (
  canonical_knowledge_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  workspace_authority_id TEXT NOT NULL,
  canonical_namespace TEXT NOT NULL,
  subject_key TEXT NOT NULL,
  current_version_id TEXT,
  status TEXT NOT NULL CHECK (status IN ('active','withdrawn')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (workspace_id, workspace_authority_id, canonical_namespace, subject_key),
  UNIQUE (canonical_knowledge_id, workspace_id, workspace_authority_id),
  CHECK ((status='active' AND current_version_id IS NOT NULL) OR
         (status='withdrawn' AND current_version_id IS NULL)),
  FOREIGN KEY (current_version_id, canonical_knowledge_id)
    REFERENCES canonical_knowledge_version(version_id, canonical_knowledge_id)
    DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE IF NOT EXISTS canonical_knowledge_version (
  version_id TEXT PRIMARY KEY,
  canonical_knowledge_id TEXT NOT NULL,
  version_number INTEGER NOT NULL CHECK (version_number>=1),
  workspace_id TEXT NOT NULL,
  content TEXT NOT NULL,
  content_sha256 TEXT NOT NULL,
  provenance_category TEXT NOT NULL CHECK (provenance_category='document_grounded'),
  verification_status TEXT NOT NULL CHECK (verification_status='citation_verified'),
  workspace_authority_id TEXT NOT NULL,
  workspace_reviewer_id TEXT NOT NULL,
  workspace_reviewer_grant_sha256 TEXT NOT NULL,
  supersedes_version_id TEXT,
  publication_receipt_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE (canonical_knowledge_id, version_number),
  UNIQUE (version_id, canonical_knowledge_id),
  FOREIGN KEY (canonical_knowledge_id, workspace_id, workspace_authority_id)
    REFERENCES canonical_knowledge(canonical_knowledge_id, workspace_id, workspace_authority_id)
    DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (supersedes_version_id, canonical_knowledge_id)
    REFERENCES canonical_knowledge_version(version_id, canonical_knowledge_id),
  FOREIGN KEY (publication_receipt_id) REFERENCES l3_publication_receipt(receipt_id)
    DEFERRABLE INITIALLY DEFERRED,
  CHECK ((version_number=1 AND supersedes_version_id IS NULL) OR
         (version_number>1 AND supersedes_version_id IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS canonical_knowledge_version_citation (
  version_id TEXT NOT NULL REFERENCES canonical_knowledge_version(version_id),
  ordinal INTEGER NOT NULL CHECK (ordinal>=0),
  citation_id TEXT NOT NULL REFERENCES citation(citation_id),
  PRIMARY KEY (version_id, ordinal),
  UNIQUE (version_id, citation_id)
);

CREATE TABLE IF NOT EXISTS l3_publication_receipt (
  receipt_id TEXT PRIMARY KEY,
  publication_request_id TEXT NOT NULL REFERENCES l3_publication_request(publication_request_id),
  proposal_id TEXT NOT NULL,
  decision_id TEXT NOT NULL,
  target_binding_id TEXT NOT NULL REFERENCES l3_target_binding(binding_id),
  workspace_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  terminal_result TEXT NOT NULL CHECK (terminal_result IN ('published_new','published_update','duplicate_no_op','stale','rejected')),
  disposition TEXT NOT NULL CHECK (disposition IN ('novel','duplicate','updates')),
  target_id TEXT,
  target_version_id TEXT,
  target_content_sha256 TEXT NOT NULL,
  proposal_sha256 TEXT NOT NULL,
  decision_sha256 TEXT NOT NULL,
  verification_status TEXT NOT NULL CHECK (verification_status='citation_verified'),
  authority_id TEXT NOT NULL,
  authority_binding_sha256 TEXT NOT NULL,
  created_target_ids_json TEXT NOT NULL CHECK (json_valid(created_target_ids_json)),
  superseded_target_ids_json TEXT NOT NULL CHECK (json_valid(superseded_target_ids_json)),
  publication_fingerprint TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  receipt_json TEXT NOT NULL CHECK (json_valid(receipt_json)),
  receipt_sha256 TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE (workspace_id, principal_id, idempotency_key),
  FOREIGN KEY (proposal_id, workspace_id, principal_id)
    REFERENCES l3_promotion_proposal(proposal_id, workspace_id, principal_id),
  FOREIGN KEY (decision_id, workspace_id, principal_id, proposal_id)
    REFERENCES l3_promotion_decision(decision_id, workspace_id, principal_id, proposal_id),
  FOREIGN KEY (target_version_id, target_id)
    REFERENCES canonical_knowledge_version(version_id, canonical_knowledge_id)
    DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE IF NOT EXISTS canonical_knowledge_event (
  event_id TEXT PRIMARY KEY,
  canonical_knowledge_id TEXT NOT NULL REFERENCES canonical_knowledge(canonical_knowledge_id),
  version_id TEXT,
  event_type TEXT NOT NULL CHECK (event_type IN ('created','version_published','withdrawn')),
  event_json TEXT NOT NULL CHECK (json_valid(event_json)),
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS canonical_withdrawal_request (
  withdrawal_request_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  canonical_knowledge_id TEXT NOT NULL REFERENCES canonical_knowledge(canonical_knowledge_id),
  observed_current_version_id TEXT NOT NULL,
  canonical_namespace TEXT NOT NULL,
  workspace_authority_id TEXT NOT NULL,
  reviewer_actor_id TEXT NOT NULL,
  workspace_reviewer_grant_id TEXT NOT NULL,
  workspace_reviewer_grant_sha256 TEXT NOT NULL,
  reason_code TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  request_fingerprint TEXT NOT NULL,
  request_json TEXT NOT NULL CHECK (json_valid(request_json)),
  request_sha256 TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE (workspace_id, workspace_authority_id, idempotency_key),
  FOREIGN KEY (workspace_reviewer_grant_id, workspace_id, reviewer_actor_id, workspace_authority_id)
    REFERENCES workspace_reviewer_grant(grant_id, workspace_id, reviewer_actor_id, workspace_authority_id)
);

CREATE TABLE IF NOT EXISTS canonical_withdrawal_receipt (
  withdrawal_receipt_id TEXT PRIMARY KEY,
  withdrawal_request_id TEXT NOT NULL UNIQUE REFERENCES canonical_withdrawal_request(withdrawal_request_id),
  workspace_id TEXT NOT NULL,
  canonical_knowledge_id TEXT NOT NULL REFERENCES canonical_knowledge(canonical_knowledge_id),
  workspace_authority_id TEXT NOT NULL,
  terminal_result TEXT NOT NULL CHECK (terminal_result IN ('withdrawn','stale','rejected')),
  status_before TEXT NOT NULL CHECK (status_before='active'),
  status_after TEXT NOT NULL CHECK (status_after IN ('active','withdrawn')),
  current_version_id_before TEXT NOT NULL,
  current_version_id_after TEXT,
  workspace_reviewer_grant_id TEXT NOT NULL,
  workspace_reviewer_grant_sha256 TEXT NOT NULL,
  identity_snapshot_sha256 TEXT NOT NULL,
  mutation_applied INTEGER NOT NULL CHECK (mutation_applied IN (0,1)),
  idempotency_key TEXT NOT NULL,
  receipt_json TEXT NOT NULL CHECK (json_valid(receipt_json)),
  receipt_sha256 TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE (workspace_id, workspace_authority_id, idempotency_key),
  CHECK ((terminal_result='withdrawn' AND status_after='withdrawn' AND current_version_id_after IS NULL AND mutation_applied=1) OR
         (terminal_result IN ('stale','rejected') AND status_after='active' AND
          current_version_id_after=current_version_id_before AND mutation_applied=0))
);

CREATE TRIGGER IF NOT EXISTS reviewer_namespace_insert_guard
BEFORE INSERT ON workspace_reviewer_grant_namespace
WHEN EXISTS (SELECT 1 FROM workspace_reviewer_grant WHERE grant_id=NEW.grant_id)
BEGIN SELECT RAISE(ABORT,'reviewer grant namespaces are sealed'); END;
CREATE TRIGGER IF NOT EXISTS reviewer_namespace_update_forbidden BEFORE UPDATE ON workspace_reviewer_grant_namespace
BEGIN SELECT RAISE(ABORT,'reviewer grant namespaces are immutable'); END;
CREATE TRIGGER IF NOT EXISTS reviewer_namespace_delete_forbidden BEFORE DELETE ON workspace_reviewer_grant_namespace
BEGIN SELECT RAISE(ABORT,'reviewer grant namespaces are immutable'); END;

CREATE TRIGGER IF NOT EXISTS reviewer_grant_before_insert
BEFORE INSERT ON workspace_reviewer_grant
BEGIN
  SELECT CASE WHEN json_array_length(NEW.authorized_namespaces_json)<1
    THEN RAISE(ABORT,'reviewer grant needs a namespace') END;
  SELECT CASE WHEN (SELECT COUNT(*) FROM workspace_reviewer_grant_namespace WHERE grant_id=NEW.grant_id)
    <> json_array_length(NEW.authorized_namespaces_json)
    THEN RAISE(ABORT,'reviewer grant namespace count mismatch') END;
  SELECT CASE WHEN EXISTS (
    SELECT value FROM json_each(NEW.authorized_namespaces_json)
    EXCEPT SELECT namespace FROM workspace_reviewer_grant_namespace WHERE grant_id=NEW.grant_id
  ) THEN RAISE(ABORT,'reviewer grant namespace set mismatch') END;
END;

CREATE TRIGGER IF NOT EXISTS reviewer_grant_update_guard
BEFORE UPDATE ON workspace_reviewer_grant
WHEN NOT (OLD.status='active' AND NEW.status='revoked' AND OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL) OR
 NEW.grant_id IS NOT OLD.grant_id OR NEW.workspace_id IS NOT OLD.workspace_id OR
 NEW.reviewer_actor_id IS NOT OLD.reviewer_actor_id OR NEW.reviewer_actor_kind IS NOT OLD.reviewer_actor_kind OR
 NEW.workspace_authority_id IS NOT OLD.workspace_authority_id OR
 NEW.authorized_namespaces_json IS NOT OLD.authorized_namespaces_json OR
 NEW.issuer_actor_id IS NOT OLD.issuer_actor_id OR NEW.issued_at IS NOT OLD.issued_at
BEGIN SELECT RAISE(ABORT,'invalid reviewer grant transition'); END;
CREATE TRIGGER IF NOT EXISTS reviewer_grant_delete_forbidden BEFORE DELETE ON workspace_reviewer_grant
BEGIN SELECT RAISE(ABORT,'reviewer grant is retained'); END;

CREATE TRIGGER IF NOT EXISTS l3_proposal_insert_pending BEFORE INSERT ON l3_promotion_proposal
WHEN NEW.state!='pending_review'
BEGIN SELECT RAISE(ABORT,'new L3 proposal must be pending_review'); END;
CREATE TRIGGER IF NOT EXISTS l3_proposal_update_guard BEFORE UPDATE ON l3_promotion_proposal
WHEN NOT ((OLD.state='pending_review' AND NEW.state IN ('approved','rejected','cancelled','stale')) OR
          (OLD.state='approved' AND NEW.state IN ('published','stale','cancelled'))) OR
 NEW.proposal_id IS NOT OLD.proposal_id OR NEW.request_id IS NOT OLD.request_id OR
 NEW.workspace_id IS NOT OLD.workspace_id OR NEW.principal_id IS NOT OLD.principal_id OR
 NEW.target_id IS NOT OLD.target_id OR NEW.proposed_content IS NOT OLD.proposed_content OR
 NEW.proposed_content_sha256 IS NOT OLD.proposed_content_sha256 OR
 NEW.workspace_authority_id IS NOT OLD.workspace_authority_id OR
 NEW.canonical_namespace IS NOT OLD.canonical_namespace OR NEW.subject_key IS NOT OLD.subject_key OR
 NEW.provenance_category IS NOT OLD.provenance_category OR NEW.verification_status IS NOT OLD.verification_status OR
 NEW.proposer_actor_id IS NOT OLD.proposer_actor_id OR NEW.proposer_actor_kind IS NOT OLD.proposer_actor_kind OR
 NEW.deterministic_disposition IS NOT OLD.deterministic_disposition OR
 NEW.request_fingerprint IS NOT OLD.request_fingerprint OR NEW.idempotency_key IS NOT OLD.idempotency_key OR
 NEW.payload_json IS NOT OLD.payload_json OR NEW.payload_sha256 IS NOT OLD.payload_sha256 OR NEW.created_at IS NOT OLD.created_at
BEGIN SELECT RAISE(ABORT,'invalid or mutating L3 proposal transition'); END;
CREATE TRIGGER IF NOT EXISTS l3_proposal_delete_forbidden BEFORE DELETE ON l3_promotion_proposal
BEGIN SELECT RAISE(ABORT,'L3 proposal is retained'); END;

CREATE TRIGGER IF NOT EXISTS l3_source_update_forbidden BEFORE UPDATE ON l3_promotion_source
BEGIN SELECT RAISE(ABORT,'L3 source is immutable'); END;
CREATE TRIGGER IF NOT EXISTS l3_source_delete_forbidden BEFORE DELETE ON l3_promotion_source
BEGIN SELECT RAISE(ABORT,'L3 source is immutable'); END;
CREATE TRIGGER IF NOT EXISTS l3_citation_update_forbidden BEFORE UPDATE ON l3_promotion_citation
BEGIN SELECT RAISE(ABORT,'L3 citation is immutable'); END;
CREATE TRIGGER IF NOT EXISTS l3_citation_delete_forbidden BEFORE DELETE ON l3_promotion_citation
BEGIN SELECT RAISE(ABORT,'L3 citation is immutable'); END;

CREATE TRIGGER IF NOT EXISTS l3_binding_update_forbidden BEFORE UPDATE ON l3_target_binding
BEGIN SELECT RAISE(ABORT,'L3 target binding is immutable'); END;
CREATE TRIGGER IF NOT EXISTS l3_binding_delete_forbidden BEFORE DELETE ON l3_target_binding
BEGIN SELECT RAISE(ABORT,'L3 target binding is immutable'); END;
CREATE TRIGGER IF NOT EXISTS l3_binding_citation_update_forbidden BEFORE UPDATE ON l3_target_binding_citation
BEGIN SELECT RAISE(ABORT,'L3 target binding citation is immutable'); END;
CREATE TRIGGER IF NOT EXISTS l3_binding_citation_delete_forbidden BEFORE DELETE ON l3_target_binding_citation
BEGIN SELECT RAISE(ABORT,'L3 target binding citation is immutable'); END;

CREATE TRIGGER IF NOT EXISTS l3_decision_before_insert BEFORE INSERT ON l3_promotion_decision
BEGIN
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1 FROM l3_promotion_proposal p
    JOIN workspace_reviewer_grant g ON g.grant_id=NEW.workspace_reviewer_grant_id
    JOIN workspace_reviewer_grant_namespace n ON n.grant_id=g.grant_id AND n.namespace=p.canonical_namespace
    WHERE p.proposal_id=NEW.proposal_id AND p.workspace_id=NEW.workspace_id AND p.principal_id=NEW.principal_id
      AND p.payload_sha256=NEW.proposal_sha256 AND p.verification_status=NEW.verification_status
      AND p.state IN ('pending_review','approved')
      AND NOT (p.proposer_actor_kind='model' AND p.proposer_actor_id=NEW.reviewer_actor_id)
      AND g.status='active' AND g.payload_sha256=NEW.workspace_reviewer_grant_sha256
      AND g.workspace_id=p.workspace_id AND g.workspace_authority_id=p.workspace_authority_id
      AND g.reviewer_actor_id=NEW.reviewer_actor_id
      AND ((p.deterministic_disposition='novel' AND NEW.selected_disposition='novel') OR
           (p.deterministic_disposition='duplicate' AND NEW.selected_disposition='duplicate') OR
           (p.deterministic_disposition='unresolved' AND NEW.decision='approve' AND NEW.selected_disposition='updates') OR
           (p.deterministic_disposition='unresolved' AND NEW.decision IN ('reject','cancel') AND NEW.selected_disposition IN ('updates','conflicts','unresolved')))
  ) THEN RAISE(ABORT,'invalid L3 decision') END;
END;
CREATE TRIGGER IF NOT EXISTS l3_decision_apply_state AFTER INSERT ON l3_promotion_decision
BEGIN
 UPDATE l3_promotion_proposal SET state=CASE NEW.decision WHEN 'approve' THEN 'approved' WHEN 'reject' THEN 'rejected' ELSE 'cancelled' END,
 state_updated_at=NEW.created_at WHERE proposal_id=NEW.proposal_id;
END;
CREATE TRIGGER IF NOT EXISTS l3_decision_update_forbidden BEFORE UPDATE ON l3_promotion_decision
BEGIN SELECT RAISE(ABORT,'L3 decision is immutable'); END;
CREATE TRIGGER IF NOT EXISTS l3_decision_delete_forbidden BEFORE DELETE ON l3_promotion_decision
BEGIN SELECT RAISE(ABORT,'L3 decision is immutable'); END;

CREATE TRIGGER IF NOT EXISTS l3_publication_request_before_insert BEFORE INSERT ON l3_publication_request
WHEN NOT EXISTS (
 SELECT 1 FROM l3_promotion_decision d WHERE d.decision_id=NEW.decision_id AND d.proposal_id=NEW.proposal_id
 AND d.workspace_id=NEW.workspace_id AND d.principal_id=NEW.principal_id
 AND (d.decision='approve' OR (d.decision='reject' AND d.selected_disposition IN ('novel','duplicate','updates')))
)
BEGIN SELECT RAISE(ABORT,'decision cannot enter L3 publication'); END;
CREATE TRIGGER IF NOT EXISTS l3_publication_request_update_forbidden BEFORE UPDATE ON l3_publication_request
BEGIN SELECT RAISE(ABORT,'L3 publication request is immutable'); END;
CREATE TRIGGER IF NOT EXISTS l3_publication_request_delete_forbidden BEFORE DELETE ON l3_publication_request
BEGIN SELECT RAISE(ABORT,'L3 publication request is immutable'); END;

CREATE TRIGGER IF NOT EXISTS canonical_version_before_insert BEFORE INSERT ON canonical_knowledge_version
BEGIN
 SELECT CASE WHEN NEW.version_number>1 AND NOT EXISTS (
  SELECT 1 FROM canonical_knowledge_version v WHERE v.version_id=NEW.supersedes_version_id
  AND v.canonical_knowledge_id=NEW.canonical_knowledge_id AND v.version_number=NEW.version_number-1
 ) THEN RAISE(ABORT,'canonical version is not N+1') END;
END;
CREATE TRIGGER IF NOT EXISTS canonical_version_update_forbidden BEFORE UPDATE ON canonical_knowledge_version
BEGIN SELECT RAISE(ABORT,'canonical version is immutable'); END;
CREATE TRIGGER IF NOT EXISTS canonical_version_delete_forbidden BEFORE DELETE ON canonical_knowledge_version
BEGIN SELECT RAISE(ABORT,'canonical version is immutable'); END;
CREATE TRIGGER IF NOT EXISTS canonical_version_citation_update_forbidden BEFORE UPDATE ON canonical_knowledge_version_citation
BEGIN SELECT RAISE(ABORT,'canonical version citation is immutable'); END;
CREATE TRIGGER IF NOT EXISTS canonical_version_citation_delete_forbidden BEFORE DELETE ON canonical_knowledge_version_citation
BEGIN SELECT RAISE(ABORT,'canonical version citation is immutable'); END;

CREATE TRIGGER IF NOT EXISTS canonical_identity_update_guard BEFORE UPDATE ON canonical_knowledge
WHEN NEW.canonical_knowledge_id IS NOT OLD.canonical_knowledge_id OR NEW.workspace_id IS NOT OLD.workspace_id OR
 NEW.workspace_authority_id IS NOT OLD.workspace_authority_id OR NEW.canonical_namespace IS NOT OLD.canonical_namespace OR
 NEW.subject_key IS NOT OLD.subject_key OR NEW.created_at IS NOT OLD.created_at OR
 NOT ((OLD.status='active' AND NEW.status='active' AND NEW.current_version_id IS NOT OLD.current_version_id AND
       EXISTS (SELECT 1 FROM l3_publication_receipt r WHERE r.terminal_result='published_update'
               AND r.target_id=OLD.canonical_knowledge_id AND r.target_version_id=NEW.current_version_id)) OR
      (OLD.status='active' AND NEW.status='withdrawn' AND NEW.current_version_id IS NULL AND
       EXISTS (SELECT 1 FROM canonical_withdrawal_receipt r WHERE r.terminal_result='withdrawn'
               AND r.canonical_knowledge_id=OLD.canonical_knowledge_id
               AND r.current_version_id_before=OLD.current_version_id)))
BEGIN SELECT RAISE(ABORT,'invalid canonical identity transition'); END;
CREATE TRIGGER IF NOT EXISTS canonical_identity_insert_active BEFORE INSERT ON canonical_knowledge
WHEN NEW.status!='active' OR NEW.current_version_id IS NULL
BEGIN SELECT RAISE(ABORT,'new canonical identity must be active at version 1'); END;
CREATE TRIGGER IF NOT EXISTS canonical_identity_delete_forbidden BEFORE DELETE ON canonical_knowledge
BEGIN SELECT RAISE(ABORT,'canonical identity is retained'); END;

CREATE TRIGGER IF NOT EXISTS l3_receipt_before_insert BEFORE INSERT ON l3_publication_receipt
BEGIN
 SELECT CASE WHEN NEW.terminal_result='failed' THEN RAISE(ABORT,'failed L3 receipt is forbidden') END;
 SELECT CASE WHEN NOT EXISTS (
  SELECT 1 FROM l3_publication_request r
  JOIN l3_promotion_decision d ON d.decision_id=NEW.decision_id AND d.proposal_id=NEW.proposal_id
  JOIN l3_promotion_proposal p ON p.proposal_id=NEW.proposal_id
  JOIN l3_target_binding b ON b.binding_id=NEW.target_binding_id AND b.proposal_id=p.proposal_id
  WHERE r.publication_request_id=NEW.publication_request_id AND r.proposal_id=p.proposal_id AND r.decision_id=d.decision_id
    AND p.workspace_id=NEW.workspace_id AND p.principal_id=NEW.principal_id
    AND p.payload_sha256=NEW.proposal_sha256 AND d.payload_sha256=NEW.decision_sha256
    AND d.selected_disposition=NEW.disposition AND p.verification_status=NEW.verification_status
    AND p.workspace_authority_id=NEW.authority_id AND b.payload_sha256=NEW.authority_binding_sha256
    AND ((NEW.terminal_result IN ('published_new','published_update','duplicate_no_op','stale') AND d.decision='approve' AND p.state='approved') OR
         (NEW.terminal_result='rejected' AND d.decision='reject' AND p.state='rejected'))
 ) THEN RAISE(ABORT,'L3 receipt does not match governance records') END;
 SELECT CASE WHEN NEW.terminal_result='published_new' AND NOT (
   NEW.disposition='novel' AND NEW.target_id IS NOT NULL AND NEW.target_version_id IS NOT NULL AND
   json_array_length(NEW.created_target_ids_json)=2 AND json_array_length(NEW.superseded_target_ids_json)=0 AND
   json_extract(NEW.created_target_ids_json,'$[0]')=NEW.target_id AND
   json_extract(NEW.created_target_ids_json,'$[1]')=NEW.target_version_id AND
   EXISTS (SELECT 1 FROM canonical_knowledge k JOIN canonical_knowledge_version v
     ON v.version_id=NEW.target_version_id AND v.canonical_knowledge_id=k.canonical_knowledge_id
     WHERE k.canonical_knowledge_id=NEW.target_id AND k.current_version_id=v.version_id
       AND v.version_number=1 AND v.supersedes_version_id IS NULL AND v.publication_receipt_id=NEW.receipt_id)
   AND (SELECT COUNT(*) FROM canonical_knowledge_version_citation c
        WHERE c.version_id=NEW.target_version_id)>=1
 ) THEN RAISE(ABORT,'invalid published_new receipt') END;
 SELECT CASE WHEN NEW.terminal_result='published_update' AND NOT (
   NEW.disposition='updates' AND NEW.target_id IS NOT NULL AND NEW.target_version_id IS NOT NULL AND
   json_array_length(NEW.created_target_ids_json)=1 AND json_array_length(NEW.superseded_target_ids_json)=1 AND
   json_extract(NEW.created_target_ids_json,'$[0]')=NEW.target_version_id AND
   EXISTS (SELECT 1 FROM l3_target_binding b JOIN canonical_knowledge_version v
     ON v.version_id=NEW.target_version_id AND v.canonical_knowledge_id=b.canonical_knowledge_id
     WHERE b.binding_id=NEW.target_binding_id AND b.current_version_id=v.supersedes_version_id
       AND b.current_version_number=v.version_number-1 AND b.canonical_knowledge_id=NEW.target_id
       AND v.publication_receipt_id=NEW.receipt_id)
   AND EXISTS (SELECT 1 FROM l3_target_binding b WHERE b.binding_id=NEW.target_binding_id
        AND json_extract(NEW.superseded_target_ids_json,'$[0]')=b.current_version_id)
   AND (SELECT COUNT(*) FROM canonical_knowledge_version_citation c
        WHERE c.version_id=NEW.target_version_id)>=1
   AND EXISTS (SELECT 1 FROM canonical_knowledge k JOIN l3_target_binding b
     ON b.canonical_knowledge_id=k.canonical_knowledge_id WHERE b.binding_id=NEW.target_binding_id
     AND k.status='active' AND k.current_version_id=b.current_version_id)
 ) THEN RAISE(ABORT,'invalid published_update receipt') END;
 SELECT CASE WHEN NEW.terminal_result='duplicate_no_op' AND NOT (
   NEW.disposition='duplicate' AND NEW.target_version_id IS NULL AND
   json_array_length(NEW.created_target_ids_json)=0 AND json_array_length(NEW.superseded_target_ids_json)=0 AND
   EXISTS (
     SELECT 1 FROM l3_target_binding b
     JOIN canonical_knowledge k ON k.canonical_knowledge_id=b.canonical_knowledge_id
     JOIN canonical_knowledge_version v ON v.version_id=k.current_version_id
       AND v.canonical_knowledge_id=k.canonical_knowledge_id
     WHERE b.binding_id=NEW.target_binding_id
       AND NEW.target_id=b.canonical_knowledge_id
       AND k.status='active'
       AND k.workspace_id=NEW.workspace_id
       AND k.workspace_authority_id=b.workspace_authority_id
       AND k.canonical_namespace=b.canonical_namespace
       AND k.subject_key=b.subject_key
       AND k.current_version_id=b.current_version_id
       AND v.version_number=b.current_version_number
       AND v.content_sha256=b.current_content_sha256
       AND NEW.target_content_sha256=b.current_content_sha256
   )
 ) THEN RAISE(ABORT,'invalid duplicate receipt') END;
 SELECT CASE WHEN NEW.terminal_result IN ('stale','rejected') AND NOT (
   NEW.target_version_id IS NULL AND json_array_length(NEW.created_target_ids_json)=0 AND
   json_array_length(NEW.superseded_target_ids_json)=0
 ) THEN RAISE(ABORT,'terminal receipt must not mutate L3') END;
END;
CREATE TRIGGER IF NOT EXISTS l3_receipt_apply_state AFTER INSERT ON l3_publication_receipt
WHEN NEW.terminal_result IN ('published_new','published_update','duplicate_no_op','stale')
BEGIN
 UPDATE l3_promotion_proposal SET state=CASE WHEN NEW.terminal_result='stale' THEN 'stale' ELSE 'published' END,
 state_updated_at=NEW.created_at WHERE proposal_id=NEW.proposal_id;
END;
CREATE TRIGGER IF NOT EXISTS l3_receipt_advance_pointer AFTER INSERT ON l3_publication_receipt
WHEN NEW.terminal_result='published_update'
BEGIN
 UPDATE canonical_knowledge SET current_version_id=NEW.target_version_id,updated_at=NEW.created_at
 WHERE canonical_knowledge_id=NEW.target_id AND status='active';
END;
CREATE TRIGGER IF NOT EXISTS l3_receipt_update_forbidden BEFORE UPDATE ON l3_publication_receipt
BEGIN SELECT RAISE(ABORT,'L3 publication receipt is immutable'); END;
CREATE TRIGGER IF NOT EXISTS l3_receipt_delete_forbidden BEFORE DELETE ON l3_publication_receipt
BEGIN SELECT RAISE(ABORT,'L3 publication receipt is immutable'); END;

CREATE TRIGGER IF NOT EXISTS canonical_event_update_forbidden BEFORE UPDATE ON canonical_knowledge_event
BEGIN SELECT RAISE(ABORT,'canonical event is immutable'); END;
CREATE TRIGGER IF NOT EXISTS canonical_event_delete_forbidden BEFORE DELETE ON canonical_knowledge_event
BEGIN SELECT RAISE(ABORT,'canonical event is immutable'); END;

CREATE TRIGGER IF NOT EXISTS withdrawal_request_before_insert BEFORE INSERT ON canonical_withdrawal_request
WHEN NOT EXISTS (
 SELECT 1 FROM canonical_knowledge k JOIN workspace_reviewer_grant g
 ON g.grant_id=NEW.workspace_reviewer_grant_id JOIN workspace_reviewer_grant_namespace n
 ON n.grant_id=g.grant_id AND n.namespace=NEW.canonical_namespace
 WHERE k.canonical_knowledge_id=NEW.canonical_knowledge_id AND k.workspace_id=NEW.workspace_id
 AND k.workspace_authority_id=NEW.workspace_authority_id AND k.canonical_namespace=NEW.canonical_namespace
 AND k.status='active' AND k.current_version_id=NEW.observed_current_version_id
 AND g.status='active' AND g.reviewer_actor_id=NEW.reviewer_actor_id
 AND g.workspace_id=NEW.workspace_id AND g.workspace_authority_id=NEW.workspace_authority_id
 AND g.payload_sha256=NEW.workspace_reviewer_grant_sha256
)
BEGIN SELECT RAISE(ABORT,'invalid canonical withdrawal request'); END;
CREATE TRIGGER IF NOT EXISTS withdrawal_request_update_forbidden BEFORE UPDATE ON canonical_withdrawal_request
BEGIN SELECT RAISE(ABORT,'withdrawal request is immutable'); END;
CREATE TRIGGER IF NOT EXISTS withdrawal_request_delete_forbidden BEFORE DELETE ON canonical_withdrawal_request
BEGIN SELECT RAISE(ABORT,'withdrawal request is immutable'); END;

CREATE TRIGGER IF NOT EXISTS withdrawal_receipt_before_insert BEFORE INSERT ON canonical_withdrawal_receipt
BEGIN
 SELECT CASE WHEN NOT EXISTS (
  SELECT 1 FROM canonical_withdrawal_request r JOIN canonical_knowledge k
  ON k.canonical_knowledge_id=r.canonical_knowledge_id
  WHERE r.withdrawal_request_id=NEW.withdrawal_request_id AND r.workspace_id=NEW.workspace_id
  AND r.workspace_authority_id=NEW.workspace_authority_id AND r.canonical_knowledge_id=NEW.canonical_knowledge_id
  AND r.workspace_reviewer_grant_id=NEW.workspace_reviewer_grant_id
  AND r.workspace_reviewer_grant_sha256=NEW.workspace_reviewer_grant_sha256
  AND k.status='active' AND k.current_version_id=NEW.current_version_id_before
 ) THEN RAISE(ABORT,'withdrawal receipt snapshot mismatch') END;
END;
CREATE TRIGGER IF NOT EXISTS withdrawal_receipt_apply AFTER INSERT ON canonical_withdrawal_receipt
WHEN NEW.terminal_result='withdrawn'
BEGIN
 UPDATE canonical_knowledge SET status='withdrawn',current_version_id=NULL,updated_at=NEW.created_at
 WHERE canonical_knowledge_id=NEW.canonical_knowledge_id AND status='active'
 AND current_version_id=NEW.current_version_id_before;
END;
CREATE TRIGGER IF NOT EXISTS withdrawal_receipt_update_forbidden BEFORE UPDATE ON canonical_withdrawal_receipt
BEGIN SELECT RAISE(ABORT,'withdrawal receipt is immutable'); END;
CREATE TRIGGER IF NOT EXISTS withdrawal_receipt_delete_forbidden BEFORE DELETE ON canonical_withdrawal_receipt
BEGIN SELECT RAISE(ABORT,'withdrawal receipt is immutable'); END;
