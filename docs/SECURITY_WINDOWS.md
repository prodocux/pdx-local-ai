# Windows filesystem security

## Path boundary

- Resolve the configured source root once and persist its canonical identity.
- Every discovered target must resolve beneath that root.
- Symlinks, junctions, mount points, and other reparse points are rejected by
  default, including reparse points encountered in ancestor directories.
- UNC paths, device paths such as `\\?\` and `\\.\`, and NTFS alternate data
  streams are rejected unless a future policy explicitly enables and tests
  them.
- User-supplied relative traversal never becomes an extraction path.
- A source root is a canonical absolute local drive path. The drive-letter
  colon is the only permitted colon. UNC/device namespaces, ADS, relative
  roots, non-normalized components, trailing dot/space components, and DOS
  device names (`CON`, `NUL`, `AUX`, `PRN`, `COM1`-`COM9`, `LPT1`-`LPT9`) are
  rejected by contract validation.
- Runtime must additionally open and inspect the root and every ancestor for
  reparse points; string validation cannot establish this property.

## Handle and snapshot rule

Path validation alone does not prevent time-of-check/time-of-use replacement.
For every indexing attempt:

1. Safely open a file handle without following an unapproved reparse point.
2. Obtain file identity, volume identity, size, and timestamps from that handle.
3. Hash bytes read from that same handle.
4. If the parser cannot consume the handle, create a private controlled
   snapshot from those bytes and extract only from the snapshot.
5. Recheck handle identity and source state after extraction.
6. Publish nothing if identity, size, timestamp, or digest is inconsistent.

The snapshot directory is outside the indexed root, is not user-addressable,
and is cleaned through a separately tested lifecycle. ProDocuX must never be
given a newly reopened untrusted source path after validation.

## Identity semantics

- SHA-256 identifies equal content, not a catalog object.
- Equal SHA-256 values may represent copies or hardlinks.
- A Windows volume/file identifier may help classify a rename on one volume,
  but is not a stable cross-volume identity.
- Watcher events are hints. Periodic reconciliation against the allowlisted
  root is authoritative.

## ACL

Gate 0 uses product workspace ACL plus the operating-system access of the
service account. A document is eligible only when both permit reading.

ACL predicates are enforced inside the SQLite retrieval query. Tests and query
plan audits must prove that unauthorized rows cannot be returned to application
code. Unauthorized text must not enter candidates, ranking, caches, snippets,
citations, logs, or receipts.

## Query audit data

Gate 0 receipts store an opaque `query_id`, not query text or a query digest.
If equality binding is later required, a workspace-specific HMAC design must
define key identifier, rotation, destruction, and backup separation before use.

## Atomic publication

Projection metadata, blocks, FTS rows, and citation anchors for a source
version publish in a single SQLite transaction. Failed, stale, unsupported, or
interrupted attempts cannot expose a partially built projection. Query-time
citations are created separately from an immutable readable projection and
must validate their anchor before publication.
