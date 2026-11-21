# Gate 0 architecture

```text
Allowlisted Windows root
        |
        v
Safe discovery and file-handle validation
        |
        v
Immutable controlled snapshot
        |
        v
Published ProDocuX extraction
        |
        v
Product-local projection transaction
  + file/source version
  + coverage disclosure
  + blocks and FTS rows
  + citation anchors
        |
        v
ACL-constrained bounded FTS retrieval
  + query-time citation creation
        |
        v
Observable results + retrieval receipt
```

## Authority boundaries

### ProDocuX Kernel

Owns deterministic supported-format intake and its declared limits. The
product consumes the published package output. It does not copy parsers or
claim extraction beyond the returned evidence.

### PDX Artifact Engine

Provides optional product-neutral artifacts, provenance, and receipt building
blocks. Gate 0 uses only capabilities that are actually wired into the product
flow and covered by integration tests. Scan scheduling and SQLite durability
remain product responsibilities in Gate 0.

### PDX Local AI

Owns roots, catalog identity, source versions, controlled snapshots, workspace
ACL, projection publication, FTS, retrieval budgets, citations, reconciliation,
and product-local receipts.

## Publication transaction

A new projection is built separately from the currently searchable version.
After extraction succeeds, source invariants still match, and schema checks
pass, one SQLite transaction publishes the new source version, projection,
blocks, FTS rows, and citation anchors. The prior successful projection remains
searchable until this transaction commits. A stale or failed attempt cannot
erase it.

A citation is created only after an authorized retrieval selects quoted text.
The query transaction resolves an immutable published projection and block,
computes the quoted-text digest, and creates the citation identity. The bound
projection must still be readable but need not be the file record's newest
version. Indexing never guesses a future query snippet or citation ID.

## Retrieval boundary

The Gate 0 security promise is not that SQLite's optimizer never evaluates an
unauthorized row internally. The promise is:

> Unauthorized content never leaves the SQLite query boundary and never enters
> application-observable candidates, ranking, cache, snippets, citations, or
> receipts.

If a future deployment requires prohibition of even internal evaluation, it
must use physically separate workspace FTS partitions or databases.
