# Gate 0 data model

## Product-local schemas

| Schema | Purpose |
|---|---|
| `pdx_local_source_root_v1` | Allowlisted root and workspace ownership |
| `pdx_local_file_record_v1` | Stable catalog object, independent of content hash |
| `pdx_local_source_version_v1` | One observed content version and coverage |
| `pdx_local_index_attempt_v1` | Mutable operational attempt, separate from source version |
| `pdx_local_document_projection_v1` | Product projection of published Kernel output |
| `pdx_local_block_instance_v1` | Positional block inside one projection |
| `pdx_local_citation_v1` | Source-version-bound citation identity |
| `pdx_local_retrieval_request_v1` | ACL scope and hard retrieval limits |
| `pdx_local_retrieval_receipt_v1` | Execution, scope, source coverage, and consumption |

## Orthogonal state dimensions

`index_attempt_status` belongs to a separate operational record:

```text
pending | running | succeeded | retryable_failed | terminal_failed | stale
```

`processing_status` describes the last publishable source-version result:

```text
indexed | unsupported | failed
```

`coverage_disposition` describes observable content coverage:

```text
complete | partial_known | partial_unknown | not_evaluated
```

Required invariants:

- Only `indexed` may use `complete`, `partial_known`, or `partial_unknown`.
- `unsupported` uses `not_evaluated`.
- `failed` uses `not_evaluated` and produces no new projection or citation.
- `partial_known` requires a known complete total or an exactly enumerable
  missing range, and therefore uses `unknown_remainder=false`.
- `partial_unknown` means truncation or omission is known but the complete
  remainder cannot be enumerated; `unknown_remainder=true` maps to this state.
- A bare Kernel `truncated=true` without totals, omitted ranges, or a
  continuation cursor is conservatively `partial_unknown`.
- A failed or stale attempt does not remove the prior successful projection.
- A source version is immutable after publication and never carries mutable
  attempt status. Multiple attempts may target the same observed source.

## Block identity

Gate 0 promises only version-local positional identity:

```text
block_instance_id = identity within one projection/source version
```

It does not promise a block identifier remains stable across document versions.
Cross-version content fingerprinting and moved/changed matching are deferred.

## Citation identity

The indexing transaction publishes a citation anchor consisting of the
immutable projection, block, locator, and source bindings. It does not create a
citation ID or quoted-text digest.

After retrieval selects an authorized snippet, the query transaction validates
that its anchor still belongs to a readable immutable projection and creates a
citation. The projection need not be the newest file version. Every citation
binds all of:

- workspace ID
- source root ID
- file record ID
- source version ID
- source SHA-256
- projection ID
- parser contract name and version
- block instance ID
- typed locator
- quoted-text SHA-256

Quote selection uses `unicode_nfc_codepoint_v1`: normalize the immutable block
text to Unicode NFC, then apply the half-open range `[quote_start, quote_end)`
in Unicode code points. The SHA-256 input is the selected text encoded as
UTF-8. Offsets are not UTF-8 bytes or UTF-16 code units.

Citation semantic validation must load the authorized immutable block, verify
the projection/block binding, normalize and slice the block, and recompute the
digest. An out-of-range/empty selection, unsupported normalization, or digest
mismatch prevents both citation and receipt creation.

The quoted text itself may be returned to an authorized caller but is not
required inside the durable citation identity.

## Semantic validation

JSON Schema validates document shape. `scripts/validate_contracts.py` owns the
cross-field Gate 0 rules that JSON Schema cannot express, including receipt
limit accounting, stop-reason consistency, root counts, result/citation
cardinality, the single-root Gate 0 profile, and safe relative paths. Both
positive and negative fixtures are required in acceptance runs.

Retrieval uses one `BEGIN IMMEDIATE` transaction for workspace/root validation,
authorized-file capture, ACL digest, FTS, citations, and receipt publication.
The digest therefore describes the same SQLite snapshot used by the query.

`consumed.elapsed_ms` is capped budget consumption and never exceeds the hard
limit. `execution.observed_elapsed_ms` records actual measured wall time. A
`time_limit` disposition requires observed time to reach the configured limit;
after the deadline the product opens no additional block and publishes no
partial citation set.

## Extraction disclosure

Source versions preserve truncation reason codes, observed limits,
processed/known-total counts, parser warnings, OCR disposition, and whether an
unknown remainder exists. Gate 0 never derives `complete` solely from a
successful parser return.
