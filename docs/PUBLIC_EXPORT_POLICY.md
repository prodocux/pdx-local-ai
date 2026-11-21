# Public export policy

The public source candidate is created through an explicit allowlist export
and is subject to product, security, license, and documentation review.

## Rules

- Export only paths listed in `public-export.allowlist` at the reviewed commit.
- Never copy `.git`, virtual environments, SQLite databases, FTS files, run
  state, caches, controlled snapshots, source documents, credentials, audit
  query text, private fixture binaries, internal strategy, or review notes.
- Generate the public root as a clean independent repository; do not move or
  reuse development checkout Git metadata and do not use a junction.
- Before export, scan allowlisted content for credentials, absolute local paths,
  prohibited internal documents, binary fixtures, and unreviewed licenses.
- After export, compare every public file byte-for-byte with the allowlisted
  reviewed source and fail on missing, changed, or extra files.
- Commit, push, remote creation, and publication require separate authorization.

Review changes to the allowlist before preparing a new candidate.
