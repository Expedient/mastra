# Fork release gates

These deterministic, credential-free gates prevent the commercial boundaries removed by the approved migration from returning to fork source or release artifacts. They do not publish or sign anything.

## Audited boundary

[`commercial-connection-audit.json`](./commercial-connection-audit.json) records exactly seventeen connection points found at upstream base `b6b1c53378a05b24aeb19ba0313203355fa82eeb` and resolved by the approved migration through `b23d4277e12e30816e154401d9d1e012d5d383e1`. Every record names a history object, connection type, remove/replace disposition, current regression path, regression check, and verified evidence status. History and fetched Git objects are evidence data; scanners inspect the active checkout and explicitly supplied build outputs, not `.git`.

The policy contains only facts demonstrated by that migration. Authoritative commercial package ownership, outbound vendor destinations, and prohibited license decisions were not present in the approved history, so the release-evidence template leaves those mandatory facts unresolved. Do not guess them. A release remains fail-closed until an accountable reviewer supplies a basis and marks each fact resolved.

## Commands

Use Node 22.23.1 and the repository pnpm version.

```sh
pnpm fork-release:test
pnpm fork-release:static
node scripts/fork-release/release-gate.mjs bundles --artifacts packages/core/dist,packages/editor/dist
node scripts/fork-release/release-gate.mjs licenses --inventory release/license-inventory.cdx.json
node scripts/fork-release/release-gate.mjs network --capture release/network.jsonl --allowlist release/network-allowlist.json -- node release/runtime-exercise.mjs
node scripts/fork-release/release-gate.mjs evidence --manifest release/release-evidence.json
```

`graph` checks dependency fields and package export maps. `source` recognizes static imports, exports-from, dynamic imports, `require`, and TypeScript import-equals while ignoring comments. `bundles` scans final bytes, including source maps. `licenses` requires a concluded license for every CycloneDX component and applies the reviewed deny policy. `network` injects a Node preload into the runtime exercise and captures `fetch`, HTTP(S), TCP, and TLS destinations before reviewing an exact protocol/host/port allowlist. Run non-Node system exercises separately and convert their capture to the same JSONL format before `network-review`.

Copy `release-evidence.template.json` to a release-specific location; never edit the template in place. Its checked-in SHA-256 makes accidental template mutation visible. Evidence validation verifies all referenced digests and Git references and rejects unresolved mandatory facts, signing, or publication fields. Use `not-applicable` only with an explicit rationale.

## Reproducible upstream sync

1. Start from a clean fork branch and record `git rev-parse HEAD` as the rollback reference.
2. Fetch the reviewed upstream remote without executing fetched content: `git fetch --no-tags upstream <ref>`.
3. Record `git rev-parse FETCH_HEAD` as the upstream commit, inspect it, and merge it without hooks or credentials used for publication.
4. Resolve conflicts by preserving native OSS features and the public `auth/authorization` and root Editor Agent Builder replacements. Never restore a prohibited subpath as a compatibility shim.
5. Run `node scripts/fork-release/release-gate.mjs upstream-sync --base <recorded-rollback-commit>` immediately after the merge. This verifies ancestry, all changed active source, prohibited paths, and the complete dependency/export graph.
6. Build the release artifacts, generate SBOM/provenance/license inventory, exercise the real runtime input class under network capture, then run every gate above.
7. Copy the immutable evidence template, resolve mandatory facts from authoritative evidence, enter artifact/version/digests, upstream commit, rollback reference, signing/publication disposition, and verify it.
8. Commit the sync and release evidence. Publication remains a separate, explicitly authorized operation.

Any gate finding blocks the sync or release; do not add scan exclusions to waive a finding.
