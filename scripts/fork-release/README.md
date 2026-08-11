# Expedient fork release gates

These credential-free gates build and verify one immutable npm bundle from the reviewed fork. They do not make `@mastra/core@1.50.1` from the upstream registry look like the fork, and they do not publish anything during a gate run.

## Exact native artifact

The checked-in `native-package-manifest.json` names the native roots required for Studio (`mastra`), Playground (`@mastra/playground-ui`), Agent Builder (`@mastra/agent-builder` and `@mastra/editor`), core/server, memory, evaluations, PostgreSQL, and their in-workspace package closure. `@mastra/inngest` is deliberately not a release root or an authoritative runtime.

Build once with Node 22.23.1 and the integrity-qualified `pnpm@11.13.1` from the root `packageManager`, then pack the selected packages into an npm-installable Expedient-owned transport bundle:

```sh
corepack enable
corepack install
pnpm install --frozen-lockfile
pnpm build
node scripts/fork-release/assemble-release-artifact.mjs \
  --root . \
  --output release/fork-npm-artifacts.tgz \
  --provenance release/fork-provenance.json \
  --name @expedient/mastra-native \
  --version 0.1.0-expedient.1 \
  --reviewed-baseline-commit <exact-reviewed-baseline-40-hex-commit> \
  --release-commit <exact-clean-HEAD-40-hex-commit>
```

The command fails closed unless the release commit is the clean checked-out `HEAD`, the reviewed baseline is its ancestor, and the exact toolchain is active. The bundle contains `package/artifact-index.json` and exact inner `@mastra/*` package tarballs. The index and sibling provenance record the distinct reviewed-baseline and clean-release commits, outer digest, toolchain, and package digests. The outer bundle is the only package eligible for publication. Never publish the inner `@mastra/*` tarballs to the public registry: they intentionally retain upstream-compatible import identities and are installable only by their exact file tarballs from this digest-bound bundle.

After accountable publication, the expected coordinate is:

```text
@expedient/mastra-native@0.1.0-expedient.1
outer SHA-256: <digest emitted by assemble-release-artifact.mjs>
```

The exact fork package coordinates consumed by an activation change are the entries in that bundle's `artifact-index.json` (including the reviewed fork's `@mastra/core` version), not the mutable upstream `@mastra/core@1.50.1` range. No activation claim is valid until the lead records the published coordinate and outer digest, then installs the inner tarballs by their recorded SHA-256.

## Gates

```sh
pnpm fork-release:test
pnpm fork-release:schemas
pnpm fork-release:static
node scripts/fork-release/release-gate.mjs bundles \
  --artifact release/fork-npm-artifacts.tgz
node scripts/fork-release/release-gate.mjs licenses \
  --artifact release/fork-npm-artifacts.tgz \
  --sbom release/fork-sbom.cdx.json \
  --inventory release/fork-licenses.cdx.json
```

`static` validates the seventeen-point commercial-boundary audit, schemas, prohibited dependency/export descendants, and active source imports. `bundles` recursively scans the outer npm bundle and every nested package archive, including generated paths and source maps; traversal entries, links, out-of-root paths, unsupported formats, and prohibited bytes fail. Historical `CHANGELOG.md` text is retained as provenance and is not executable/runtime content. The CycloneDX gate binds the exact outer digest, complete shipped-production closure, SBOM, license inventory, component set, and dependency graph. Blank, malformed, unknown, `NOASSERTION`, unlicensed, proprietary, commercial, or Mastra EE conclusions fail.

The Linux network gate uses `strace -ff -e trace=network` over every declared runtime exercise and descendant. A reviewed allowlist source is copied and bound to the fresh artifact digest, capture runs against that bound copy, and an explicit `network-review` must pass before final-manifest assembly. The final manifest records the source, bound allowlist, capture, review command, and their digests. Node API preloads are not comprehensive evidence.

Every native compatibility area installs the exact inner tarballs into a temporary credential-free clean room with lifecycle scripts disabled before testing. This includes installed Studio CLI startup and Playground UI loading, plus Agent Builder, agents/tools, workflows, schedules, AG-UI, skills, workspaces, memory, settings, evaluations, PostgreSQL, and public OSS APIs. Evidence is bound to both provenance commits, the artifact digest, matrix digest, command digest, output digest, and exact required area set.

Copy `release-evidence.template.json` to a release-specific canonical repository-relative evidence seed; never edit the template. After fresh SBOM/license, network, and clean-room compatibility evidence pass their reviews, `assemble-release-manifest.mjs` replaces generated sections with digest-bound facts and writes the final manifest. `release-gate.mjs release` then re-runs all correlations and requires clean `HEAD`. Signing, rollback ownership, accountable facts, and publication authorization remain external; missing evidence blocks release.

The reusable workflow checks out the exact clean release commit, proves reviewed-baseline ancestry and cleanliness, activates the integrity-qualified pnpm baseline, builds once, generates and explicitly reviews fresh evidence, assembles the final manifest, and uploads only fully gated material. `fork-npm-publish.yml` uses pinned npm 11.5.1, the protected `fork-production` environment, trusted publishing, explicit approval/confirmation, and the returned digest. It publishes only `@expedient/mastra-native`.

## Upstream synchronization

1. Record an exact 40-hex rollback commit from a clean fork branch.
2. Fetch the reviewed upstream object without tags or publication credentials.
3. Inspect and merge that exact object while preserving public authorization and root Agent Builder replacements.
4. Run `node scripts/fork-release/release-gate.mjs upstream-sync --base <exact-rollback-commit>` immediately; mutable expressions are rejected.
5. Build and gate the exact bundle through the workflow above.
6. Supply real accountable facts, signing, rollback, publication authorization, and post-publication receipt evidence. Any finding blocks publication.
