#!/usr/bin/env node
import { existsSync, writeFileSync } from 'node:fs';
import path from 'node:path';

import {
  GateError,
  readArtifactIndex,
  readJson,
  reviewNetworkCapture,
  schemaFindings,
  sha256,
  verifyCompatibilityEvidence,
} from './lib.mjs';

function option(name) {
  const index = process.argv.indexOf(`--${name}`);
  const value = index === -1 ? undefined : process.argv[index + 1];
  if (!value || value.startsWith('--')) throw new GateError(`--${name} is required`);
  return value;
}

const root = path.resolve(option('root'));
function file(name, { output = false } = {}) {
  const value = option(name);
  if (
    path.isAbsolute(value) ||
    value.includes('\\') ||
    path.posix.normalize(value) !== value ||
    value.startsWith('../')
  ) {
    throw new GateError(`--${name} must be a canonical repository-relative path`);
  }
  const absolute = path.resolve(root, value);
  const relative = path.relative(root, absolute);
  if (relative.startsWith('..') || path.isAbsolute(relative)) throw new GateError(`--${name} escapes the repository`);
  if (!output && !existsSync(absolute)) throw new GateError(`--${name} does not exist: ${value}`);
  return { path: value, absolute };
}
function evidence(value) {
  return { path: value.path, sha256: sha256(value.absolute) };
}

const seedPath = file('seed');
const outputPath = file('output', { output: true });
const artifact = file('artifact');
const provenance = file('provenance');
const sbom = file('sbom');
const licenses = file('licenses');
const capture = file('network-capture');
const allowlist = file('network-allowlist');
const reviewedAllowlistSource = file('reviewed-network-allowlist');
const compatibility = file('compatibility');
if (existsSync(outputPath.absolute)) throw new GateError('refusing to overwrite an existing final release manifest');

const seed = readJson(seedPath.absolute);
const index = readArtifactIndex(artifact.absolute);
const artifactSha256 = sha256(artifact.absolute);
const provenanceDocument = readJson(provenance.absolute);
if (
  provenanceDocument.reviewedBaselineCommit !== index.reviewedBaselineCommit ||
  provenanceDocument.releaseCommit !== index.releaseCommit ||
  provenanceDocument.artifactSha256 !== artifactSha256
) {
  throw new GateError('provenance does not match the artifact baseline, release commit, and digest');
}
const networkFindings = reviewNetworkCapture(capture.absolute, allowlist.absolute, {
  root,
  artifactPath: artifact.absolute,
});
if (networkFindings.length > 0) throw new GateError('network evidence has not passed explicit review', networkFindings);
const compatibilityFindings = verifyCompatibilityEvidence(root, compatibility.absolute, {
  artifactPath: artifact.absolute,
  reviewedBaselineCommit: index.reviewedBaselineCommit,
  releaseCommit: index.releaseCommit,
});
if (compatibilityFindings.length > 0)
  throw new GateError('compatibility evidence has not passed review', compatibilityFindings);

const manifest = {
  ...seed,
  schemaVersion: 3,
  evidenceClass: 'release',
  reviewedBaselineCommit: index.reviewedBaselineCommit,
  releaseCommit: index.releaseCommit,
  artifact: {
    name: index.artifact.name,
    version: index.artifact.version,
    path: artifact.path,
    sha256: artifactSha256,
  },
  sbom: { ...evidence(sbom), artifactSha256 },
  provenance: {
    ...evidence(provenance),
    artifactSha256,
    reviewedBaselineCommit: index.reviewedBaselineCommit,
    releaseCommit: index.releaseCommit,
    version: index.artifact.version,
  },
  licenseEvidence: {
    ...evidence(licenses),
    artifactSha256,
    sbomSha256: sha256(sbom.absolute),
  },
  networkEvidence: {
    artifactSha256,
    capture: evidence(capture),
    allowlist: evidence(allowlist),
    reviewedAllowlistSource: evidence(reviewedAllowlistSource),
    review: {
      status: 'passed',
      command: 'network-review',
      captureSha256: sha256(capture.absolute),
      allowlistSha256: sha256(allowlist.absolute),
    },
  },
  compatibilityEvidence: { ...evidence(compatibility), artifactSha256 },
  rollback: { ...seed.rollback, artifactSha256 },
  signing: { ...seed.signing, artifactSha256 },
  publicationAuthorization: { ...seed.publicationAuthorization, artifactSha256 },
};
const findings = schemaFindings(manifest, 'release-evidence.schema.json', 'assembled release evidence');
if (findings.length > 0) throw new GateError('assembled release evidence is invalid', findings);
writeFileSync(outputPath.absolute, `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
console.log(JSON.stringify({ path: outputPath.path, sha256: sha256(outputPath.absolute), artifactSha256 }));
