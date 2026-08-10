import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  captureNetwork,
  extractActiveModuleSpecifiers,
  readJson,
  reviewNetworkCapture,
  scanActiveSource,
  scanBundles,
  scanDependencyGraph,
  scanLicenseInventory,
  sha256,
  verifyAudit,
  verifyEvidence,
  verifyTemplateIntegrity,
  verifyUpstreamSync,
} from '../lib.mjs';

const testRoot = path.dirname(fileURLToPath(import.meta.url));
const toolingRoot = path.dirname(testRoot);
const repoRoot = path.resolve(toolingRoot, '../..');
const fixture = name => path.join(testRoot, 'fixtures', name);
const policy = readJson(fixture('policy.resolved.json'));

function temporaryDirectory() {
  const directory = mkdtempSync(path.join(tmpdir(), 'fork-release-gate-'));
  test.after(() => rmSync(directory, { recursive: true, force: true }));
  return directory;
}

test('active import extraction covers supported forms and ignores comments', () => {
  const source = `
    // import '@vendor/commercial/ee';
    /* require('@vendor/commercial/ee') */
    import type { A } from '@vendor/commercial/ee';
    export { B } from '@vendor/commercial/ee';
    void import('@vendor/commercial/ee');
    const value = require('@vendor/commercial/ee');
    import Legacy = require('@vendor/commercial/ee');
  `;
  assert.equal(extractActiveModuleSpecifiers(source).filter(item => item.specifier.includes('/ee')).length, 5);
});

test('dependency graph rejects prohibited packages and export subpaths', () => {
  const root = temporaryDirectory();
  writeFileSync(
    path.join(root, 'package.json'),
    JSON.stringify({
      name: '@vendor/commercial',
      dependencies: { '@vendor/commercial': '1.0.0' },
      exports: { './ee': './dist/ee.js' },
    }),
  );
  writeFileSync(path.join(root, 'pnpm-lock.yaml'), "packages:\n  '@vendor/commercial@1.0.0': {}\n");
  const findings = scanDependencyGraph(root, {
    ...policy,
    prohibitedModuleSpecifiers: ['@vendor/commercial/ee'],
  });
  assert.deepEqual(findings, [
    'package.json: dependencies.@vendor/commercial',
    'package.json: exports../ee',
    'pnpm-lock.yaml:2: @vendor/commercial',
  ]);
});

test('source scan detects active imports and prohibited paths but not comments', () => {
  const root = temporaryDirectory();
  mkdirSync(path.join(root, 'src', 'ee'), { recursive: true });
  writeFileSync(path.join(root, 'src', 'safe.ts'), `// import '@vendor/commercial/ee';\nexport const safe = true;\n`);
  writeFileSync(path.join(root, 'src', 'bad.ts'), `void import('@vendor/commercial/ee');\n`);
  writeFileSync(path.join(root, 'src', 'ee', 'index.ts'), 'export const retired = true;\n');
  assert.deepEqual(scanActiveSource(root, policy), [
    'src/bad.ts:1: @vendor/commercial/ee',
    'src/ee/index.ts: prohibited source path',
  ]);
});

test('final bundle scan detects prohibited bytes', () => {
  const root = temporaryDirectory();
  const safe = path.join(root, 'safe.js');
  const bad = path.join(root, 'bad.js');
  writeFileSync(safe, 'export const nativeFeature = true;\n');
  writeFileSync(bad, 'const source = "COMMERCIAL_SENTINEL";\n');
  assert.deepEqual(scanBundles([safe], policy), []);
  assert.deepEqual(scanBundles([bad], policy), [`${bad}: COMMERCIAL_SENTINEL`]);
});

test('license inventory requires conclusions and applies reviewed deny expressions', () => {
  assert.deepEqual(scanLicenseInventory(fixture('licenses.pass.json'), policy), []);
  assert.deepEqual(scanLicenseInventory(fixture('licenses.fail.json'), policy), [
    'commercial@2.0.0: prohibited license LicenseRef-Commercial',
    'unknown@1.0.0: missing or unresolved license conclusion',
  ]);
});

test('runtime capture records destinations and exact allowlist review fails closed', () => {
  const root = temporaryDirectory();
  const capture = path.join(root, 'capture.jsonl');
  assert.deepEqual(
    captureNetwork({
      command: process.execPath,
      args: [fixture('network-exercise.mjs')],
      capturePath: capture,
      allowlistPath: fixture('network.allow.json'),
      cwd: repoRoot,
    }),
    [],
  );
  assert.deepEqual(reviewNetworkCapture(capture, fixture('network.deny.json')), ['tcp://127.0.0.1:9 (net.connect)']);
});

test('commercial audit has exactly seventeen history-backed records', () => {
  assert.deepEqual(verifyAudit(repoRoot), []);
});

test('immutable evidence template is intact and deliberately unresolved', () => {
  assert.deepEqual(verifyTemplateIntegrity(), []);
  const findings = verifyEvidence(repoRoot, path.join(toolingRoot, 'release-evidence.template.json'));
  assert.ok(findings.includes('requiredFacts.commercialPackageNames is unresolved'));
  assert.ok(findings.includes('artifact.sha256 is unresolved'));
  assert.ok(findings.includes('publication.status is unresolved'));
});

test('resolved evidence verifies Git references and all file digests', () => {
  const root = temporaryDirectory();
  const files = {};
  for (const name of [
    'artifact.tgz',
    'sbom.json',
    'provenance.json',
    'licenses.json',
    'network.jsonl',
    'allowlist.json',
  ]) {
    files[name] = path.join(root, name);
    writeFileSync(files[name], `${name}\n`);
  }
  const head = execFileSync('git', ['-C', repoRoot, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
  const manifest = {
    schemaVersion: 1,
    upstreamCommit: head,
    requiredFacts: {
      commercialPackageNames: { status: 'resolved', value: [], basis: 'review-1' },
      commercialNetworkDestinations: { status: 'resolved', value: [], basis: 'review-2' },
      prohibitedLicenseExpressions: { status: 'resolved', value: [], basis: 'review-3' },
    },
    artifact: { name: 'fork', version: '1.0.0', path: files['artifact.tgz'], sha256: sha256(files['artifact.tgz']) },
    sbom: { path: files['sbom.json'], sha256: sha256(files['sbom.json']) },
    provenance: { path: files['provenance.json'], sha256: sha256(files['provenance.json']) },
    licenseEvidence: { path: files['licenses.json'], sha256: sha256(files['licenses.json']) },
    networkEvidence: {
      capture: { path: files['network.jsonl'], sha256: sha256(files['network.jsonl']) },
      allowlist: { path: files['allowlist.json'], sha256: sha256(files['allowlist.json']) },
    },
    rollbackReference: head,
    signing: { status: 'not-applicable', reference: '', rationale: 'synthetic fixture' },
    publication: { status: 'not-applicable', reference: '', rationale: 'synthetic fixture' },
  };
  const manifestPath = path.join(root, 'evidence.json');
  writeFileSync(manifestPath, JSON.stringify(manifest));
  assert.deepEqual(verifyEvidence(repoRoot, manifestPath), []);
  const licenseFact = manifest.requiredFacts.prohibitedLicenseExpressions;
  delete manifest.requiredFacts.prohibitedLicenseExpressions;
  writeFileSync(manifestPath, JSON.stringify(manifest));
  assert.ok(
    verifyEvidence(repoRoot, manifestPath).includes('requiredFacts.prohibitedLicenseExpressions is unresolved'),
  );
  manifest.requiredFacts.prohibitedLicenseExpressions = licenseFact;
  writeFileSync(manifestPath, JSON.stringify(manifest));
  writeFileSync(files['artifact.tgz'], 'tampered\n');
  assert.deepEqual(verifyEvidence(repoRoot, manifestPath), [`artifact.sha256 does not match ${files['artifact.tgz']}`]);
});

test('upstream-sync gate accepts an unchanged reviewed base', () => {
  const head = execFileSync('git', ['-C', repoRoot, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
  assert.deepEqual(verifyUpstreamSync(repoRoot, head), []);
});
