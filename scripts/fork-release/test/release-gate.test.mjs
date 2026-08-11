import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  GateError,
  canonicalRepositoryPath,
  extractActiveModuleSpecifiers,
  parseCapture,
  readJson,
  redactOutput,
  reviewNetworkCapture,
  scanActiveSource,
  scanBundles,
  scanDependencyGraph,
  scanLicenseInventory,
  schemaFindings,
  sha256,
  sha256Text,
  verifyAudit,
  verifyCompatibilityEvidence,
  verifyEvidence,
  verifyTemplateIntegrity,
  verifyUpstreamSync,
} from '../lib.mjs';

const testRoot = path.dirname(fileURLToPath(import.meta.url));
const toolingRoot = path.dirname(testRoot);
const repoRoot = path.resolve(toolingRoot, '../..');
const policy = readJson(path.join(toolingRoot, 'policy.json'));
const zeroDigest = '0'.repeat(64);
const head = execFileSync('git', ['-C', repoRoot, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();

function temporaryDirectory() {
  const directory = mkdtempSync(path.join(tmpdir(), 'fork-release-gate-synthetic-fixture-'));
  test.after(() => rmSync(directory, { recursive: true, force: true }));
  return directory;
}

function writeJson(file, value) {
  writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function review() {
  return {
    reviewer: 'Synthetic Fixture Reviewer',
    organization: 'Synthetic Fixture Only',
    reviewedAt: '2026-01-01T00:00:00.000Z',
    reference: 'synthetic-fixture-review',
    path: 'synthetic-review.json',
    sha256: zeroDigest,
  };
}

function resolvedFact(values = []) {
  return { status: 'resolved', decision: values.length === 0 ? 'none' : 'enumerated', values, review: review() };
}

function evidenceManifest(overrides = {}) {
  return {
    schemaVersion: 3,
    evidenceClass: 'synthetic-fixture',
    reviewedBaselineCommit: head,
    releaseCommit: head,
    upstreamCommit: head,
    requiredFacts: {
      commercialPackageNames: resolvedFact(),
      commercialNetworkDestinations: resolvedFact(),
      prohibitedLicenseExpressions: resolvedFact(),
    },
    artifact: {
      name: 'synthetic-fixture-artifact',
      version: '0.0.0-fixture',
      path: 'artifact.tar',
      sha256: zeroDigest,
    },
    sbom: { path: 'sbom.json', sha256: zeroDigest, artifactSha256: zeroDigest },
    provenance: {
      path: 'provenance.json',
      sha256: zeroDigest,
      artifactSha256: zeroDigest,
      reviewedBaselineCommit: head,
      releaseCommit: head,
      version: '0.0.0-fixture',
    },
    licenseEvidence: {
      path: 'licenses.json',
      sha256: zeroDigest,
      artifactSha256: zeroDigest,
      sbomSha256: zeroDigest,
    },
    networkEvidence: {
      artifactSha256: zeroDigest,
      capture: { path: 'capture.jsonl', sha256: zeroDigest },
      allowlist: { path: 'allowlist.json', sha256: zeroDigest },
      reviewedAllowlistSource: { path: 'reviewed-allowlist.json', sha256: zeroDigest },
      review: {
        status: 'passed',
        command: 'network-review',
        captureSha256: zeroDigest,
        allowlistSha256: zeroDigest,
      },
    },
    compatibilityEvidence: { path: 'compatibility.json', sha256: zeroDigest, artifactSha256: zeroDigest },
    rollback: { path: 'rollback.json', sha256: zeroDigest, artifactSha256: zeroDigest, commit: head },
    signing: {
      status: 'completed',
      artifactSha256: zeroDigest,
      reference: 'synthetic-fixture-signing-reference',
      evidence: { path: 'signing.json', sha256: zeroDigest },
    },
    publicationAuthorization: {
      status: 'approved',
      artifactSha256: zeroDigest,
      reference: 'synthetic-fixture-publication-reference',
      review: review(),
    },
    ...overrides,
  };
}

function cyclonedx(rootName, artifactDigest, components, { sbomDigest } = {}) {
  const rootRef = `fixture:${rootName}`;
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber: 'urn:uuid:00000000-0000-4000-8000-000000000001',
    version: 1,
    metadata: {
      component: {
        type: 'application',
        'bom-ref': rootRef,
        name: rootName,
        version: '0.0.0-fixture',
        hashes: [{ alg: 'SHA-256', content: artifactDigest }],
        licenses: [{ expression: 'Apache-2.0' }],
      },
      properties: [
        { name: 'expedient:artifact:sha256', value: artifactDigest },
        { name: 'expedient:inventory:complete', value: 'true' },
        { name: 'expedient:inventory:scope', value: 'shipped-production-closure' },
        ...(sbomDigest ? [{ name: 'expedient:sbom:sha256', value: sbomDigest }] : []),
      ],
    },
    components,
    dependencies: [
      { ref: rootRef, dependsOn: components.map(component => component['bom-ref']) },
      ...components.map(component => ({ ref: component['bom-ref'], dependsOn: [] })),
    ],
  };
}

function component(name, license = 'MIT') {
  return {
    type: 'library',
    'bom-ref': `fixture:${name}`,
    name,
    version: '1.0.0-fixture',
    hashes: [{ alg: 'SHA-256', content: sha256Text(name) }],
    licenses: [{ expression: license }],
  };
}

function networkFiles(root, artifact, { events, exercised = ['node', 'browser'], headerDigest, exitCode = 0 } = {}) {
  const artifactDigest = headerDigest ?? sha256(artifact);
  const allowlistPath = path.join(root, 'allowlist.json');
  const capturePath = path.join(root, 'capture.jsonl');
  writeJson(allowlistPath, {
    schemaVersion: 2,
    exerciseId: 'synthetic-fixture-network-exercise',
    artifactSha256: sha256(artifact),
    requiredRuntimeClasses: ['node', 'browser'],
    destinations: [{ protocol: 'tcp', host: '127.0.0.1', ports: [9], basis: 'synthetic fixture only' }],
    environment: { passThrough: [], sensitive: [], fixed: { LANG: 'C' } },
  });
  const lines = [
    {
      type: 'header',
      schemaVersion: 2,
      exerciseId: 'synthetic-fixture-network-exercise',
      artifactSha256: artifactDigest,
      startedAt: '2026-01-01T00:00:00.000Z',
      requiredRuntimeClasses: ['node', 'browser'],
      coverage: {
        mechanism: 'os-syscall',
        platform: 'linux',
        comprehensive: true,
        descendants: true,
        transports: ['tcp', 'udp', 'subprocess', 'native'],
        tool: 'synthetic fixture syscall capture',
      },
    },
    ...(events ?? [
      {
        type: 'network',
        protocol: 'tcp',
        host: '127.0.0.1',
        port: 9,
        source: 'connect',
        pid: 42,
        runtimeClass: 'node',
      },
    ]),
    {
      type: 'completion',
      exerciseId: 'synthetic-fixture-network-exercise',
      completedAt: '2026-01-01T00:00:01.000Z',
      status: exitCode === 0 ? 'completed' : 'failed',
      exitCode,
      exercisedRuntimeClasses: exercised,
      outputSha256: zeroDigest,
      outputTruncated: false,
    },
  ];
  writeFileSync(capturePath, `${lines.map(line => JSON.stringify(line)).join('\n')}\n`);
  return { allowlistPath, capturePath };
}

test('active import extraction covers descendants and ignores comments', () => {
  const retiredRoot = ['@mastra/editor', 'ee'].join('/');
  const source = `
    // import '${retiredRoot}/hidden';
    /* require('${retiredRoot}/hidden') */
    import type { A } from '${retiredRoot}/types';
    export { B } from '${retiredRoot}/runtime';
    void import('${retiredRoot}/dynamic');
    const value = require('${retiredRoot}/required');
  `;
  assert.equal(extractActiveModuleSpecifiers(source).filter(item => item.specifier.includes('/ee/')).length, 4);
});

test('dependency graph rejects descendant exports and package/TypeScript aliases', () => {
  const root = temporaryDirectory();
  mkdirSync(path.join(root, 'src'), { recursive: true });
  writeJson(path.join(root, 'package.json'), {
    name: '@mastra/editor',
    imports: { '#commercial': './packages/editor/src/ee/index.ts' },
    exports: { './ee/*': './dist/ee/*.js' },
  });
  writeJson(path.join(root, 'tsconfig.json'), {
    compilerOptions: { paths: { '#retired/*': ['packages/core/src/auth/ee/*'] } },
  });
  assert.deepEqual(scanDependencyGraph(root, policy), [
    'package.json: exports../ee/*',
    'package.json: prohibited package import alias ./packages/editor/src/ee/index.ts',
    'tsconfig.json: prohibited TypeScript alias packages/core/src/auth/ee/*',
  ]);
});

test('source scan follows in-root symlinks and rejects out-of-root symlinks', () => {
  const root = temporaryDirectory();
  const outside = temporaryDirectory();
  mkdirSync(path.join(root, 'src'));
  writeFileSync(path.join(root, 'src', 'bad.ts'), "import '@mastra/core/auth/ee/descendant';\n");
  symlinkSync(path.join(root, 'src', 'bad.ts'), path.join(root, 'linked.ts'));
  assert.ok(scanActiveSource(root, policy).some(finding => finding.includes('linked.ts')));
  writeFileSync(path.join(outside, 'escape.ts'), 'export const escaped = true;\n');
  symlinkSync(path.join(outside, 'escape.ts'), path.join(root, 'escape.ts'));
  assert.throws(() => scanActiveSource(root, policy), /Symlink resolves outside scan root/);
});

test('bundle scan rejects prohibited descendants in files and packed archives', () => {
  const root = temporaryDirectory();
  const unpacked = path.join(root, 'bundle.js');
  const retiredRoot = ['@mastra/editor', 'ee'].join('/');
  writeFileSync(unpacked, `import('${retiredRoot}/hidden')\n`);
  assert.ok(scanBundles([unpacked], policy)[0].includes(retiredRoot));
  const archiveRoot = path.join(root, 'archive');
  mkdirSync(archiveRoot);
  writeFileSync(path.join(archiveRoot, 'generated.js'), 'MASTRA_LICENSE_KEY\n');
  const archive = path.join(root, 'artifact.tar');
  execFileSync('tar', ['-cf', archive, '-C', archiveRoot, '.']);
  assert.ok(scanBundles([archive], policy).some(finding => finding.includes('MASTRA_LICENSE_KEY')));
  const nestedRoot = path.join(root, 'nested-package');
  mkdirSync(nestedRoot);
  writeFileSync(path.join(nestedRoot, 'generated.js'), 'MASTRA_LICENSE_URL\\n');
  const nested = path.join(root, 'nested.tgz');
  execFileSync('tar', ['-czf', nested, '-C', nestedRoot, '.']);
  const outerRoot = path.join(root, 'outer');
  mkdirSync(outerRoot);
  execFileSync('cp', [nested, path.join(outerRoot, 'nested.tgz')]);
  const outer = path.join(root, 'outer.tar');
  execFileSync('tar', ['-cf', outer, '-C', outerRoot, '.']);
  assert.ok(scanBundles([outer], policy).some(finding => finding.includes('MASTRA_LICENSE_URL')));
});

test('CycloneDX gate binds the exact artifact, SBOM, complete component set, and source-established license policy', () => {
  const root = temporaryDirectory();
  const artifact = path.join(root, 'artifact.tar');
  const sbomPath = path.join(root, 'sbom.json');
  const inventoryPath = path.join(root, 'licenses.json');
  writeFileSync(artifact, 'synthetic fixture artifact\n');
  const safeComponents = [component('safe')];
  writeJson(sbomPath, cyclonedx('synthetic-fixture', sha256(artifact), safeComponents));
  writeJson(
    inventoryPath,
    cyclonedx('synthetic-fixture', sha256(artifact), safeComponents, { sbomDigest: sha256(sbomPath) }),
  );
  assert.deepEqual(scanLicenseInventory(inventoryPath, policy, { artifactPath: artifact, sbomPath }), []);

  const prohibited = [component('retired-ee', 'Mastra Enterprise Edition (EE) License')];
  writeJson(
    inventoryPath,
    cyclonedx('synthetic-fixture', sha256(artifact), prohibited, { sbomDigest: sha256(sbomPath) }),
  );
  const prohibitedFindings = scanLicenseInventory(inventoryPath, policy, { artifactPath: artifact, sbomPath });
  assert.ok(prohibitedFindings.some(finding => finding.includes('prohibited license')));
  assert.ok(
    prohibitedFindings.includes('license inventory component set does not exactly match the SBOM component set'),
  );
});

test('CycloneDX gate rejects NOASSERTION, malformed components, incomplete graphs, and unbound artifacts', () => {
  const root = temporaryDirectory();
  const artifact = path.join(root, 'artifact.tar');
  const sbomPath = path.join(root, 'sbom.json');
  const inventoryPath = path.join(root, 'licenses.json');
  writeFileSync(artifact, 'synthetic fixture artifact\n');
  const unknown = [component('unknown', 'NOASSERTION')];
  writeJson(sbomPath, cyclonedx('synthetic-fixture', sha256(artifact), unknown));
  const inventory = cyclonedx('synthetic-fixture', sha256(artifact), unknown, { sbomDigest: sha256(sbomPath) });
  writeJson(inventoryPath, inventory);
  assert.ok(
    scanLicenseInventory(inventoryPath, policy, { artifactPath: artifact, sbomPath }).some(finding =>
      finding.includes('missing or unresolved license conclusion'),
    ),
  );
  inventory.metadata.properties.find(property => property.name === 'expedient:artifact:sha256').value = zeroDigest;
  writeJson(inventoryPath, inventory);
  assert.ok(
    scanLicenseInventory(inventoryPath, policy, { artifactPath: artifact, sbomPath }).includes(
      'license inventory artifact digest does not match the built artifact',
    ),
  );
  inventory.dependencies.pop();
  writeJson(inventoryPath, inventory);
  const findings = scanLicenseInventory(inventoryPath, policy, { artifactPath: artifact, sbomPath });
  assert.ok(findings.some(finding => finding.includes('/dependencies') || finding.includes('dependency graph')));
  delete inventory.components[0].version;
  writeJson(inventoryPath, inventory);
  assert.ok(
    scanLicenseInventory(inventoryPath, policy, { artifactPath: artifact, sbomPath }).some(finding =>
      finding.includes("must have required property 'version'"),
    ),
  );
});

test('network review requires well-formed complete JSONL bound to all required runtime classes and artifact', () => {
  const root = temporaryDirectory();
  const artifact = path.join(root, 'artifact.tar');
  writeFileSync(artifact, 'synthetic fixture artifact\n');
  const valid = networkFiles(root, artifact);
  assert.deepEqual(reviewNetworkCapture(valid.capturePath, valid.allowlistPath, { root, artifactPath: artifact }), []);

  const omitted = networkFiles(root, artifact, { exercised: ['node'] });
  assert.deepEqual(reviewNetworkCapture(omitted.capturePath, omitted.allowlistPath, { root, artifactPath: artifact }), [
    'network runtime class was not exercised: browser',
  ]);
  const unbound = networkFiles(root, artifact, { headerDigest: zeroDigest });
  assert.ok(
    reviewNetworkCapture(unbound.capturePath, unbound.allowlistPath, { root, artifactPath: artifact }).includes(
      'network evidence is not bound to the exact built artifact digest',
    ),
  );
});

test('network review rejects empty, incomplete, malformed, failed, and implicit-port captures', () => {
  const root = temporaryDirectory();
  const artifact = path.join(root, 'artifact.tar');
  writeFileSync(artifact, 'synthetic fixture artifact\n');
  const { allowlistPath, capturePath } = networkFiles(root, artifact, { events: [] });
  assert.deepEqual(reviewNetworkCapture(capturePath, allowlistPath, { root, artifactPath: artifact }), [
    'network capture contains no network records',
  ]);
  writeFileSync(capturePath, '{bad json}\n{}\n');
  assert.throws(() => parseCapture(capturePath), /Invalid network capture line/);
  writeFileSync(capturePath, '{}');
  assert.throws(() => parseCapture(capturePath), /must end with a newline/);
  const validCapture = networkFiles(root, artifact).capturePath;
  const allowlist = readJson(allowlistPath);
  delete allowlist.destinations[0].ports;
  writeJson(allowlistPath, allowlist);
  assert.ok(
    reviewNetworkCapture(validCapture, allowlistPath, { root, artifactPath: artifact }).some(finding =>
      finding.includes("must have required property 'ports'"),
    ),
  );
});

test('capture output redaction is bounded and removes passed and token-shaped secrets', () => {
  const secret = 'fixture-secret-value-123456';
  const redacted = redactOutput(`${secret}\nghp_abcdefghijklmnopqrstuvwxyz0123456789\n${'x'.repeat(100000)}`, [secret]);
  assert.ok(!redacted.includes(secret));
  assert.ok(!redacted.includes('ghp_'));
  assert.ok(redacted.length <= 64 * 1024);
  assert.match(
    readFileSync(path.join(toolingRoot, 'network-capture-register.mjs'), 'utf8'),
    /not comprehensive release evidence/,
  );
});

test('release evidence schema rejects mutable commits, extra fields, unresolved facts, and noncanonical paths', () => {
  const mutable = evidenceManifest({ releaseCommit: 'HEAD' });
  assert.ok(
    schemaFindings(mutable, 'release-evidence.schema.json').some(finding => finding.includes('/releaseCommit')),
  );
  const extra = evidenceManifest({ unexpected: true });
  assert.ok(
    schemaFindings(extra, 'release-evidence.schema.json').some(finding => finding.includes('additional properties')),
  );
  const unresolved = evidenceManifest();
  unresolved.requiredFacts.commercialPackageNames = {
    status: 'resolved',
    decision: 'enumerated',
    values: [],
    review: review(),
  };
  assert.ok(
    schemaFindings(unresolved, 'release-evidence.schema.json').some(finding =>
      finding.includes('must NOT have fewer than 1 items'),
    ),
  );
  const absolute = evidenceManifest();
  absolute.artifact.path = '/tmp/artifact.tar';
  assert.ok(
    schemaFindings(absolute, 'release-evidence.schema.json').some(finding => finding.includes('/artifact/path')),
  );
});

test('synthetic fixture evidence can never authorize production and exact commits are checked against HEAD', () => {
  const root = temporaryDirectory();
  const manifestPath = path.join(root, 'evidence.json');
  writeJson(manifestPath, evidenceManifest());
  assert.deepEqual(verifyEvidence(repoRoot, manifestPath), [
    'synthetic fixture evidence cannot authorize a production release',
  ]);
  assert.ok(
    verifyEvidence(repoRoot, manifestPath, { allowSynthetic: true }).some(finding =>
      finding.includes('does not exist'),
    ),
  );

  const parent = execFileSync('git', ['-C', repoRoot, 'rev-parse', 'HEAD^'], { encoding: 'utf8' }).trim();
  const production = evidenceManifest({
    evidenceClass: 'release',
    reviewedBaselineCommit: parent,
    releaseCommit: parent,
  });
  writeJson(manifestPath, production);
  assert.ok(verifyEvidence(repoRoot, manifestPath).includes('releaseCommit is not the checked-out HEAD'));
});

test('canonical path resolution rejects traversal and out-of-root symlinks', () => {
  const root = temporaryDirectory();
  const outside = temporaryDirectory();
  writeFileSync(path.join(outside, 'evidence.json'), '{}\n');
  symlinkSync(path.join(outside, 'evidence.json'), path.join(root, 'evidence.json'));
  assert.throws(() => canonicalRepositoryPath(root, '../escape', 'fixture'), /canonical repository-relative path/);
  assert.throws(() => canonicalRepositoryPath(root, 'evidence.json', 'fixture'), /resolves outside/);
});

test('native compatibility evidence requires the exact fourteen areas, commands, commit, and artifact', () => {
  const root = temporaryDirectory();
  const artifact = path.join(root, 'artifact.tar');
  const evidencePath = path.join(root, 'compatibility.json');
  writeFileSync(artifact, 'synthetic fixture artifact\n');
  const manifest = readJson(path.join(toolingRoot, 'native-compatibility.json'));
  const evidence = {
    schemaVersion: 2,
    evidenceClass: 'synthetic-fixture',
    reviewedBaselineCommit: head,
    releaseCommit: head,
    artifactSha256: sha256(artifact),
    manifestSha256: sha256(path.join(toolingRoot, 'native-compatibility.json')),
    installationMode: 'clean-room-installed-tarballs',
    results: manifest.areas.map(area => ({
      id: area.id,
      status: 'passed',
      exitCode: 0,
      commandSha256: sha256Text(JSON.stringify(area.argv)),
      outputSha256: zeroDigest,
    })),
  };
  writeJson(evidencePath, evidence);
  assert.deepEqual(
    verifyCompatibilityEvidence(repoRoot, evidencePath, {
      artifactPath: artifact,
      reviewedBaselineCommit: head,
      releaseCommit: head,
    }),
    [],
  );
  evidence.results[0].commandSha256 = zeroDigest;
  evidence.artifactSha256 = zeroDigest;
  writeJson(evidencePath, evidence);
  const findings = verifyCompatibilityEvidence(repoRoot, evidencePath, {
    artifactPath: artifact,
    reviewedBaselineCommit: head,
    releaseCommit: head,
  });
  assert.ok(findings.some(finding => finding.includes('command drift')));
  assert.ok(findings.some(finding => finding.includes('not bound')));
});

test('commercial audit binds all seventeen records, complete discovery, snippets, blobs, drift, and commands', () => {
  assert.deepEqual(verifyAudit(repoRoot, undefined, { executeCommands: false }), []);
  assert.deepEqual(verifyAudit(repoRoot, undefined, { onlyId: 'CP-10', executeCommands: false }), []);
  const root = temporaryDirectory();
  const audit = readJson(path.join(toolingRoot, 'commercial-connection-audit.json'));
  audit.connectionPoints[0].historySources[0].snippetSha256 = zeroDigest;
  const auditPath = path.join(root, 'audit.json');
  writeJson(auditPath, audit);
  assert.ok(
    verifyAudit(repoRoot, auditPath, { executeCommands: false }).some(finding =>
      finding.includes('snippet fingerprint mismatch'),
    ),
  );
});

test('upstream sync accepts the immutable reviewed base and rejects mutable expressions', () => {
  assert.deepEqual(verifyUpstreamSync(repoRoot, head), []);
  assert.throws(() => verifyUpstreamSync(repoRoot, 'HEAD'), /exact lowercase 40-hex commit/);
});

test('artifact assembly rejects a dirty release checkout before packing', () => {
  const dirty = path.join(repoRoot, '.fork-release-dirty-fixture');
  writeFileSync(dirty, 'dirty fixture\n');
  try {
    const output = spawnSync(
      process.execPath,
      [
        path.join(toolingRoot, 'assemble-release-artifact.mjs'),
        '--root',
        repoRoot,
        '--output',
        'release/dirty-fixture.tgz',
        '--provenance',
        'release/dirty-fixture-provenance.json',
        '--name',
        '@expedient/mastra-native',
        '--version',
        '0.0.0-dirty-fixture',
        '--reviewed-baseline-commit',
        head,
        '--release-commit',
        head,
      ],
      { cwd: repoRoot, encoding: 'utf8' },
    );
    assert.notEqual(output.status, 0);
    assert.match(`${output.stdout}\n${output.stderr}`, /clean HEAD/);
  } finally {
    rmSync(dirty, { force: true });
  }
});

test('template checksum is root-relative and unresolved template remains fail closed', () => {
  assert.deepEqual(verifyTemplateIntegrity(), []);
  const checksum = readFileSync(path.join(toolingRoot, 'release-evidence.template.json.sha256'), 'utf8');
  assert.match(checksum, /scripts\/fork-release\/release-evidence\.template\.json/);
  assert.notEqual(verifyEvidence(repoRoot, path.join(toolingRoot, 'release-evidence.template.json')).length, 0);
});

test('publication workflow consumes only the artifact output of the full reusable release gate', () => {
  const gate = readFileSync(path.join(repoRoot, '.github/workflows/fork-release-gates.yml'), 'utf8');
  const publish = readFileSync(path.join(repoRoot, '.github/workflows/fork-npm-publish.yml'), 'utf8');
  for (const requirement of [
    'assemble-release-artifact.mjs',
    'assemble-release-manifest.mjs',
    'fork-npm-artifacts.tgz',
    'licenses',
    'network-linux',
    'network-review',
    'compatibility-run',
    'release --manifest',
  ])
    assert.ok(gate.includes(requirement));
  assert.match(publish, /needs: release-gates/);
  assert.match(publish, /needs\.release-gates\.outputs\.artifact_sha256/);
  assert.match(publish, /@expedient\/mastra-native/);
  assert.match(publish, /npm publish release\/fork-npm-artifacts\.tgz/);
  assert.match(publish, /PUBLISH-GATED-EXPEDIENT-FORK/);
  assert.doesNotMatch(publish, /npm publish \"\$tarball\"/);
});

test('release workflows pin the integrity-qualified toolchain and clean-room evidence order', () => {
  const packageJson = readJson(path.join(repoRoot, 'package.json'));
  assert.equal(
    packageJson.packageManager,
    'pnpm@11.13.1+sha512.b2fc7683b8a6525414e7d13e1ba28caaddde96bf66ec540bfaeb7e702b81f3e0be4d1f295edf7f9fe0396740a8dce4509c582ddf79891f4543fea32d37645f25',
  );
  const gate = readFileSync(path.join(repoRoot, '.github/workflows/fork-release-gates.yml'), 'utf8');
  const publish = readFileSync(path.join(repoRoot, '.github/workflows/fork-npm-publish.yml'), 'utf8');
  const cleanRoom = readFileSync(path.join(toolingRoot, 'clean-room-agent-builder.mjs'), 'utf8');
  assert.match(cleanRoom, /packageManager: EXPECTED_PACKAGE_MANAGER/);
  assert.match(cleanRoom, /pnpm@11\.13\.1\+sha512\.b2fc7683/);
  assert.match(gate, /git status --porcelain=v1 --untracked-files=all/);
  assert.match(gate, /PNPM_VERSION: 11\.13\.1/);
  assert.ok(gate.indexOf('network-review') < gate.indexOf('assemble-release-manifest.mjs'));
  assert.ok(gate.indexOf('compatibility-review') < gate.indexOf('assemble-release-manifest.mjs'));
  assert.match(publish, /npm install --global npm@11\.5\.1/);
  assert.match(publish, /EXPECTED_NAME:[^\n]+\n\s+EXPECTED_SHA256:[^\n]+\n\s+EXPECTED_VERSION:[^\n]+\n\s+NPM_TAG:/);
});
