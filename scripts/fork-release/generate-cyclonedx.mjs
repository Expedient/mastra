#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';

import { GateError, readArtifactIndex, readJson, redactOutput, sha256 } from './lib.mjs';

function option(name) {
  const index = process.argv.indexOf(`--${name}`);
  if (index === -1 || !process.argv[index + 1]) throw new GateError(`--${name} is required`);
  return process.argv[index + 1];
}

let storeRoot;
function findInstalledManifest(root, name, version) {
  const candidates = [path.join(root, 'node_modules', name, 'package.json')];
  const scanRoots = [path.join(root, 'node_modules', '.pnpm', 'node_modules')];
  if (storeRoot === undefined) {
    const result = spawnSync('pnpm', ['store', 'path'], { encoding: 'utf8', timeout: 30_000, maxBuffer: 4096 });
    storeRoot = result.status === 0 ? result.stdout.trim().split(/\r?\n/).at(-1) || null : null;
  }
  if (storeRoot) {
    const linkName = name.startsWith('@') ? name.split('/') : ['@', name];
    scanRoots.push(path.join(storeRoot, 'links', ...linkName, version));
  }
  const visited = new Set();
  const visit = directory => {
    if (!existsSync(directory) || visited.has(directory)) return;
    visited.add(directory);
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const candidate = path.join(directory, entry.name);
      if (entry.isFile() && entry.name === 'package.json') candidates.push(candidate);
      else if (entry.isDirectory() && !entry.isSymbolicLink()) visit(candidate);
      else if (entry.isSymbolicLink()) candidates.push(path.join(candidate, 'package.json'));
    }
  };
  for (const scanRoot of scanRoots) visit(scanRoot);
  for (const candidate of candidates) {
    try {
      const manifest = JSON.parse(readFileSync(candidate, 'utf8'));
      if (manifest.name === name && manifest.version === version) return candidate;
    } catch {
      // An incomplete optional dependency is handled by the fail-closed error below.
    }
  }
  return undefined;
}

function componentHash(packagePath, name, version, root) {
  const direct = path.join(packagePath, 'package.json');
  const manifest = existsSync(direct) ? direct : findInstalledManifest(root, name, version);
  if (!manifest) throw new GateError(`Cannot bind ${name}@${version} to an installed package manifest`);
  return sha256(manifest);
}

function uuidFromDigest(digest) {
  const value = digest.slice(0, 32);
  return `${value.slice(0, 8)}-${value.slice(8, 12)}-4${value.slice(13, 16)}-8${value.slice(17, 20)}-${value.slice(20, 32)}`;
}

const root = path.resolve(option('root'));
const artifactPath = path.resolve(root, option('artifact'));
const sbomPath = path.resolve(root, option('sbom'));
const inventoryPath = path.resolve(root, option('inventory'));
const artifactName = option('name');
const artifactVersion = option('version');
const artifactDigest = sha256(artifactPath);
const artifactIndex = readArtifactIndex(artifactPath);
if (artifactIndex.artifact.name !== artifactName || artifactIndex.artifact.version !== artifactVersion) {
  throw new GateError('Requested CycloneDX identity does not match the packed artifact index');
}

const filters = artifactIndex.packages.flatMap(item => ['--filter', item.name]);
const result = spawnSync('pnpm', ['licenses', 'list', '--prod', '--json', ...filters], {
  cwd: root,
  env: { HOME: process.env.HOME ?? root, LANG: 'C', PATH: process.env.PATH ?? '/usr/bin:/bin' },
  encoding: 'utf8',
  timeout: 180_000,
  maxBuffer: 64 * 1024 * 1024,
});
if (result.error || result.status !== 0)
  throw new GateError('Cannot enumerate production licenses', [redactOutput(result.stderr)]);
const licenses = JSON.parse(result.stdout);
const componentMap = new Map();
for (const [license, packages] of Object.entries(licenses)) {
  for (const entry of packages) {
    for (const version of entry.versions ?? []) {
      const key = `${entry.name}@${version}`;
      if (componentMap.has(key) && componentMap.get(key).license !== license) {
        throw new GateError(`Conflicting license conclusions for ${key}`);
      }
      componentMap.set(key, {
        license,
        component: {
          type: 'library',
          'bom-ref': `pkg:npm/${encodeURIComponent(entry.name)}@${encodeURIComponent(version)}`,
          name: entry.name,
          version,
          hashes: [{ alg: 'SHA-256', content: componentHash(entry.paths?.[0] ?? '', entry.name, version, root) }],
          licenses: [{ expression: license }],
          purl: `pkg:npm/${encodeURIComponent(entry.name)}@${encodeURIComponent(version)}`,
        },
      });
    }
  }
}
const components = [...componentMap.values()]
  .map(value => value.component)
  .sort((left, right) => left['bom-ref'].localeCompare(right['bom-ref']));
if (components.length === 0) throw new GateError('Production license inventory is empty');
const rootRef = `urn:expedient:artifact:${artifactDigest}`;
const rootComponent = {
  type: 'application',
  'bom-ref': rootRef,
  name: artifactName,
  version: artifactVersion,
  hashes: [{ alg: 'SHA-256', content: artifactDigest }],
  licenses: [{ expression: 'Apache-2.0' }],
};
const dependencies = [
  { ref: rootRef, dependsOn: components.map(component => component['bom-ref']) },
  ...components.map(component => ({ ref: component['bom-ref'], dependsOn: [] })),
];
const base = {
  bomFormat: 'CycloneDX',
  specVersion: '1.6',
  serialNumber: `urn:uuid:${uuidFromDigest(artifactDigest)}`,
  version: 1,
  metadata: {
    component: rootComponent,
    properties: [
      { name: 'expedient:artifact:sha256', value: artifactDigest },
      { name: 'expedient:inventory:complete', value: 'true' },
      { name: 'expedient:inventory:scope', value: 'shipped-production-closure' },
    ],
  },
  components,
  dependencies,
};
writeFileSync(sbomPath, `${JSON.stringify(base, null, 2)}\n`, { mode: 0o600 });
const inventory = structuredClone(base);
inventory.metadata.properties.push({ name: 'expedient:sbom:sha256', value: sha256(sbomPath) });
writeFileSync(inventoryPath, `${JSON.stringify(inventory, null, 2)}\n`, { mode: 0o600 });
void readJson(inventoryPath);
console.log(
  JSON.stringify({
    artifactSha256: artifactDigest,
    componentCount: components.length,
    sbomSha256: sha256(sbomPath),
    inventorySha256: sha256(inventoryPath),
  }),
);
