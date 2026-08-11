#!/usr/bin/env node
import { execFileSync, spawnSync } from 'node:child_process';
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { GateError, readJson, redactOutput, schemaFindings, sha256 } from './lib.mjs';

const EXPECTED_NODE = '22.23.1';
const EXPECTED_PNPM = '11.13.1';
const NATIVE_PACKAGE = /^(?:mastra|@mastra\/[a-z0-9][a-z0-9-]*)$/;
const COMMIT = /^[0-9a-f]{40}$/;
const SEMVER =
  /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

function option(name, fallback) {
  const index = process.argv.indexOf(`--${name}`);
  if (index === -1) {
    if (fallback !== undefined) return fallback;
    throw new GateError(`--${name} is required`);
  }
  const value = process.argv[index + 1];
  if (!value || value.startsWith('--')) throw new GateError(`--${name} requires a value`);
  return value;
}

function within(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
}

function repositoryPath(root, value, label, { mustExist = true } = {}) {
  if (typeof value !== 'string' || value.length === 0 || path.isAbsolute(value) || value.includes('\\')) {
    throw new GateError(`${label} must be a canonical repository-relative path`);
  }
  const normalized = path.posix.normalize(value);
  if (normalized !== value || normalized === '.' || normalized.startsWith('../')) {
    throw new GateError(`${label} must be a canonical repository-relative path`);
  }
  const absoluteRoot = realpathSync(root);
  const absolute = path.resolve(absoluteRoot, value);
  if (!within(absoluteRoot, absolute)) throw new GateError(`${label} escapes the repository`);
  if (!existsSync(absolute)) {
    if (mustExist) throw new GateError(`${label} does not exist: ${value}`);
    return absolute;
  }
  if (!within(absoluteRoot, realpathSync(absolute))) throw new GateError(`${label} resolves outside the repository`);
  return absolute;
}

function verifyCommit(root, value, label) {
  if (!COMMIT.test(value)) throw new GateError(`--${label} must be an exact lowercase 40-hex commit`);
  const result = spawnSync('git', ['-C', root, 'cat-file', '-t', value], {
    encoding: 'utf8',
    timeout: 30_000,
    maxBuffer: 1024,
  });
  if (result.error || result.status !== 0 || result.stdout.trim() !== 'commit') {
    throw new GateError(`--${label} is not a commit object: ${value}`);
  }
}

function verifyCleanRelease(root, releaseCommit, reviewedBaselineCommit) {
  verifyCommit(root, releaseCommit, 'release-commit');
  verifyCommit(root, reviewedBaselineCommit, 'reviewed-baseline-commit');
  const head = spawnSync('git', ['-C', root, 'rev-parse', 'HEAD'], { encoding: 'utf8', timeout: 30_000 });
  if (head.status !== 0 || head.stdout.trim() !== releaseCommit) {
    throw new GateError('release commit must be the checked-out HEAD');
  }
  const ancestor = spawnSync(
    'git',
    ['-C', root, 'merge-base', '--is-ancestor', reviewedBaselineCommit, releaseCommit],
    {
      encoding: 'utf8',
      timeout: 30_000,
    },
  );
  if (ancestor.status !== 0) throw new GateError('reviewed baseline commit must be an ancestor of the release commit');
  const status = spawnSync('git', ['-C', root, 'status', '--porcelain=v1', '--untracked-files=all'], {
    encoding: 'utf8',
    timeout: 30_000,
    maxBuffer: 1024 * 1024,
  });
  if (status.status !== 0) throw new GateError('cannot inspect release checkout cleanliness');
  if (status.stdout.trim()) {
    throw new GateError(
      'release artifact must be assembled from a clean HEAD',
      redactOutput(status.stdout).trim().split('\n'),
    );
  }
}

function verifyToolchain() {
  if (process.versions.node !== EXPECTED_NODE) {
    throw new GateError(`Node ${EXPECTED_NODE} is required; found ${process.versions.node}`);
  }
  const result = spawnSync('pnpm', ['--version'], {
    encoding: 'utf8',
    timeout: 30_000,
    maxBuffer: 1024,
  });
  if (result.error || result.status !== 0 || result.stdout.trim() !== EXPECTED_PNPM) {
    throw new GateError(`pnpm ${EXPECTED_PNPM} is required; found ${(result.stdout ?? '').trim()}`);
  }
}

function listWorkspaceProjects(root) {
  const result = spawnSync('pnpm', ['--silent', '-r', 'list', '--depth', '-1', '--json'], {
    cwd: root,
    env: { HOME: process.env.HOME ?? root, LANG: 'C', PATH: process.env.PATH ?? '/usr/bin:/bin' },
    encoding: 'utf8',
    timeout: 120_000,
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.error || result.status !== 0) {
    throw new GateError('Cannot enumerate workspace packages', [
      redactOutput(`${result.stdout ?? ''}\n${result.stderr ?? ''}`),
    ]);
  }
  let projects;
  try {
    projects = JSON.parse(result.stdout);
  } catch (error) {
    throw new GateError(`Workspace package inventory is not valid JSON: ${error.message}`);
  }
  if (!Array.isArray(projects)) throw new GateError('Workspace package inventory must be an array');
  const byName = new Map();
  for (const project of projects) {
    if (typeof project?.name !== 'string' || typeof project.path !== 'string') continue;
    const projectPath = realpathSync(project.path);
    if (!within(realpathSync(root), projectPath)) {
      throw new GateError(`Workspace package resolves outside the repository: ${project.name}`);
    }
    const manifest = readJson(path.join(projectPath, 'package.json'));
    if (manifest.name !== project.name) throw new GateError(`Workspace package name drifted: ${project.name}`);
    if (byName.has(manifest.name)) throw new GateError(`Duplicate workspace package name: ${manifest.name}`);
    byName.set(manifest.name, { name: manifest.name, path: projectPath, manifest });
  }
  return byName;
}

function nativeDependencyNames(manifest) {
  return [
    ...new Set(
      ['dependencies', 'optionalDependencies', 'peerDependencies'].flatMap(field =>
        Object.keys(manifest[field] ?? {}).filter(name => NATIVE_PACKAGE.test(name)),
      ),
    ),
  ];
}

function selectProjects(byName, packageManifest) {
  const selected = new Set();
  const queue = [...packageManifest.roots];
  while (queue.length > 0) {
    const name = queue.shift();
    if (selected.has(name)) continue;
    if (!NATIVE_PACKAGE.test(name)) throw new GateError(`Unsupported native package identity: ${name}`);
    if (name === '@mastra/inngest') {
      throw new GateError('Inngest is an optional adapter and may not be an authoritative release root');
    }
    const project = byName.get(name);
    if (!project) throw new GateError(`Required native package is not in the workspace: ${name}`);
    if (project.manifest.private === true) throw new GateError(`Required native package is private: ${name}`);
    selected.add(name);
    for (const dependency of nativeDependencyNames(project.manifest)) {
      if (dependency === '@mastra/inngest') {
        throw new GateError(`Inngest may not be selected as a dependency of ${name}`);
      }
      if (!byName.has(dependency)) {
        throw new GateError(`Native package dependency is not in the workspace: ${name} -> ${dependency}`);
      }
      queue.push(dependency);
    }
  }
  return [...selected].sort((left, right) => left.localeCompare(right));
}

function packedManifest(tarball) {
  try {
    return JSON.parse(execFileSync('tar', ['-xOzf', tarball, 'package/package.json'], { encoding: 'utf8' }));
  } catch (error) {
    throw new GateError(`Packed package has no readable package/package.json: ${path.basename(tarball)}`, [
      redactOutput(error.stderr ?? error.message),
    ]);
  }
}

function packedEntries(tarball) {
  try {
    return execFileSync('tar', ['-tzf', tarball], { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 })
      .split('\n')
      .filter(Boolean);
  } catch (error) {
    throw new GateError(`Cannot inspect packed package ${path.basename(tarball)}`, [
      redactOutput(error.stderr ?? error.message),
    ]);
  }
}

function exportTargets(value, result = new Set()) {
  if (typeof value === 'string') {
    if (value.startsWith('./') && !value.includes('*')) result.add(value.slice(2));
  } else if (Array.isArray(value)) {
    for (const child of value) exportTargets(child, result);
  } else if (value && typeof value === 'object') {
    for (const child of Object.values(value)) exportTargets(child, result);
  }
  return result;
}

function verifyPackedPackage(tarball, expected) {
  const manifest = packedManifest(tarball);
  if (manifest.name !== expected.name || manifest.version !== expected.version) {
    throw new GateError(
      `Packed package identity drifted for ${expected.name}: ${manifest.name ?? '<missing>'}@${manifest.version ?? '<missing>'}`,
    );
  }
  const entries = new Set(packedEntries(tarball));
  const rootExport = manifest.exports?.['.'] ?? manifest.exports;
  for (const target of exportTargets(rootExport)) {
    if (!entries.has(`package/${target}`))
      throw new GateError(`${expected.name} root export is missing from its tarball: ${target}`);
  }
  for (const target of [manifest.main, manifest.module, manifest.types]) {
    if (typeof target === 'string' && target.startsWith('./') && !entries.has(`package/${target.slice(2)}`)) {
      throw new GateError(`${expected.name} entrypoint is missing from its tarball: ${target}`);
    }
  }
  return manifest;
}

function writeNpmBundle(output, temporary) {
  const version = spawnSync('tar', ['--version'], { encoding: 'utf8', timeout: 30_000, maxBuffer: 1024 });
  const gnu = version.status === 0 && /^tar \(GNU tar\)/.test(version.stdout);
  const args = gnu
    ? [
        '--sort=name',
        '--mtime=UTC 1970-01-01',
        '--owner=0',
        '--group=0',
        '--numeric-owner',
        '-czf',
        output,
        '-C',
        temporary,
        'package',
      ]
    : ['-czf', output, '-C', temporary, 'package'];
  const result = spawnSync('tar', args, {
    encoding: 'utf8',
    timeout: 180_000,
    maxBuffer: 64 * 1024,
    env: { ...process.env, COPYFILE_DISABLE: '1' },
  });
  if (result.error || result.status !== 0) {
    throw new GateError('Cannot assemble npm bundle', [redactOutput(`${result.stdout ?? ''}\n${result.stderr ?? ''}`)]);
  }
}

const root = realpathSync(path.resolve(option('root', '.')));
const manifestPath = repositoryPath(
  root,
  option('manifest', 'scripts/fork-release/native-package-manifest.json'),
  'package manifest',
);
const packageManifest = readJson(manifestPath);
const manifestErrors = schemaFindings(
  packageManifest,
  'native-package-manifest.schema.json',
  'native package manifest',
);
if (manifestErrors.length > 0) throw new GateError('Native package manifest is invalid', manifestErrors);
const artifactName = option('name', packageManifest.artifactName);
const artifactVersion = option('version');
const releaseCommit = option('release-commit');
const reviewedBaselineCommit = option('reviewed-baseline-commit');
const output = repositoryPath(root, option('output'), 'artifact output', { mustExist: false });
const provenance = repositoryPath(root, option('provenance', 'release/fork-provenance.json'), 'provenance output', {
  mustExist: false,
});
if (artifactName !== packageManifest.artifactName) {
  throw new GateError(`Artifact name must be ${packageManifest.artifactName}; refusing an unowned identity`);
}
if (!SEMVER.test(artifactVersion)) throw new GateError(`Artifact version is not npm-compatible: ${artifactVersion}`);
if (existsSync(output) || existsSync(provenance))
  throw new GateError('Refusing to overwrite an existing release artifact or provenance file');
verifyCleanRelease(root, releaseCommit, reviewedBaselineCommit);
verifyToolchain();
mkdirSync(path.dirname(output), { recursive: true });
mkdirSync(path.dirname(provenance), { recursive: true });

const byName = listWorkspaceProjects(root);
const packageNames = selectProjects(byName, packageManifest);
const temporary = mkdtempSync(path.join(tmpdir(), 'fork-release-pack-'));
chmodSync(temporary, 0o700);
try {
  const packageRoot = path.join(temporary, 'package');
  const tarballDirectory = path.join(packageRoot, 'tarballs');
  mkdirSync(tarballDirectory, { recursive: true, mode: 0o700 });
  const index = [];
  for (const name of packageNames) {
    const project = byName.get(name);
    const before = new Set(readdirSync(tarballDirectory));
    const result = spawnSync('pnpm', ['pack', '--pack-destination', tarballDirectory], {
      cwd: project.path,
      env: {
        HOME: process.env.HOME ?? root,
        LANG: 'C',
        PATH: process.env.PATH ?? '/usr/bin:/bin',
        npm_config_ignore_scripts: 'true',
      },
      encoding: 'utf8',
      timeout: 180_000,
      maxBuffer: 256 * 1024,
    });
    if (result.error || result.status !== 0) {
      throw new GateError(`Packing failed for ${name}`, [
        redactOutput(`${result.stdout ?? ''}\n${result.stderr ?? ''}`),
      ]);
    }
    const created = readdirSync(tarballDirectory).filter(file => file.endsWith('.tgz') && !before.has(file));
    if (created.length !== 1) throw new GateError(`Packing did not produce exactly one tarball for ${name}`);
    const file = created[0];
    const absoluteTarball = path.join(tarballDirectory, file);
    const packed = verifyPackedPackage(absoluteTarball, project.manifest);
    index.push({ name, version: packed.version, file, sha256: sha256(absoluteTarball) });
  }
  if (new Set(index.map(item => item.name)).size !== index.length)
    throw new GateError('Duplicate package identities in artifact');
  if (new Set(index.map(item => item.file)).size !== index.length)
    throw new GateError('Duplicate package tarball names in artifact');

  const artifactIndex = {
    schemaVersion: 2,
    artifact: { name: artifactName, version: artifactVersion },
    reviewedBaselineCommit,
    releaseCommit,
    toolchain: { node: EXPECTED_NODE, pnpm: EXPECTED_PNPM },
    packages: index,
  };
  writeFileSync(path.join(packageRoot, 'artifact-index.json'), `${JSON.stringify(artifactIndex, null, 2)}\n`, {
    mode: 0o644,
  });
  writeFileSync(
    path.join(packageRoot, 'package.json'),
    `${JSON.stringify(
      {
        name: artifactName,
        version: artifactVersion,
        description: 'Immutable Expedient Mastra native package bundle',
        type: 'module',
        license: 'Apache-2.0',
        files: ['artifact-index.json', 'tarballs', 'README.md'],
        exports: {
          './artifact-index': './artifact-index.json',
          './tarballs/*': './tarballs/*',
        },
        publishConfig: { access: 'public' },
        engines: { node: `>=${EXPECTED_NODE}` },
      },
      null,
      2,
    )}\n`,
    { mode: 0o644 },
  );
  writeFileSync(
    path.join(packageRoot, 'README.md'),
    `# ${artifactName}\n\nThis is an immutable transport bundle for the Expedient Mastra fork. It is not an upstream @mastra/* registry release. Install the exact inner package tarballs listed in artifact-index.json and verify each SHA-256 before activating a fork runtime.\n\nReviewed baseline commit: ${reviewedBaselineCommit}\nRelease commit: ${releaseCommit}\n\nThe bundle intentionally does not select Inngest as an authoritative runtime.\n`,
    { mode: 0o644 },
  );
  writeNpmBundle(output, temporary);
  const artifactSha256 = sha256(output);
  const provenanceDocument = {
    predicateType: 'https://slsa.dev/provenance/v1',
    buildType: 'https://schemas.expedient.invalid/fork-release/native-package-bundle/v2',
    builder: { id: 'https://github.com/Expedient/mastra/.github/workflows/fork-release-gates.yml' },
    reviewedBaselineCommit,
    releaseCommit,
    version: artifactVersion,
    artifactSha256,
    subject: [{ name: artifactName, digest: { sha256: artifactSha256 } }],
    toolchain: { node: EXPECTED_NODE, pnpm: EXPECTED_PNPM },
    packages: index,
  };
  writeFileSync(provenance, `${JSON.stringify(provenanceDocument, null, 2)}\n`, { mode: 0o600 });
  console.log(
    JSON.stringify({
      artifact: { name: artifactName, version: artifactVersion },
      packageCount: index.length,
      path: output,
      sha256: artifactSha256,
      provenance,
      provenanceSha256: sha256(provenance),
    }),
  );
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
