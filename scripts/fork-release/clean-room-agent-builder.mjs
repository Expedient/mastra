#!/usr/bin/env node
import { execFileSync, spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { readArtifactIndex, sha256 } from './lib.mjs';

const EXPECTED_NODE = '22.23.1';
const EXPECTED_PNPM = '11.13.1';
const EXPECTED_PACKAGE_MANAGER =
  'pnpm@11.13.1+sha512.b2fc7683b8a6525414e7d13e1ba28caaddde96bf66ec540bfaeb7e702b81f3e0be4d1f295edf7f9fe0396740a8dce4509c582ddf79891f4543fea32d37645f25';
const AREA_IMPORTS = {
  studio: [],
  playground: ['@mastra/playground-ui/tokens'],
  'clean-room-agent-builder': ['@mastra/agent-builder', '@mastra/editor', '@mastra/core/mastra'],
  'agents-tools': ['@mastra/core/agent', '@mastra/core/tools'],
  'workflows-recovery': ['@mastra/core/workflows'],
  schedules: ['@mastra/core/workflows'],
  'ag-ui': ['@mastra/core/agent/message-list'],
  skills: ['@mastra/core/agent'],
  workspaces: ['@mastra/core/workspace'],
  memory: ['@mastra/memory'],
  'settings-upgrade': ['@mastra/core'],
  evaluations: ['@mastra/evals'],
  postgres: ['@mastra/pg'],
  'public-oss-apis': ['@mastra/core/auth', '@mastra/server'],
};

function argument(name) {
  const index = process.argv.indexOf(`--${name}`);
  return index === -1 ? undefined : process.argv[index + 1];
}

const artifact = process.env.FORK_RELEASE_ARTIFACT;
const area = argument('area');
if (!artifact || !path.isAbsolute(artifact))
  throw new Error('FORK_RELEASE_ARTIFACT must be an absolute immutable bundle path');
if (!existsSync(artifact)) throw new Error(`FORK_RELEASE_ARTIFACT does not exist: ${artifact}`);
if (!area || !Object.hasOwn(AREA_IMPORTS, area)) throw new Error('--area must name one declared compatibility area');
if (process.versions.node !== EXPECTED_NODE) throw new Error(`Node ${EXPECTED_NODE} is required`);
const pnpmVersion = spawnSync('pnpm', ['--version'], { encoding: 'utf8', timeout: 30_000 });
if (pnpmVersion.status !== 0 || pnpmVersion.stdout.trim() !== EXPECTED_PNPM)
  throw new Error(`pnpm ${EXPECTED_PNPM} is required`);
const storeResult = spawnSync('pnpm', ['store', 'path'], { encoding: 'utf8', timeout: 30_000 });
if (storeResult.status !== 0) throw new Error('Cannot locate the pinned pnpm store for clean-room installation');
const storePath = storeResult.stdout.trim().split(/\r?\n/).at(-1);
if (!storePath || !path.isAbsolute(storePath)) throw new Error('Pinned pnpm store path is not absolute');

function tar(args, options = {}) {
  const compressed = artifact.endsWith('.tgz') || artifact.endsWith('.tar.gz');
  return execFileSync('tar', [compressed ? '-xzf' : '-xf', ...args], {
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
    stdio: ['ignore', 'pipe', 'pipe'],
    ...options,
  });
}

const temporary = mkdtempSync(path.join(tmpdir(), 'fork-release-clean-room-'));
chmodSync(temporary, 0o700);
try {
  const listing = execFileSync(
    'tar',
    [artifact.endsWith('.tgz') || artifact.endsWith('.tar.gz') ? '-tzf' : '-tf', artifact],
    { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 },
  )
    .split('\n')
    .filter(Boolean);
  if (listing.length === 0) throw new Error('immutable release bundle is empty');
  for (const entry of listing) {
    if (entry.includes('\\') || path.posix.isAbsolute(entry) || path.posix.normalize(entry).startsWith('../')) {
      throw new Error(`unsafe release bundle entry: ${entry}`);
    }
  }
  tar([artifact, '-C', temporary]);
  const packageRoot = existsSync(path.join(temporary, 'package')) ? path.join(temporary, 'package') : temporary;
  const tarballDirectory = path.join(packageRoot, 'tarballs');
  const tarballs = readdirSync(tarballDirectory)
    .filter(name => name.endsWith('.tgz'))
    .sort();
  if (tarballs.length === 0) throw new Error('immutable release bundle contains no npm package tarballs');

  const packages = new Map();
  for (const file of tarballs) {
    const tarball = path.join(tarballDirectory, file);
    const manifest = JSON.parse(execFileSync('tar', ['-xOzf', tarball, 'package/package.json'], { encoding: 'utf8' }));
    if (!manifest.name || !manifest.version || packages.has(manifest.name)) {
      throw new Error(`invalid or duplicate packed package: ${manifest.name ?? file}`);
    }
    packages.set(manifest.name, { manifest, tarball });
  }
  const artifactIndex = readArtifactIndex(artifact);
  if (artifactIndex.packages.length !== packages.size) throw new Error('artifact index package count is incomplete');
  if (artifactIndex.releaseCommit !== process.env.RELEASE_COMMIT) {
    throw new Error('artifact release commit does not match the compatibility checkout');
  }
  if (artifactIndex.reviewedBaselineCommit !== process.env.REVIEWED_BASELINE_COMMIT) {
    throw new Error('artifact reviewed baseline does not match compatibility evidence');
  }
  for (const item of artifactIndex.packages) {
    const packed = packages.get(item.name);
    if (
      !packed ||
      packed.manifest.version !== item.version ||
      path.basename(packed.tarball) !== item.file ||
      sha256(packed.tarball) !== item.sha256
    ) {
      throw new Error(`artifact index does not match packed package ${item.name}`);
    }
  }
  for (const required of [
    '@mastra/core',
    '@mastra/agent-builder',
    '@mastra/editor',
    '@mastra/playground-ui',
    'mastra',
  ]) {
    if (!packages.has(required)) throw new Error(`immutable bundle is missing ${required}`);
  }
  if (packages.has('@mastra/inngest')) throw new Error('Inngest must not be authoritative in the native bundle');
  for (const { manifest } of packages.values()) {
    for (const field of ['dependencies', 'optionalDependencies', 'peerDependencies']) {
      for (const dependency of Object.keys(manifest[field] ?? {})) {
        if ((dependency.startsWith('@mastra/') || dependency === 'mastra') && !packages.has(dependency)) {
          throw new Error(`immutable bundle omitted native dependency ${dependency} required by ${manifest.name}`);
        }
      }
    }
  }

  const fileDependencies = Object.fromEntries([...packages].map(([name, value]) => [name, `file:${value.tarball}`]));
  writeFileSync(
    path.join(temporary, 'package.json'),
    `${JSON.stringify(
      {
        name: 'fork-release-clean-room',
        private: true,
        type: 'module',
        packageManager: EXPECTED_PACKAGE_MANAGER,
        dependencies: fileDependencies,
      },
      null,
      2,
    )}\n`,
    { mode: 0o600 },
  );
  writeFileSync(
    path.join(temporary, 'pnpm-workspace.yaml'),
    `overrides:\n${Object.entries(fileDependencies)
      .map(([name, value]) => `  ${JSON.stringify(name)}: ${JSON.stringify(value)}`)
      .join('\n')}\n`,
    { mode: 0o600 },
  );
  execFileSync('pnpm', ['install', '--store-dir', storePath, '--ignore-scripts', '--frozen-lockfile=false'], {
    cwd: temporary,
    env: {
      HOME: temporary,
      LANG: 'C',
      PATH: process.env.PATH ?? '/usr/bin:/bin',
      PNPM_HOME: process.env.PNPM_HOME ?? '',
      XDG_CACHE_HOME:
        process.env.XDG_CACHE_HOME ??
        (process.platform === 'darwin'
          ? path.join(process.env.HOME ?? temporary, 'Library', 'Caches')
          : path.join(process.env.HOME ?? temporary, '.cache')),
    },
    encoding: 'utf8',
    maxBuffer: 256 * 1024,
    timeout: 240_000,
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  if (area === 'studio') {
    const cli = path.join(temporary, 'node_modules', '.bin', process.platform === 'win32' ? 'mastra.cmd' : 'mastra');
    const result = spawnSync(cli, ['--help'], {
      cwd: temporary,
      env: { HOME: temporary, LANG: 'C', PATH: process.env.PATH ?? '/usr/bin:/bin' },
      encoding: 'utf8',
      timeout: 30_000,
    });
    const cliOutput = `${result.stdout ?? ''}\n${result.stderr ?? ''}`;
    if (result.error || result.status !== 0 || !cliOutput.toLowerCase().includes('mastra')) {
      throw new Error(
        `installed Studio CLI failed its clean-room startup check (status ${result.status ?? 'none'}): ${cliOutput.slice(0, 4096) || result.error?.message || 'no output'}`,
      );
    }
  } else {
    writeFileSync(
      path.join(temporary, 'smoke.mjs'),
      `${AREA_IMPORTS[area].map(specifier => `const m${Math.random().toString(16).slice(2)} = await import(${JSON.stringify(specifier)});`).join('\n')}\n`,
      { mode: 0o600 },
    );
    execFileSync(process.execPath, ['smoke.mjs'], {
      cwd: temporary,
      env: { HOME: temporary, LANG: 'C', NODE_ENV: 'test', PATH: process.env.PATH ?? '/usr/bin:/bin' },
      encoding: 'utf8',
      maxBuffer: 64 * 1024,
      timeout: 30_000,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  }
  console.log(
    `clean-room ${area} passed from ${packages.size} installed tarballs (${artifactIndex.artifact.name}@${artifactIndex.artifact.version}, ${sha256(artifact)})`,
  );
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
