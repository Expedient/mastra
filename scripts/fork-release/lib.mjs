import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import Ajv2020 from 'ajv/dist/2020.js';

export const toolingRoot = path.dirname(fileURLToPath(import.meta.url));
export const defaultPolicyPath = path.join(toolingRoot, 'policy.json');
export const defaultAuditPath = path.join(toolingRoot, 'commercial-connection-audit.json');
export const defaultCompatibilityPath = path.join(toolingRoot, 'native-compatibility.json');
export const templatePath = path.join(toolingRoot, 'release-evidence.template.json');
export const templateDigestPath = `${templatePath}.sha256`;

const schemaRoot = path.join(toolingRoot, 'schemas');
const dependencyFields = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'];
const sourceExtensions = new Set(['.cjs', '.cts', '.js', '.jsx', '.mjs', '.mts', '.ts', '.tsx']);
const archiveExtensions = ['.tar', '.tar.gz', '.tgz'];
const skippedDirectories = new Set(['.git', '.next', '.turbo', 'coverage', 'dist', 'node_modules']);
const placeholderPattern =
  /(?:^|\b)(?:UNKNOWN|UNRESOLVED|TBD|PLACEHOLDER|NOASSERTION|UNLICENSED|N\/A|NOT[ -]?APPLICABLE)(?:\b|$)/i;
const commitPattern = /^[0-9a-f]{40}$/;
const digestPattern = /^[0-9a-f]{64}$/;
const requiredCompatibilityAreas = [
  'studio',
  'playground',
  'clean-room-agent-builder',
  'agents-tools',
  'workflows-recovery',
  'schedules',
  'ag-ui',
  'skills',
  'workspaces',
  'memory',
  'settings-upgrade',
  'evaluations',
  'postgres',
  'public-oss-apis',
];

export class GateError extends Error {
  constructor(message, findings = []) {
    super(message);
    this.name = 'GateError';
    this.findings = findings;
  }
}

export function readJson(file) {
  try {
    return JSON.parse(readFileSync(file, 'utf8'));
  } catch (error) {
    throw new GateError(`Cannot read JSON ${file}: ${error.message}`);
  }
}

const validators = new Map();

function schemaValidator(schemaName) {
  if (!validators.has(schemaName)) {
    const schemaPath = path.join(schemaRoot, schemaName);
    const ajv = new Ajv2020({ allErrors: true, strict: true });
    const validate = ajv.compile(readJson(schemaPath));
    validators.set(schemaName, validate);
  }
  return validators.get(schemaName);
}

export function schemaFindings(value, schemaName, label = schemaName) {
  const validate = schemaValidator(schemaName);
  if (validate(value)) return [];
  return (validate.errors ?? []).map(error => {
    const location = error.instancePath || '/';
    return `${label}${location}: ${error.message}`;
  });
}

function requireSchema(value, schemaName, label) {
  const findings = schemaFindings(value, schemaName, label);
  if (findings.length > 0) throw new GateError(`${label} does not satisfy ${schemaName}`, findings);
}

export function loadPolicy(file = defaultPolicyPath) {
  const policy = readJson(file);
  requireSchema(policy, 'policy.schema.json', `Policy ${file}`);
  return policy;
}

function normalize(relativePath) {
  return relativePath.split(path.sep).join('/');
}

function within(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
}

export function canonicalRepositoryPath(root, candidate, label, { mustExist = true } = {}) {
  if (
    typeof candidate !== 'string' ||
    candidate.length === 0 ||
    path.isAbsolute(candidate) ||
    candidate.includes('\\')
  ) {
    throw new GateError(`${label} must be a canonical repository-relative path`);
  }
  const normalized = path.posix.normalize(candidate);
  if (normalized !== candidate || normalized === '.' || normalized.startsWith('../')) {
    throw new GateError(`${label} must be a canonical repository-relative path`);
  }
  const absoluteRoot = realpathSync(root);
  const absolute = path.resolve(absoluteRoot, candidate);
  if (!within(absoluteRoot, absolute)) throw new GateError(`${label} escapes the repository: ${candidate}`);
  if (!existsSync(absolute)) {
    if (mustExist) throw new GateError(`${label} does not exist: ${candidate}`);
    return absolute;
  }
  const real = realpathSync(absolute);
  if (!within(absoluteRoot, real)) throw new GateError(`${label} resolves outside the repository: ${candidate}`);
  return absolute;
}

function walk(
  directory,
  { includeFile = () => true, excludedPrefixes = [], skipDirectories = skippedDirectories } = {},
  root = directory,
) {
  if (!existsSync(directory)) throw new GateError(`Path does not exist: ${directory}`);
  const absoluteRoot = realpathSync(root);
  const result = [];
  const activeDirectories = new Set();

  function visit(physicalDirectory, logicalDirectory) {
    const realDirectory = realpathSync(physicalDirectory);
    if (!within(absoluteRoot, realDirectory))
      throw new GateError(`Directory resolves outside scan root: ${logicalDirectory}`);
    if (activeDirectories.has(realDirectory))
      throw new GateError(`Symlink directory cycle detected: ${logicalDirectory}`);
    activeDirectories.add(realDirectory);
    for (const entry of readdirSync(physicalDirectory, { withFileTypes: true })) {
      const physical = path.join(physicalDirectory, entry.name);
      const logical = path.join(logicalDirectory, entry.name);
      const relative = normalize(path.relative(root, logical));
      if (excludedPrefixes.some(prefix => relative === prefix || relative.startsWith(`${prefix}/`))) continue;
      const metadata = lstatSync(physical);
      if (metadata.isSymbolicLink()) {
        const target = realpathSync(physical);
        if (!within(absoluteRoot, target)) throw new GateError(`Symlink resolves outside scan root: ${relative}`);
        const targetMetadata = statSync(target);
        if (targetMetadata.isDirectory()) visit(target, logical);
        else if (targetMetadata.isFile() && includeFile(target, relative)) result.push({ absolute: target, relative });
      } else if (metadata.isDirectory()) {
        if (!skipDirectories.has(entry.name)) visit(physical, logical);
      } else if (metadata.isFile() && includeFile(physical, relative)) {
        result.push({ absolute: physical, relative });
      }
    }
    activeDirectories.delete(realDirectory);
  }

  visit(directory, directory);
  return result.sort((left, right) => left.relative.localeCompare(right.relative));
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function prohibitedSpecifier(specifier, policy) {
  return policy.prohibitedModuleSpecifiers.some(root => specifier === root || specifier.startsWith(`${root}/`));
}

function prohibitedPackage(name, policy) {
  return policy.prohibitedPackageNames.some(root => name === root || name.startsWith(`${root}/`));
}

function prohibitedPath(relative, policy) {
  return policy.prohibitedSourcePathSegments.some(
    segment => relative === segment || relative.startsWith(`${segment}/`),
  );
}

function stringsIn(value) {
  if (typeof value === 'string') return [value];
  if (Array.isArray(value)) return value.flatMap(stringsIn);
  if (value && typeof value === 'object')
    return Object.entries(value).flatMap(([key, child]) => [key, ...stringsIn(child)]);
  return [];
}

export function scanDependencyGraph(root, policy = loadPolicy()) {
  const findings = [];
  const manifests = walk(root, {
    includeFile: (_absolute, relative) => path.basename(relative) === 'package.json',
    excludedPrefixes: policy.scanExcludedPrefixes,
  });
  for (const { absolute: manifestPath, relative } of manifests) {
    const manifest = readJson(manifestPath);
    for (const field of dependencyFields) {
      for (const dependency of Object.keys(manifest[field] ?? {})) {
        if (prohibitedPackage(dependency, policy)) findings.push(`${relative}: ${field}.${dependency}`);
      }
    }
    if (typeof manifest.name === 'string') {
      for (const exportKey of Object.keys(manifest.exports ?? {})) {
        const specifier = exportKey === '.' ? manifest.name : `${manifest.name}/${exportKey.replace(/^\.\//, '')}`;
        if (prohibitedSpecifier(specifier.replace(/\/\*$/, ''), policy))
          findings.push(`${relative}: exports.${exportKey}`);
      }
    }
    for (const value of stringsIn(manifest.imports ?? {})) {
      const normalized = value.replace(/^\.\//, '');
      if (
        prohibitedSpecifier(value.replace(/\/\*$/, ''), policy) ||
        prohibitedPath(normalized.replace(/\/\*$/, ''), policy)
      ) {
        findings.push(`${relative}: prohibited package import alias ${value}`);
      }
    }
  }
  const tsconfigs = walk(root, {
    includeFile: (_absolute, relative) => /^tsconfig(?:\.[^.]+)?\.json$/.test(path.basename(relative)),
    excludedPrefixes: policy.scanExcludedPrefixes,
  });
  for (const { absolute, relative } of tsconfigs) {
    let config;
    try {
      config = readJson(absolute);
    } catch {
      continue;
    }
    for (const value of stringsIn(config.compilerOptions?.paths ?? {})) {
      const normalized = value.replace(/^\.\//, '').replace(/\/\*$/, '');
      if (prohibitedSpecifier(value.replace(/\/\*$/, ''), policy) || prohibitedPath(normalized, policy)) {
        findings.push(`${relative}: prohibited TypeScript alias ${value}`);
      }
    }
  }
  const lockPath = path.join(root, 'pnpm-lock.yaml');
  if (existsSync(lockPath)) {
    const lines = readFileSync(lockPath, 'utf8').split('\n');
    for (const dependency of policy.prohibitedPackageNames) {
      const pattern = new RegExp(`(^|[\\s/'"])${escapeRegExp(dependency)}(?=[:@/\\s'"])`);
      lines.forEach((line, index) => {
        if (pattern.test(line)) findings.push(`pnpm-lock.yaml:${index + 1}: ${dependency}`);
      });
    }
  }
  return [...new Set(findings)].sort();
}

function maskComments(source) {
  let output = '';
  let state = 'code';
  let quote = '';
  for (let index = 0; index < source.length; index += 1) {
    const char = source[index];
    const next = source[index + 1];
    if (state === 'line') {
      if (char === '\n') {
        state = 'code';
        output += '\n';
      } else output += ' ';
      continue;
    }
    if (state === 'block') {
      if (char === '*' && next === '/') {
        output += '  ';
        index += 1;
        state = 'code';
      } else output += char === '\n' ? '\n' : ' ';
      continue;
    }
    if (state === 'string') {
      output += char;
      if (char === '\\') {
        output += next ?? '';
        index += 1;
      } else if (char === quote) state = 'code';
      continue;
    }
    if (char === '/' && next === '/') {
      output += '  ';
      index += 1;
      state = 'line';
    } else if (char === '/' && next === '*') {
      output += '  ';
      index += 1;
      state = 'block';
    } else {
      output += char;
      if (char === "'" || char === '"' || char === '`') {
        state = 'string';
        quote = char;
      }
    }
  }
  return output;
}

export function extractActiveModuleSpecifiers(source) {
  const masked = maskComments(source);
  const found = [];
  const patterns = [
    /(?:^|[;\n])\s*(?:import|export)\s+(?:type\s+)?(?:(?!;)[\s\S])*?\bfrom\s*(['"])([^'"]+)\1/g,
    /(?:^|[;\n])\s*import\s*(['"])([^'"]+)\1/g,
    /\b(?:import|require)\s*\(\s*(['"])([^'"]+)\1\s*\)/g,
  ];
  for (const pattern of patterns) {
    for (const match of masked.matchAll(pattern)) found.push({ specifier: match[2], index: match.index ?? 0 });
  }
  return found;
}

export function scanActiveSource(root, policy = loadPolicy(), onlyRelativePaths) {
  const selected = onlyRelativePaths ? new Set(onlyRelativePaths.map(normalize)) : undefined;
  const files = walk(root, {
    includeFile: (absolute, relative) =>
      sourceExtensions.has(path.extname(absolute)) && (!selected || selected.has(normalize(relative))),
    excludedPrefixes: policy.scanExcludedPrefixes,
  });
  const findings = [];
  for (const { absolute: file, relative } of files) {
    if (prohibitedPath(relative, policy)) findings.push(`${relative}: prohibited source path`);
    const source = readFileSync(file, 'utf8');
    for (const { specifier, index } of extractActiveModuleSpecifiers(source)) {
      if (!prohibitedSpecifier(specifier, policy)) continue;
      const line = source.slice(0, index).split('\n').length;
      findings.push(`${relative}:${line}: ${specifier}`);
    }
  }
  return [...new Set(findings)].sort();
}

function archiveKind(file) {
  return archiveExtensions.find(extension => file.endsWith(extension));
}

function extractedArchive(file) {
  const temporary = mkdtempSync(path.join(tmpdir(), 'fork-release-archive-'));
  chmodSync(temporary, 0o700);
  try {
    const compressed = file.endsWith('.tgz') || file.endsWith('.tar.gz');
    const listArgs = [compressed ? '-tzf' : '-tf', file];
    const listing = execFileSync('tar', listArgs, { encoding: 'utf8', maxBuffer: 4 * 1024 * 1024 })
      .split('\n')
      .filter(Boolean);
    if (listing.length === 0) throw new GateError(`Archive is empty: ${file}`);
    for (const entry of listing) {
      if (path.posix.isAbsolute(entry) || entry.includes('\\') || path.posix.normalize(entry).startsWith('../')) {
        throw new GateError(`Unsafe archive entry in ${file}: ${entry}`);
      }
    }
    const verbose = execFileSync('tar', [compressed ? '-tzvf' : '-tvf', file], {
      encoding: 'utf8',
      maxBuffer: 8 * 1024 * 1024,
    });
    if (verbose.split('\n').some(line => /^[lh]/.test(line))) throw new GateError(`Archive contains links: ${file}`);
    execFileSync('tar', [compressed ? '-xzf' : '-xf', file, '-C', temporary], {
      stdio: ['ignore', 'ignore', 'pipe'],
      maxBuffer: 1024 * 1024,
    });
    return { temporary, cleanup: () => rmSync(temporary, { recursive: true, force: true }) };
  } catch (error) {
    rmSync(temporary, { recursive: true, force: true });
    if (error instanceof GateError) throw error;
    throw new GateError(`Cannot inspect archive ${file}: ${error.message}`);
  }
}

function bundleTokenFindings(file, logicalPath, policy) {
  const findings = [];
  const pathValue = normalize(logicalPath);
  if (prohibitedPath(pathValue, policy)) findings.push(`${logicalPath}: prohibited generated path`);
  if (pathValue.split('/').includes('ee')) findings.push(`${logicalPath}: prohibited generated EE path`);
  // Changelogs preserve historical release notes; they are not shipped runtime code or source maps.
  if (path.posix.basename(pathValue) === 'CHANGELOG.md') return findings;
  for (const token of policy.prohibitedBundleTokens) {
    if (pathValue.includes(token) || readFileSync(file).includes(Buffer.from(token)))
      findings.push(`${logicalPath}: ${token}`);
  }
  return findings;
}

function scanBundleFile(file, logicalPath, policy, findings) {
  findings.push(...bundleTokenFindings(file, logicalPath, policy));
  const kind = archiveKind(file);
  if (!kind) return;
  const { temporary, cleanup } = extractedArchive(file);
  try {
    for (const item of walk(temporary, { skipDirectories: new Set() })) {
      scanBundleFile(item.absolute, path.posix.join(logicalPath, item.relative), policy, findings);
    }
  } finally {
    cleanup();
  }
}

export function scanBundles(artifactPaths, policy = loadPolicy()) {
  if (!Array.isArray(artifactPaths) || artifactPaths.length === 0) {
    throw new GateError('At least one built artifact path is required');
  }
  const findings = [];
  for (const artifactPath of artifactPaths) {
    const absolute = path.resolve(artifactPath);
    if (!existsSync(absolute)) throw new GateError(`Built artifact does not exist: ${artifactPath}`);
    const metadata = lstatSync(absolute);
    if (metadata.isSymbolicLink()) throw new GateError(`Built artifact path may not be a symlink: ${artifactPath}`);
    const kind = metadata.isFile() && archiveKind(absolute);
    if (metadata.isFile() && /\.(?:zip|gz)$/i.test(absolute) && !kind) {
      throw new GateError(`Unsupported compressed artifact format: ${artifactPath}`);
    }
    if (metadata.isDirectory()) {
      for (const item of walk(absolute)) scanBundleFile(item.absolute, item.relative, policy, findings);
    } else {
      scanBundleFile(absolute, absolute, policy, findings);
    }
  }
  return [...new Set(findings)].sort();
}

function componentLicenses(component) {
  return (component.licenses ?? []).flatMap(item => {
    if (typeof item?.expression === 'string') return [item.expression];
    if (typeof item?.license?.id === 'string') return [item.license.id];
    if (typeof item?.license?.name === 'string') return [item.license.name];
    return [];
  });
}

function propertyValue(document, name) {
  return document.metadata?.properties?.find(property => property.name === name)?.value;
}

function cyclonedxRefs(document) {
  return [document.metadata.component, ...(document.components ?? [])].map(component => component['bom-ref']);
}

export function scanLicenseInventory(inventoryPath, policy = loadPolicy(), { artifactPath, sbomPath } = {}) {
  if (!artifactPath || !sbomPath) throw new GateError('License gate requires exact --artifact and --sbom paths');
  const inventory = readJson(inventoryPath);
  const sbom = readJson(sbomPath);
  const findings = [
    ...schemaFindings(inventory, 'cyclonedx-license.schema.json', 'license inventory'),
    ...schemaFindings(sbom, 'cyclonedx-sbom.schema.json', 'SBOM'),
  ];
  if (findings.length > 0) return findings.sort();
  const artifactDigest = sha256(artifactPath);
  const sbomDigest = sha256(sbomPath);
  if (propertyValue(inventory, 'expedient:artifact:sha256') !== artifactDigest) {
    findings.push('license inventory artifact digest does not match the built artifact');
  }
  if (propertyValue(inventory, 'expedient:sbom:sha256') !== sbomDigest) {
    findings.push('license inventory SBOM digest does not match the exact SBOM');
  }
  if (propertyValue(sbom, 'expedient:artifact:sha256') !== artifactDigest) {
    findings.push('SBOM artifact digest does not match the built artifact');
  }
  const inventoryRefs = cyclonedxRefs(inventory);
  const sbomRefs = cyclonedxRefs(sbom);
  if (new Set(inventoryRefs).size !== inventoryRefs.length)
    findings.push('license inventory contains duplicate bom-ref values');
  if (new Set(sbomRefs).size !== sbomRefs.length) findings.push('SBOM contains duplicate bom-ref values');
  if (JSON.stringify([...inventoryRefs].sort()) !== JSON.stringify([...sbomRefs].sort())) {
    findings.push('license inventory component set does not exactly match the SBOM component set');
  }
  const dependencyRefs = inventory.dependencies.map(dependency => dependency.ref);
  if (JSON.stringify([...dependencyRefs].sort()) !== JSON.stringify([...inventoryRefs].sort())) {
    findings.push('license inventory dependency graph is incomplete');
  }
  const knownRefs = new Set(inventoryRefs);
  for (const dependency of inventory.dependencies) {
    for (const reference of dependency.dependsOn) {
      if (!knownRefs.has(reference))
        findings.push(`${dependency.ref}: dependency references missing component ${reference}`);
    }
  }
  const rootHash = inventory.metadata.component.hashes.find(hash => hash.alg === 'SHA-256')?.content;
  if (rootHash !== artifactDigest)
    findings.push('license inventory root component is not bound to the artifact digest');
  for (const component of [inventory.metadata.component, ...inventory.components]) {
    const label = `${component.name}@${component.version}`;
    const licenses = componentLicenses(component);
    if (licenses.length === 0 || licenses.some(value => placeholderPattern.test(value) || !value.trim())) {
      findings.push(`${label}: missing or unresolved license conclusion`);
      continue;
    }
    for (const expression of licenses) {
      if (
        policy.deniedLicenseExpressions.some(denied =>
          new RegExp(`(?:^|[^a-z0-9])${escapeRegExp(denied)}(?:[^a-z0-9]|$)`, 'i').test(expression),
        )
      ) {
        findings.push(`${label}: prohibited license ${expression}`);
      }
    }
  }
  return [...new Set(findings)].sort();
}

export function parseCapture(capturePath) {
  if (!existsSync(capturePath)) throw new GateError(`Network capture was not produced: ${capturePath}`);
  const raw = readFileSync(capturePath, 'utf8');
  if (!raw.endsWith('\n')) throw new GateError('Network capture JSONL must end with a newline');
  const lines = raw.slice(0, -1).split('\n');
  if (lines.length < 2 || lines.some(line => line.trim() === ''))
    throw new GateError('Network capture JSONL is empty or incomplete');
  const records = lines.map((line, index) => {
    let value;
    try {
      value = JSON.parse(line);
    } catch (error) {
      throw new GateError(`Invalid network capture line ${index + 1}: ${error.message}`);
    }
    const schemaErrors = schemaFindings(value, 'network-capture.schema.json', `network capture line ${index + 1}`);
    if (schemaErrors.length > 0) throw new GateError(`Invalid network capture line ${index + 1}`, schemaErrors);
    return value;
  });
  if (records[0].type !== 'header' || records.at(-1).type !== 'completion') {
    throw new GateError('Network capture must begin with one header and end with one completion record');
  }
  if (records.slice(1, -1).some(record => record.type !== 'network')) {
    throw new GateError('Network records may only appear between the header and completion');
  }
  return { header: records[0], events: records.slice(1, -1), completion: records.at(-1) };
}

export function reviewNetworkCapture(capturePath, allowlistPath, { root = process.cwd(), artifactPath } = {}) {
  if (!artifactPath) throw new GateError('Network review requires the exact built artifact path');
  const capture = parseCapture(capturePath);
  const allowlist = readJson(allowlistPath);
  const findings = schemaFindings(allowlist, 'network-allowlist.schema.json', 'network allowlist');
  if (findings.length > 0) return findings.sort();
  const artifactDigest = sha256(artifactPath);
  if (capture.header.artifactSha256 !== artifactDigest || allowlist.artifactSha256 !== artifactDigest) {
    findings.push('network evidence is not bound to the exact built artifact digest');
  }
  if (capture.header.exerciseId !== allowlist.exerciseId || capture.completion.exerciseId !== allowlist.exerciseId) {
    findings.push('network capture and allowlist exercise identities do not match');
  }
  if (capture.completion.exitCode !== 0 || capture.completion.status !== 'completed') {
    findings.push('network exercise did not complete successfully');
  }
  const requiredClasses = [...allowlist.requiredRuntimeClasses].sort();
  if (JSON.stringify([...capture.header.requiredRuntimeClasses].sort()) !== JSON.stringify(requiredClasses)) {
    findings.push('network capture omitted required runtime classes');
  }
  for (const runtimeClass of requiredClasses) {
    if (!capture.completion.exercisedRuntimeClasses.includes(runtimeClass)) {
      findings.push(`network runtime class was not exercised: ${runtimeClass}`);
    }
  }
  if (capture.events.length === 0) {
    const zero = capture.header.zeroPolicy;
    if (!zero) findings.push('network capture contains no network records');
    else {
      try {
        const proof = canonicalRepositoryPath(root, zero.proofPath, 'network zero-policy proof');
        if (sha256(proof) !== zero.proofSha256) findings.push('network zero-policy proof digest does not match');
      } catch (error) {
        findings.push(error.message);
      }
    }
  }
  for (const event of capture.events) {
    const allowed = allowlist.destinations.some(
      rule =>
        rule.protocol === event.protocol &&
        rule.host.toLowerCase() === event.host.toLowerCase() &&
        rule.ports.includes(event.port),
    );
    if (!allowed) findings.push(`${event.protocol}://${event.host}:${event.port} (${event.source})`);
  }
  return [...new Set(findings)].sort();
}

function git(root, args) {
  try {
    return execFileSync('git', ['-C', root, ...args], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      maxBuffer: 16 * 1024 * 1024,
    }).trim();
  } catch (error) {
    throw new GateError(`git ${args.join(' ')} failed: ${error.stderr?.trim() || error.message}`);
  }
}

function exactCommit(root, value, label) {
  if (!commitPattern.test(value ?? '')) throw new GateError(`${label} must be an exact lowercase 40-hex commit`);
  if (git(root, ['cat-file', '-t', value]) !== 'commit')
    throw new GateError(`${label} is not a commit object: ${value}`);
  return value;
}

function discoveredCommercialPaths(root, audit) {
  const paths = new Set();
  const tree = git(root, ['ls-tree', '-r', '--name-only', audit.auditedBase]).split('\n').filter(Boolean);
  for (const candidate of tree) {
    if (audit.inventory.sourcePathPrefixes.some(prefix => candidate === prefix || candidate.startsWith(`${prefix}/`))) {
      paths.add(candidate);
    }
  }
  for (const specifier of audit.inventory.moduleSpecifiers) {
    const result = spawnSync('git', ['-C', root, 'grep', '-l', '-F', specifier, audit.auditedBase, '--'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      maxBuffer: 16 * 1024 * 1024,
    });
    if (![0, 1].includes(result.status)) throw new GateError(`Cannot enumerate commercial references for ${specifier}`);
    for (const line of (result.stdout ?? '').split('\n').filter(Boolean)) paths.add(line.slice(line.indexOf(':') + 1));
  }
  return [...paths].sort();
}

export function verifyAudit(root, auditPath = defaultAuditPath, { onlyId, executeCommands = true } = {}) {
  const audit = readJson(auditPath);
  const findings = schemaFindings(audit, 'commercial-connection-audit.schema.json', 'commercial audit');
  if (findings.length > 0) return findings.sort();
  try {
    exactCommit(root, audit.auditedBase, 'audit.auditedBase');
    exactCommit(root, audit.approvedMigrationTip, 'audit.approvedMigrationTip');
    git(root, ['merge-base', '--is-ancestor', audit.auditedBase, audit.approvedMigrationTip]);
    git(root, ['merge-base', '--is-ancestor', audit.approvedMigrationTip, 'HEAD']);
  } catch (error) {
    findings.push(`audit history is not anchored to HEAD: ${error.message}`);
  }
  const expectedIds = new Set(Array.from({ length: 17 }, (_, index) => `CP-${String(index + 1).padStart(2, '0')}`));
  const ids = new Set();
  const points = onlyId ? audit.connectionPoints.filter(point => point.id === onlyId) : audit.connectionPoints;
  if (onlyId && points.length !== 1) findings.push(`${onlyId}: missing audit record`);
  for (const point of points) {
    if (ids.has(point.id)) findings.push(`${point.id}: duplicate id`);
    ids.add(point.id);
    for (const source of point.historySources) {
      try {
        const objectId = git(root, ['rev-parse', `${source.commit}:${source.path}`]);
        if (objectId !== source.objectId)
          findings.push(`${point.id}: history object drift ${source.commit}:${source.path}`);
        const content = git(root, ['show', `${source.commit}:${source.path}`]);
        if (!content.includes(source.snippet) || sha256Text(source.snippet) !== source.snippetSha256) {
          findings.push(`${point.id}: history snippet fingerprint mismatch ${source.path}`);
        }
      } catch (error) {
        findings.push(`${point.id}: missing history object ${source.commit}:${source.path}: ${error.message}`);
      }
    }
    for (const replacement of point.replacementFingerprints) {
      try {
        const file = canonicalRepositoryPath(root, replacement.path, `${point.id} replacement`);
        if (sha256(file) !== replacement.sha256) findings.push(`${point.id}: replacement drift ${replacement.path}`);
      } catch (error) {
        findings.push(`${point.id}: ${error.message}`);
      }
    }
    const expectedCommand = [
      process.execPath,
      'scripts/fork-release/release-gate.mjs',
      'regression',
      '--id',
      point.id,
      '--root',
      '.',
    ];
    const normalizedCommand = [
      point.regressionCommand[0] === 'node' ? process.execPath : point.regressionCommand[0],
      ...point.regressionCommand.slice(1),
    ];
    if (JSON.stringify(normalizedCommand) !== JSON.stringify(expectedCommand)) {
      findings.push(`${point.id}: regression command is not the enforced audit command`);
    }
    if (point.evidenceStatus !== 'verified') findings.push(`${point.id}: evidence is not verified`);
  }
  if (!onlyId) {
    for (const expectedId of expectedIds)
      if (!ids.has(expectedId)) findings.push(`${expectedId}: missing audit record`);
    const inventoryLines = audit.inventory.paths.map(item => `${item.connectionPointId}\t${item.path}`).sort();
    if (sha256Text(`${inventoryLines.join('\n')}\n`) !== audit.inventory.sha256) {
      findings.push('commercial inventory path digest does not match');
    }
    const discovered = discoveredCommercialPaths(root, audit);
    if (discovered.length !== audit.inventory.discoveredPathCount) {
      findings.push(
        `commercial inventory discovery count drift: expected ${audit.inventory.discoveredPathCount}, got ${discovered.length}`,
      );
    }
    if (sha256Text(`${discovered.join('\n')}\n`) !== audit.inventory.discoveredPathsSha256) {
      findings.push('commercial inventory discovered-path digest drift');
    }
    for (const item of audit.inventory.paths) {
      if (!expectedIds.has(item.connectionPointId)) findings.push(`inventory path has unknown owner: ${item.path}`);
      try {
        git(root, ['cat-file', '-e', `${audit.auditedBase}:${item.path}`]);
      } catch {
        findings.push(`inventory history path is missing: ${item.path}`);
      }
    }
    if (executeCommands && findings.length === 0) {
      for (const point of audit.connectionPoints) {
        const result = spawnSync(process.execPath, point.regressionCommand.slice(1), {
          cwd: root,
          env: { PATH: process.env.PATH ?? '/usr/bin:/bin', HOME: process.env.HOME ?? root, LANG: 'C' },
          encoding: 'utf8',
          timeout: 30_000,
          maxBuffer: 64 * 1024,
        });
        if (result.status !== 0) findings.push(`${point.id}: executable regression failed`);
      }
    }
  }
  return [...new Set(findings)].sort();
}

export function verifyUpstreamSync(root, base, policy = loadPolicy()) {
  exactCommit(root, base, 'upstream-sync base');
  git(root, ['merge-base', '--is-ancestor', base, 'HEAD']);
  const changed = git(root, ['diff', '--name-only', '--diff-filter=ACMR', `${base}..HEAD`])
    .split('\n')
    .filter(Boolean);
  const findings = [];
  for (const relative of changed) {
    const normalized = normalize(relative);
    if (prohibitedPath(normalized, policy)) findings.push(`${normalized}: prohibited path reintroduced since ${base}`);
  }
  findings.push(...scanDependencyGraph(root, policy), ...scanActiveSource(root, policy));
  return [...new Set(findings)].sort();
}

export function sha256(file) {
  return createHash('sha256').update(readFileSync(file)).digest('hex');
}

function sha256Bytes(value) {
  return createHash('sha256').update(value).digest('hex');
}

function artifactArchiveEntries(artifactPath) {
  const compressed = artifactPath.endsWith('.tgz') || artifactPath.endsWith('.tar.gz');
  try {
    return {
      compressed,
      entries: execFileSync('tar', [compressed ? '-tzf' : '-tf', artifactPath], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
        maxBuffer: 16 * 1024 * 1024,
      })
        .split('\n')
        .filter(Boolean),
    };
  } catch (error) {
    throw new GateError(`Cannot list release artifact ${artifactPath}: ${error.message}`);
  }
}

function artifactIndexLocation(artifactPath) {
  const { entries, compressed } = artifactArchiveEntries(artifactPath);
  for (const entry of entries) {
    if (path.posix.isAbsolute(entry) || entry.includes('\\') || path.posix.normalize(entry).startsWith('../')) {
      throw new GateError(`Unsafe release artifact entry: ${entry}`);
    }
  }
  const indexes = entries.filter(entry => entry === 'artifact-index.json' || entry.endsWith('/artifact-index.json'));
  if (indexes.length !== 1)
    throw new GateError(`Release artifact must contain exactly one artifact-index.json: ${artifactPath}`);
  return { entries, compressed, indexPath: indexes[0] };
}

function verifyArtifactPackages(artifactPath, index, archive) {
  const prefix = archive.indexPath.endsWith('artifact-index.json')
    ? archive.indexPath.slice(0, -'artifact-index.json'.length)
    : '';
  const expectedEntries = new Set(index.packages.map(item => `${prefix}tarballs/${item.file}`));
  const actualEntries = new Set(
    archive.entries.filter(entry => entry.startsWith(`${prefix}tarballs/`) && entry.endsWith('.tgz')),
  );
  const findings = [];
  if (actualEntries.size !== expectedEntries.size || [...expectedEntries].some(entry => !actualEntries.has(entry))) {
    findings.push('artifact package tarball set does not match artifact-index.json');
  }
  for (const item of index.packages) {
    const entry = `${prefix}tarballs/${item.file}`;
    if (!actualEntries.has(entry)) continue;
    try {
      const packed = execFileSync('tar', [archive.compressed ? '-xOzf' : '-xOf', artifactPath, entry], {
        stdio: ['ignore', 'pipe', 'pipe'],
        maxBuffer: 256 * 1024 * 1024,
      });
      if (sha256Bytes(packed) !== item.sha256) findings.push(`${item.name}: tarball digest mismatch`);
      const manifest = JSON.parse(
        execFileSync('tar', ['-xOzf', '-', 'package/package.json'], {
          input: packed,
          encoding: 'utf8',
          maxBuffer: 4 * 1024 * 1024,
        }),
      );
      if (manifest.name !== item.name || manifest.version !== item.version) {
        findings.push(`${item.name}: packed package identity does not match artifact-index.json`);
      }
    } catch (error) {
      findings.push(`${item.name}: cannot inspect packed tarball (${error.message})`);
    }
  }
  return findings;
}

export function readArtifactIndex(artifactPath) {
  const archive = artifactIndexLocation(artifactPath);
  let index;
  try {
    const raw = execFileSync('tar', [archive.compressed ? '-xOzf' : '-xOf', artifactPath, archive.indexPath], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      maxBuffer: 4 * 1024 * 1024,
    });
    index = JSON.parse(raw);
  } catch (error) {
    throw new GateError(`Cannot read ${archive.indexPath} from ${artifactPath}: ${error.message}`);
  }
  const findings = schemaFindings(index, 'artifact-index.schema.json', 'artifact index');
  const names = index.packages?.map(item => item.name) ?? [];
  const files = index.packages?.map(item => item.file) ?? [];
  if (new Set(names).size !== names.length) findings.push('artifact index contains duplicate package names');
  if (new Set(files).size !== files.length) findings.push('artifact index contains duplicate tarball names');
  if (findings.length > 0) throw new GateError('Artifact index is invalid', findings);
  findings.push(...verifyArtifactPackages(artifactPath, index, archive));
  if (findings.length > 0) throw new GateError('Artifact index is invalid', findings);
  return index;
}

export function verifyArtifactIdentity(artifactPath, name, version, { reviewedBaselineCommit, releaseCommit } = {}) {
  try {
    const index = readArtifactIndex(artifactPath);
    const findings = [];
    if (index.artifact.name !== name || index.artifact.version !== version) {
      findings.push('artifact name/version does not match the packed artifact index');
    }
    if (reviewedBaselineCommit && index.reviewedBaselineCommit !== reviewedBaselineCommit) {
      findings.push('artifact index is not bound to the reviewed baseline commit');
    }
    if (releaseCommit && index.releaseCommit !== releaseCommit) {
      findings.push('artifact index is not bound to the clean release commit');
    }
    return findings;
  } catch (error) {
    return [error.message, ...(error.findings ?? [])];
  }
}

export function sha256Text(value) {
  return createHash('sha256').update(value).digest('hex');
}

function unresolved(value) {
  return typeof value !== 'string' || value.trim() === '' || placeholderPattern.test(value);
}

function evidenceFile(root, section, evidence, findings) {
  try {
    const file = canonicalRepositoryPath(root, evidence.path, `${section}.path`);
    if (!digestPattern.test(evidence.sha256)) findings.push(`${section}.sha256 is not an exact digest`);
    else if (sha256(file) !== evidence.sha256) findings.push(`${section}.sha256 does not match ${evidence.path}`);
    return file;
  } catch (error) {
    findings.push(error.message);
    return undefined;
  }
}

function factValues(manifest, policy) {
  const facts = manifest.requiredFacts;
  const packageFact = facts.commercialPackageNames;
  const licenseFact = facts.prohibitedLicenseExpressions;
  return {
    ...policy,
    prohibitedPackageNames: [
      ...policy.prohibitedPackageNames,
      ...(packageFact.decision === 'enumerated'
        ? packageFact.values.filter(item => item.disposition === 'prohibited').map(item => item.name)
        : []),
    ],
    deniedLicenseExpressions: [
      ...policy.deniedLicenseExpressions,
      ...(licenseFact.decision === 'enumerated' ? licenseFact.values.map(item => item.expression) : []),
    ],
  };
}

export function verifyCompatibilityEvidence(
  root,
  evidencePath,
  { artifactPath, manifestPath = defaultCompatibilityPath, reviewedBaselineCommit, releaseCommit } = {},
) {
  if (!artifactPath) throw new GateError('Compatibility evidence requires the exact built artifact');
  const manifest = readJson(manifestPath);
  const evidence = readJson(evidencePath);
  const findings = [
    ...schemaFindings(manifest, 'native-compatibility.schema.json', 'native compatibility manifest'),
    ...schemaFindings(evidence, 'native-compatibility-evidence.schema.json', 'native compatibility evidence'),
  ];
  if (findings.length > 0) return findings.sort();
  const areaNames = manifest.areas.map(area => area.id).sort();
  if (JSON.stringify(areaNames) !== JSON.stringify([...requiredCompatibilityAreas].sort())) {
    findings.push('native compatibility manifest does not cover the exact required release matrix');
  }
  if (
    evidence.reviewedBaselineCommit !== reviewedBaselineCommit ||
    evidence.releaseCommit !== releaseCommit ||
    evidence.artifactSha256 !== sha256(artifactPath)
  ) {
    findings.push('native compatibility evidence is not bound to the reviewed baseline, release commit, and artifact');
  }
  if (evidence.manifestSha256 !== sha256(manifestPath)) findings.push('native compatibility manifest digest mismatch');
  const resultById = new Map(evidence.results.map(result => [result.id, result]));
  for (const area of manifest.areas) {
    const result = resultById.get(area.id);
    if (!result || result.status !== 'passed' || result.exitCode !== 0) {
      findings.push(`native compatibility area did not pass: ${area.id}`);
      continue;
    }
    if (result.commandSha256 !== sha256Text(JSON.stringify(area.argv))) {
      findings.push(`native compatibility command drift: ${area.id}`);
    }
    for (const fixturePath of area.fixturePaths) {
      try {
        canonicalRepositoryPath(root, fixturePath, `${area.id} fixture`);
      } catch (error) {
        findings.push(error.message);
      }
    }
  }
  if (resultById.size !== manifest.areas.length)
    findings.push('native compatibility evidence has missing or extra results');
  return [...new Set(findings)].sort();
}

export function verifyEvidence(root, manifestPath, { allowSynthetic = false, policy = loadPolicy() } = {}) {
  const manifest = readJson(manifestPath);
  const findings = schemaFindings(manifest, 'release-evidence.schema.json', 'release evidence');
  if (findings.length > 0) return findings.sort();
  if (manifest.evidenceClass === 'synthetic-fixture' && !allowSynthetic) {
    return ['synthetic fixture evidence cannot authorize a production release'];
  }
  if (manifest.evidenceClass === 'release' && allowSynthetic) {
    findings.push('production evidence may not be validated through the synthetic-fixture path');
  }
  try {
    exactCommit(root, manifest.reviewedBaselineCommit, 'reviewedBaselineCommit');
    exactCommit(root, manifest.releaseCommit, 'releaseCommit');
    exactCommit(root, manifest.upstreamCommit, 'upstreamCommit');
    exactCommit(root, manifest.rollback.commit, 'rollback.commit');
    if (git(root, ['rev-parse', 'HEAD']) !== manifest.releaseCommit)
      findings.push('releaseCommit is not the checked-out HEAD');
    const ancestry = spawnSync('git', [
      '-C',
      root,
      'merge-base',
      '--is-ancestor',
      manifest.reviewedBaselineCommit,
      manifest.releaseCommit,
    ]);
    if (ancestry.status !== 0) findings.push('reviewedBaselineCommit is not an ancestor of releaseCommit');
    const status = git(root, ['status', '--porcelain=v1', '--untracked-files=all']);
    if (status) findings.push('release evidence requires a clean checked-out HEAD');
  } catch (error) {
    findings.push(error.message);
  }
  const files = {};
  for (const section of ['artifact', 'sbom', 'provenance', 'licenseEvidence', 'compatibilityEvidence', 'rollback']) {
    files[section] = evidenceFile(root, section, manifest[section], findings);
  }
  files.capture = evidenceFile(root, 'networkEvidence.capture', manifest.networkEvidence.capture, findings);
  files.allowlist = evidenceFile(root, 'networkEvidence.allowlist', manifest.networkEvidence.allowlist, findings);
  files.reviewedAllowlistSource = evidenceFile(
    root,
    'networkEvidence.reviewedAllowlistSource',
    manifest.networkEvidence.reviewedAllowlistSource,
    findings,
  );
  files.signing = evidenceFile(root, 'signing.evidence', manifest.signing.evidence, findings);
  for (const name of ['commercialPackageNames', 'commercialNetworkDestinations', 'prohibitedLicenseExpressions']) {
    files[`factReview.${name}`] = evidenceFile(
      root,
      `requiredFacts.${name}.review`,
      manifest.requiredFacts[name].review,
      findings,
    );
  }
  files.publicationReview = evidenceFile(
    root,
    'publicationAuthorization.review',
    manifest.publicationAuthorization.review,
    findings,
  );
  if (findings.length > 0) return [...new Set(findings)].sort();
  const artifactDigest = manifest.artifact.sha256;
  for (const [section, value] of [
    ['sbom', manifest.sbom.artifactSha256],
    ['provenance', manifest.provenance.artifactSha256],
    ['licenseEvidence', manifest.licenseEvidence.artifactSha256],
    ['networkEvidence', manifest.networkEvidence.artifactSha256],
    ['compatibilityEvidence', manifest.compatibilityEvidence.artifactSha256],
    ['rollback', manifest.rollback.artifactSha256],
    ['signing', manifest.signing.artifactSha256],
    ['publicationAuthorization', manifest.publicationAuthorization.artifactSha256],
  ]) {
    if (value !== artifactDigest) findings.push(`${section} is not bound to the exact artifact digest`);
  }
  if (manifest.licenseEvidence.sbomSha256 !== manifest.sbom.sha256) {
    findings.push('licenseEvidence is not bound to the exact SBOM digest');
  }
  if (
    manifest.networkEvidence.review.captureSha256 !== manifest.networkEvidence.capture.sha256 ||
    manifest.networkEvidence.review.allowlistSha256 !== manifest.networkEvidence.allowlist.sha256
  ) {
    findings.push('explicit network review is not digest-bound to the fresh capture and bound allowlist');
  }
  if (
    manifest.reviewedBaselineCommit !== manifest.provenance.reviewedBaselineCommit ||
    manifest.releaseCommit !== manifest.provenance.releaseCommit
  ) {
    findings.push('provenance is not bound to the reviewed baseline and release commits');
  }
  if (manifest.artifact.version !== manifest.provenance.version)
    findings.push('artifact version and provenance version differ');
  findings.push(
    ...verifyArtifactIdentity(files.artifact, manifest.artifact.name, manifest.artifact.version, {
      reviewedBaselineCommit: manifest.reviewedBaselineCommit,
      releaseCommit: manifest.releaseCommit,
    }),
  );
  const effectivePolicy = factValues(manifest, policy);
  const reviewedAllowlist = readJson(files.allowlist);
  for (const destination of manifest.requiredFacts.commercialNetworkDestinations.values) {
    const present = reviewedAllowlist.destinations.some(
      rule =>
        rule.protocol === destination.protocol &&
        rule.host.toLowerCase() === destination.host.toLowerCase() &&
        destination.ports.every(port => rule.ports.includes(port)),
    );
    if (destination.disposition === 'prohibited' && present) {
      findings.push(`prohibited commercial network destination is allowlisted: ${destination.host}`);
    }
    if (destination.disposition === 'allowed' && !present) {
      findings.push(`reviewed commercial network destination is missing from allowlist: ${destination.host}`);
    }
  }
  findings.push(...scanBundles([files.artifact], effectivePolicy));
  findings.push(
    ...scanLicenseInventory(files.licenseEvidence, effectivePolicy, {
      artifactPath: files.artifact,
      sbomPath: files.sbom,
    }),
  );
  findings.push(
    ...reviewNetworkCapture(files.capture, files.allowlist, {
      root,
      artifactPath: files.artifact,
    }),
  );
  findings.push(
    ...verifyCompatibilityEvidence(root, files.compatibilityEvidence, {
      artifactPath: files.artifact,
      reviewedBaselineCommit: manifest.reviewedBaselineCommit,
      releaseCommit: manifest.releaseCommit,
    }),
  );
  const provenance = readJson(files.provenance);
  if (
    provenance.reviewedBaselineCommit !== manifest.reviewedBaselineCommit ||
    provenance.releaseCommit !== manifest.releaseCommit ||
    provenance.artifactSha256 !== artifactDigest ||
    provenance.version !== manifest.artifact.version
  ) {
    findings.push(
      'provenance document is not internally bound to the reviewed baseline, release commit, artifact, and version',
    );
  }
  const subject = provenance.subject?.find(item => item.name === manifest.artifact.name);
  if (subject?.digest?.sha256 !== artifactDigest)
    findings.push('provenance subject does not match artifact name and digest');
  const rollback = readJson(files.rollback);
  if (
    rollback.releaseCommit !== manifest.releaseCommit ||
    rollback.rollbackCommit !== manifest.rollback.commit ||
    rollback.artifactSha256 !== artifactDigest ||
    rollback.status !== 'passed'
  ) {
    findings.push('rollback evidence did not pass for the clean release commit and artifact');
  }
  if (unresolved(manifest.signing.reference) || unresolved(manifest.publicationAuthorization.reference)) {
    findings.push('signing and publication authorization references must be resolved');
  }
  return [...new Set(findings)].sort();
}

export function verifyTemplateIntegrity() {
  const expected = readFileSync(templateDigestPath, 'utf8').trim().split(/\s+/)[0];
  const actual = sha256(templatePath);
  return expected === actual ? [] : [`release evidence template digest mismatch: expected ${expected}, got ${actual}`];
}

export function runCompatibilityMatrix(
  root,
  artifactPath,
  outputPath,
  { manifestPath = defaultCompatibilityPath, timeoutMs = 20 * 60_000 } = {},
) {
  const manifest = readJson(manifestPath);
  requireSchema(manifest, 'native-compatibility.schema.json', 'native compatibility manifest');
  const releaseCommit = exactCommit(root, git(root, ['rev-parse', 'HEAD']), 'HEAD');
  const artifactIndex = readArtifactIndex(artifactPath);
  if (artifactIndex.releaseCommit !== releaseCommit)
    throw new GateError('Compatibility checkout does not match artifact release commit');
  const reviewedBaselineCommit = artifactIndex.reviewedBaselineCommit;
  const results = [];
  for (const area of manifest.areas) {
    const [command, ...args] = area.argv;
    const result = spawnSync(command, args, {
      cwd: root,
      env: {
        PATH: process.env.PATH ?? '/usr/bin:/bin',
        HOME: process.env.HOME ?? root,
        CI: 'true',
        LANG: 'C',
        NODE_ENV: 'test',
        FORK_RELEASE_ARTIFACT: path.resolve(artifactPath),
        RELEASE_COMMIT: releaseCommit,
        REVIEWED_BASELINE_COMMIT: reviewedBaselineCommit,
      },
      encoding: 'utf8',
      timeout: Math.min(area.timeoutMs, timeoutMs),
      maxBuffer: 256 * 1024,
    });
    const bounded = `${result.stdout ?? ''}\n${result.stderr ?? ''}`.slice(0, 256 * 1024);
    results.push({
      id: area.id,
      status: result.status === 0 && !result.error ? 'passed' : 'failed',
      exitCode: result.status ?? -1,
      commandSha256: sha256Text(JSON.stringify(area.argv)),
      outputSha256: sha256Text(bounded),
    });
    if (result.error || result.status !== 0) {
      throw new GateError(`Native compatibility command failed: ${area.id}`, [redactOutput(bounded)]);
    }
  }
  const evidence = {
    schemaVersion: 2,
    evidenceClass: 'release',
    reviewedBaselineCommit,
    releaseCommit,
    artifactSha256: sha256(artifactPath),
    manifestSha256: sha256(manifestPath),
    installationMode: 'clean-room-installed-tarballs',
    results,
  };
  writeFileSync(outputPath, `${JSON.stringify(evidence, null, 2)}\n`, { mode: 0o600 });
  return [];
}

export function redactOutput(value, secretValues = []) {
  let output = String(value).slice(0, 64 * 1024);
  for (const secret of secretValues.filter(secret => typeof secret === 'string' && secret.length >= 4)) {
    output = output.split(secret).join('[REDACTED]');
  }
  output = output.replace(
    /\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|(?:sk|pk)-[A-Za-z0-9_-]{16,}|Bearer\s+\S+)\b/gi,
    '[REDACTED]',
  );
  return output;
}

export function assertGate(name, findings) {
  if (findings.length > 0) throw new GateError(`${name} failed`, findings);
  return `${name} passed`;
}
