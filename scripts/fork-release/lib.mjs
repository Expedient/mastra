import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const toolingRoot = path.dirname(fileURLToPath(import.meta.url));
export const defaultPolicyPath = path.join(toolingRoot, 'policy.json');
export const defaultAuditPath = path.join(toolingRoot, 'commercial-connection-audit.json');
export const templatePath = path.join(toolingRoot, 'release-evidence.template.json');
export const templateDigestPath = `${templatePath}.sha256`;

const dependencyFields = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'];
const sourceExtensions = new Set(['.cjs', '.cts', '.js', '.jsx', '.mjs', '.mts', '.ts', '.tsx']);
const skippedDirectories = new Set(['.git', '.next', '.turbo', 'coverage', 'dist', 'node_modules']);

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

export function loadPolicy(file = defaultPolicyPath) {
  const policy = readJson(file);
  const requiredArrays = [
    'prohibitedModuleSpecifiers',
    'prohibitedPackageNames',
    'prohibitedSourcePathSegments',
    'prohibitedBundleTokens',
    'deniedLicenseExpressions',
    'scanExcludedPrefixes',
  ];
  if (policy.schemaVersion !== 1 || requiredArrays.some(key => !Array.isArray(policy[key]))) {
    throw new GateError(`Policy ${file} does not satisfy fork release policy schema version 1`);
  }
  return policy;
}

function normalize(relativePath) {
  return relativePath.split(path.sep).join('/');
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function walk(directory, { includeFile = () => true, excludedPrefixes = [] } = {}, root = directory) {
  if (!existsSync(directory)) throw new GateError(`Path does not exist: ${directory}`);
  const result = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const absolute = path.join(directory, entry.name);
    const relative = normalize(path.relative(root, absolute));
    if (excludedPrefixes.some(prefix => relative === prefix || relative.startsWith(`${prefix}/`))) continue;
    if (entry.isDirectory()) {
      if (!skippedDirectories.has(entry.name)) result.push(...walk(absolute, { includeFile, excludedPrefixes }, root));
    } else if (entry.isFile() && includeFile(absolute, relative)) {
      result.push(absolute);
    }
  }
  return result.sort();
}

export function scanDependencyGraph(root, policy = loadPolicy()) {
  const findings = [];
  const manifests = walk(root, {
    includeFile: (_absolute, relative) => path.basename(relative) === 'package.json',
    excludedPrefixes: policy.scanExcludedPrefixes,
  });
  for (const manifestPath of manifests) {
    const manifest = readJson(manifestPath);
    const relative = normalize(path.relative(root, manifestPath));
    for (const field of dependencyFields) {
      for (const dependency of Object.keys(manifest[field] ?? {})) {
        if (policy.prohibitedPackageNames.includes(dependency)) {
          findings.push(`${relative}: ${field}.${dependency}`);
        }
      }
    }
    if (typeof manifest.name === 'string') {
      for (const exportKey of Object.keys(manifest.exports ?? {})) {
        const specifier = exportKey === '.' ? manifest.name : `${manifest.name}/${exportKey.replace(/^\.\//, '')}`;
        if (policy.prohibitedModuleSpecifiers.includes(specifier)) findings.push(`${relative}: exports.${exportKey}`);
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
  for (const file of files) {
    const relative = normalize(path.relative(root, file));
    if (policy.prohibitedSourcePathSegments.some(segment => `/${relative}/`.includes(`/${segment}/`))) {
      findings.push(`${relative}: prohibited source path`);
    }
    const source = readFileSync(file, 'utf8');
    for (const { specifier, index } of extractActiveModuleSpecifiers(source)) {
      if (!policy.prohibitedModuleSpecifiers.includes(specifier)) continue;
      const line = source.slice(0, index).split('\n').length;
      findings.push(`${relative}:${line}: ${specifier}`);
    }
  }
  return [...new Set(findings)].sort();
}

export function scanBundles(artifactPaths, policy = loadPolicy()) {
  if (artifactPaths.length === 0) throw new GateError('At least one built artifact path is required');
  const findings = [];
  for (const artifactPath of artifactPaths) {
    const absolute = path.resolve(artifactPath);
    const files = statSync(absolute).isDirectory() ? walk(absolute) : [absolute];
    for (const file of files) {
      const content = readFileSync(file);
      for (const token of policy.prohibitedBundleTokens) {
        if (content.includes(Buffer.from(token))) findings.push(`${file}: ${token}`);
      }
    }
  }
  return findings.sort();
}

function componentLicenses(component) {
  return (component.licenses ?? []).flatMap(item => {
    if (typeof item === 'string') return [item];
    if (typeof item?.expression === 'string') return [item.expression];
    if (typeof item?.license?.id === 'string') return [item.license.id];
    if (typeof item?.license?.name === 'string') return [item.license.name];
    return [];
  });
}

export function scanLicenseInventory(inventoryPath, policy = loadPolicy()) {
  const inventory = readJson(inventoryPath);
  if (!Array.isArray(inventory.components) || inventory.components.length === 0) {
    throw new GateError('License inventory must contain at least one component');
  }
  const findings = [];
  for (const component of inventory.components) {
    const label = `${component.name ?? '<unnamed>'}@${component.version ?? '<unversioned>'}`;
    const licenses = componentLicenses(component);
    if (licenses.length === 0 || licenses.some(value => /^(NOASSERTION|UNKNOWN|UNLICENSED)$/i.test(value))) {
      findings.push(`${label}: missing or unresolved license conclusion`);
      continue;
    }
    for (const expression of licenses) {
      if (policy.deniedLicenseExpressions.some(denied => expression.toLowerCase().includes(denied.toLowerCase()))) {
        findings.push(`${label}: prohibited license ${expression}`);
      }
    }
  }
  return findings.sort();
}

export function parseCapture(capturePath) {
  if (!existsSync(capturePath)) throw new GateError(`Network capture was not produced: ${capturePath}`);
  return readFileSync(capturePath, 'utf8')
    .split('\n')
    .filter(Boolean)
    .map((line, index) => {
      try {
        return JSON.parse(line);
      } catch (error) {
        throw new GateError(`Invalid network capture line ${index + 1}: ${error.message}`);
      }
    });
}

export function reviewNetworkCapture(capturePath, allowlistPath) {
  const events = parseCapture(capturePath);
  const allowlist = readJson(allowlistPath);
  if (!Array.isArray(allowlist.destinations))
    throw new GateError('Network allowlist must contain a destinations array');
  const findings = [];
  for (const event of events) {
    const allowed = allowlist.destinations.some(rule => {
      const protocolMatches = rule.protocol === event.protocol;
      const hostMatches = String(rule.host).toLowerCase() === String(event.host).toLowerCase();
      const portMatches = !Array.isArray(rule.ports) || rule.ports.includes(event.port);
      return protocolMatches && hostMatches && portMatches;
    });
    if (!allowed) findings.push(`${event.protocol}://${event.host}:${event.port} (${event.source})`);
  }
  return [...new Set(findings)].sort();
}

export function captureNetwork({ command, args, capturePath, allowlistPath, cwd = process.cwd() }) {
  if (!command) throw new GateError('Network capture requires a command after --');
  writeFileSync(capturePath, '');
  const register = path.join(toolingRoot, 'network-capture-register.mjs');
  const nodeOptions = [process.env.NODE_OPTIONS, `--import=${pathToFileURL(register).href}`].filter(Boolean).join(' ');
  const result = spawnSync(command, args, {
    cwd,
    env: { ...process.env, FORK_RELEASE_NETWORK_CAPTURE: path.resolve(capturePath), NODE_OPTIONS: nodeOptions },
    encoding: 'utf8',
  });
  if (result.stdout) process.stdout.write(result.stdout);
  if (result.stderr) process.stderr.write(result.stderr);
  if (result.error) throw new GateError(`Network exercise could not start: ${result.error.message}`);
  if (result.status !== 0) throw new GateError(`Network exercise exited with status ${result.status}`);
  return reviewNetworkCapture(capturePath, allowlistPath);
}

function git(root, args) {
  try {
    return execFileSync('git', ['-C', root, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
  } catch (error) {
    throw new GateError(`git ${args.join(' ')} failed: ${error.stderr?.trim() || error.message}`);
  }
}

export function verifyAudit(root, auditPath = defaultAuditPath) {
  const audit = readJson(auditPath);
  const findings = [];
  if (audit.schemaVersion !== 1) findings.push('audit schemaVersion must be 1');
  if (!Array.isArray(audit.connectionPoints) || audit.connectionPoints.length !== 17) {
    findings.push(`audit must contain exactly 17 connection points (found ${audit.connectionPoints?.length ?? 0})`);
    return findings;
  }
  try {
    git(root, ['merge-base', '--is-ancestor', audit.auditedBase, audit.approvedMigrationTip]);
    git(root, ['merge-base', '--is-ancestor', audit.approvedMigrationTip, 'HEAD']);
  } catch (error) {
    findings.push(`audit history is not anchored to HEAD: ${error.message}`);
  }
  const expectedIds = new Set(Array.from({ length: 17 }, (_, index) => `CP-${String(index + 1).padStart(2, '0')}`));
  const ids = new Set();
  for (const point of audit.connectionPoints) {
    if (!point.id || ids.has(point.id)) findings.push(`${point.id ?? '<missing>'}: duplicate or missing id`);
    ids.add(point.id);
    if (!['remove', 'replace'].includes(point.disposition)) findings.push(`${point.id}: invalid disposition`);
    if (point.evidenceStatus !== 'verified') findings.push(`${point.id}: evidence is not verified`);
    if (!point.connectionType || !point.replacementRegressionCheck) findings.push(`${point.id}: incomplete record`);
    if (!Array.isArray(point.historySources) || point.historySources.length === 0) {
      findings.push(`${point.id}: no history source`);
    } else {
      for (const source of point.historySources) {
        try {
          git(root, ['cat-file', '-e', `${source.commit}:${source.path}`]);
        } catch {
          findings.push(`${point.id}: missing history object ${source.commit}:${source.path}`);
        }
      }
    }
    if (
      !Array.isArray(point.replacementPaths) ||
      point.replacementPaths.some(file => !existsSync(path.join(root, file)))
    ) {
      findings.push(`${point.id}: replacement path missing`);
    }
  }
  for (const expectedId of expectedIds) {
    if (!ids.has(expectedId)) findings.push(`${expectedId}: missing audit record`);
  }
  return findings;
}

export function verifyUpstreamSync(root, base, policy = loadPolicy()) {
  if (!base) throw new GateError('Upstream-sync gate requires --base <commit>');
  git(root, ['merge-base', '--is-ancestor', base, 'HEAD']);
  const changed = git(root, ['diff', '--name-only', '--diff-filter=ACMR', `${base}..HEAD`])
    .split('\n')
    .filter(Boolean);
  const findings = [];
  for (const relative of changed) {
    const normalized = normalize(relative);
    if (policy.prohibitedSourcePathSegments.some(segment => `/${normalized}/`.includes(`/${segment}/`))) {
      findings.push(`${normalized}: prohibited path reintroduced since ${base}`);
    }
  }
  findings.push(...scanDependencyGraph(root, policy));
  findings.push(...scanActiveSource(root, policy));
  return [...new Set(findings)].sort();
}

export function sha256(file) {
  return createHash('sha256').update(readFileSync(file)).digest('hex');
}

function unresolved(value) {
  return typeof value !== 'string' || value.trim() === '' || /^(UNRESOLVED|TBD|PLACEHOLDER)/i.test(value);
}

export function verifyEvidence(root, manifestPath) {
  const manifest = readJson(manifestPath);
  const findings = [];
  if (manifest.schemaVersion !== 1) findings.push('schemaVersion must be 1');
  const requiredFactNames = ['commercialPackageNames', 'commercialNetworkDestinations', 'prohibitedLicenseExpressions'];
  for (const name of requiredFactNames) {
    const fact = manifest.requiredFacts?.[name];
    if (fact?.status !== 'resolved' || !Array.isArray(fact.value) || unresolved(fact.basis)) {
      findings.push(`requiredFacts.${name} is unresolved`);
    }
  }
  for (const field of ['upstreamCommit', 'rollbackReference']) {
    if (unresolved(manifest[field])) findings.push(`${field} is unresolved`);
  }
  for (const field of ['name', 'version', 'path', 'sha256']) {
    if (unresolved(manifest.artifact?.[field])) findings.push(`artifact.${field} is unresolved`);
  }
  for (const section of ['sbom', 'provenance', 'licenseEvidence']) {
    for (const field of ['path', 'sha256']) {
      if (unresolved(manifest[section]?.[field])) findings.push(`${section}.${field} is unresolved`);
    }
  }
  for (const section of ['capture', 'allowlist']) {
    for (const field of ['path', 'sha256']) {
      if (unresolved(manifest.networkEvidence?.[section]?.[field])) {
        findings.push(`networkEvidence.${section}.${field} is unresolved`);
      }
    }
  }
  for (const section of ['signing', 'publication']) {
    if (!['completed', 'not-applicable'].includes(manifest[section]?.status))
      findings.push(`${section}.status is unresolved`);
    if (manifest[section]?.status === 'not-applicable' && unresolved(manifest[section]?.rationale)) {
      findings.push(`${section}.rationale is required when not applicable`);
    }
    if (manifest[section]?.status === 'completed' && unresolved(manifest[section]?.reference)) {
      findings.push(`${section}.reference is required when completed`);
    }
  }
  if (findings.length > 0) return findings;

  try {
    git(root, ['cat-file', '-e', `${manifest.upstreamCommit}^{commit}`]);
    git(root, ['rev-parse', '--verify', manifest.rollbackReference]);
  } catch (error) {
    findings.push(error.message);
  }
  const evidenceFiles = [
    ['artifact', manifest.artifact],
    ['sbom', manifest.sbom],
    ['provenance', manifest.provenance],
    ['licenseEvidence', manifest.licenseEvidence],
    ['networkEvidence.capture', manifest.networkEvidence.capture],
    ['networkEvidence.allowlist', manifest.networkEvidence.allowlist],
  ];
  for (const [section, evidence] of evidenceFiles) {
    const file = path.resolve(root, evidence.path);
    if (!existsSync(file)) findings.push(`${section}.path does not exist: ${evidence.path}`);
    else if (sha256(file) !== evidence.sha256.toLowerCase())
      findings.push(`${section}.sha256 does not match ${evidence.path}`);
  }
  return findings;
}

export function verifyTemplateIntegrity() {
  const expected = readFileSync(templateDigestPath, 'utf8').trim().split(/\s+/)[0];
  const actual = sha256(templatePath);
  return expected === actual ? [] : [`release evidence template digest mismatch: expected ${expected}, got ${actual}`];
}

export function assertGate(name, findings) {
  if (findings.length > 0) throw new GateError(`${name} failed`, findings);
  return `${name} passed`;
}
