#!/usr/bin/env node
import path from 'node:path';

import {
  GateError,
  assertGate,
  defaultAuditPath,
  defaultCompatibilityPath,
  defaultPolicyPath,
  loadPolicy,
  readJson,
  reviewNetworkCapture,
  runCompatibilityMatrix,
  scanActiveSource,
  scanBundles,
  scanDependencyGraph,
  scanLicenseInventory,
  schemaFindings,
  verifyAudit,
  verifyCompatibilityEvidence,
  verifyEvidence,
  verifyTemplateIntegrity,
  verifyUpstreamSync,
} from './lib.mjs';
import { captureNetworkLinux } from './network-capture-linux.mjs';

function parse(argv) {
  const [command, ...rest] = argv;
  const options = { _: [] };
  for (let index = 0; index < rest.length; index += 1) {
    const argument = rest[index];
    if (argument.startsWith('--')) {
      const key = argument.slice(2);
      const value = rest[index + 1];
      if (!value || value.startsWith('--')) throw new GateError(`Option ${argument} requires a value`);
      options[key] = value;
      index += 1;
    } else options._.push(argument);
  }
  return { command, options };
}

function usage() {
  return `Usage: node scripts/fork-release/release-gate.mjs <command> [options]

Commands:
  audit [--root .] [--audit file]
  regression --id CP-NN [--root .] [--audit file]
  graph [--root .] [--policy file]
  source [--root .] [--policy file]
  bundles --artifact path[,path] [--policy file]
  licenses --inventory file --artifact file --sbom file [--policy file]
  network-linux --artifact file --capture file --allowlist file --exercises file [--root .]
  network-review --artifact file --capture file --allowlist file [--root .]
  compatibility-run --artifact file --output file [--manifest file] [--root .]
  compatibility-review --artifact file --evidence file --baseline-commit hash --release-commit hash [--manifest file] [--root .]
  upstream-sync --base commit [--root .] [--policy file]
  evidence --manifest file [--root .]
  release --manifest file [--root .]
  schemas [--root .]
  static [--root .] [--policy file]
`;
}

function required(options, name) {
  if (!options[name]) throw new GateError(`--${name} is required`);
  return options[name];
}

function absolute(root, value) {
  return path.resolve(root, value);
}

function schemaParity(root) {
  const findings = [];
  const documents = [
    ['policy.json', 'policy.schema.json'],
    ['commercial-connection-audit.json', 'commercial-connection-audit.schema.json'],
    ['native-compatibility.json', 'native-compatibility.schema.json'],
    ['native-package-manifest.json', 'native-package-manifest.schema.json'],
  ];
  for (const [document, schema] of documents) {
    findings.push(...schemaFindings(readJson(path.join(root, 'scripts/fork-release', document)), schema, document));
  }
  findings.push(...verifyTemplateIntegrity());
  const templateFindings = verifyEvidence(root, path.join(root, 'scripts/fork-release/release-evidence.template.json'));
  if (templateFindings.length === 0) findings.push('unresolved evidence template unexpectedly authorizes a release');
  return findings;
}

function run(argv = process.argv.slice(2)) {
  const { command, options } = parse(argv);
  const root = path.resolve(options.root ?? '.');
  const policy = loadPolicy(path.resolve(options.policy ?? defaultPolicyPath));
  const auditPath = path.resolve(options.audit ?? defaultAuditPath);
  const compatibilityPath = path.resolve(options.manifest ?? defaultCompatibilityPath);
  const passed = [];
  switch (command) {
    case 'audit':
      passed.push(assertGate('commercial connection audit', verifyAudit(root, auditPath)));
      passed.push(assertGate('release evidence template integrity', verifyTemplateIntegrity()));
      break;
    case 'regression':
      passed.push(
        assertGate(
          `commercial connection ${required(options, 'id')} regression`,
          verifyAudit(root, auditPath, { onlyId: required(options, 'id'), executeCommands: false }),
        ),
      );
      break;
    case 'graph':
      passed.push(assertGate('prohibited dependency graph', scanDependencyGraph(root, policy)));
      break;
    case 'source':
      passed.push(assertGate('active source imports', scanActiveSource(root, policy)));
      break;
    case 'bundles':
      passed.push(
        assertGate(
          'built bundle scan',
          scanBundles(
            required(options, 'artifact')
              .split(',')
              .map(value => absolute(root, value)),
            policy,
          ),
        ),
      );
      break;
    case 'licenses':
      passed.push(
        assertGate(
          'complete CycloneDX license inventory',
          scanLicenseInventory(absolute(root, required(options, 'inventory')), policy, {
            artifactPath: absolute(root, required(options, 'artifact')),
            sbomPath: absolute(root, required(options, 'sbom')),
          }),
        ),
      );
      break;
    case 'network-linux':
      captureNetworkLinux({
        root,
        artifactPath: absolute(root, required(options, 'artifact')),
        capturePath: absolute(root, required(options, 'capture')),
        allowlistPath: absolute(root, required(options, 'allowlist')),
        exercisesPath: absolute(root, required(options, 'exercises')),
      });
      passed.push('comprehensive Linux network capture passed');
      break;
    case 'network-review':
      passed.push(
        assertGate(
          'runtime outbound network allowlist',
          reviewNetworkCapture(
            absolute(root, required(options, 'capture')),
            absolute(root, required(options, 'allowlist')),
            { root, artifactPath: absolute(root, required(options, 'artifact')) },
          ),
        ),
      );
      break;
    case 'compatibility-run':
      passed.push(
        assertGate(
          'native compatibility matrix execution',
          runCompatibilityMatrix(
            root,
            absolute(root, required(options, 'artifact')),
            absolute(root, required(options, 'output')),
            { manifestPath: compatibilityPath },
          ),
        ),
      );
      break;
    case 'compatibility-review':
      passed.push(
        assertGate(
          'native compatibility matrix evidence',
          verifyCompatibilityEvidence(root, absolute(root, required(options, 'evidence')), {
            artifactPath: absolute(root, required(options, 'artifact')),
            manifestPath: compatibilityPath,
            reviewedBaselineCommit: required(options, 'baseline-commit'),
            releaseCommit: required(options, 'release-commit'),
          }),
        ),
      );
      break;
    case 'upstream-sync':
      passed.push(
        assertGate('upstream-sync reintroduction', verifyUpstreamSync(root, required(options, 'base'), policy)),
      );
      break;
    case 'evidence':
      passed.push(
        assertGate(
          'correlated production release evidence',
          verifyEvidence(root, absolute(root, required(options, 'manifest'))),
        ),
      );
      break;
    case 'release': {
      const manifestPath = absolute(root, required(options, 'manifest'));
      const manifest = readJson(manifestPath);
      passed.push(assertGate('commercial connection audit', verifyAudit(root)));
      passed.push(assertGate('prohibited dependency graph', scanDependencyGraph(root, policy)));
      passed.push(assertGate('active source imports', scanActiveSource(root, policy)));
      passed.push(assertGate('correlated production release evidence', verifyEvidence(root, manifestPath)));
      passed.push(
        assertGate('release artifact immutability', scanBundles([absolute(root, manifest.artifact.path)], policy)),
      );
      break;
    }
    case 'schemas':
      passed.push(assertGate('fork release schema parity', schemaParity(root)));
      break;
    case 'static':
      passed.push(assertGate('commercial connection audit', verifyAudit(root)));
      passed.push(assertGate('release evidence schema parity', schemaParity(root)));
      passed.push(assertGate('prohibited dependency graph', scanDependencyGraph(root, policy)));
      passed.push(assertGate('active source imports', scanActiveSource(root, policy)));
      break;
    default:
      throw new GateError(command ? `Unknown command: ${command}\n${usage()}` : usage());
  }
  for (const message of passed) console.log(`PASS ${message}`);
}

try {
  run();
} catch (error) {
  if (error instanceof GateError) {
    console.error(`FAIL ${error.message}`);
    for (const finding of error.findings) console.error(`  - ${finding}`);
    process.exitCode = 1;
  } else {
    throw error;
  }
}
