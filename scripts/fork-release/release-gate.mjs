#!/usr/bin/env node
import path from 'node:path';

import {
  GateError,
  assertGate,
  captureNetwork,
  defaultAuditPath,
  defaultPolicyPath,
  loadPolicy,
  reviewNetworkCapture,
  scanActiveSource,
  scanBundles,
  scanDependencyGraph,
  scanLicenseInventory,
  verifyAudit,
  verifyEvidence,
  verifyTemplateIntegrity,
  verifyUpstreamSync,
} from './lib.mjs';

function parse(argv) {
  const [command, ...rest] = argv;
  const options = { _: [] };
  for (let index = 0; index < rest.length; index += 1) {
    const argument = rest[index];
    if (argument === '--') {
      options.command = rest.slice(index + 1);
      break;
    }
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
  graph [--root .] [--policy file]
  source [--root .] [--policy file]
  bundles --artifacts path[,path] [--policy file]
  licenses --inventory file [--policy file]
  network-review --capture file --allowlist file
  network --capture file --allowlist file -- <command> [args...]
  upstream-sync --base commit [--root .] [--policy file]
  evidence --manifest file [--root .]
  static [--root .] [--policy file]
`;
}

function required(options, name) {
  if (!options[name]) throw new GateError(`--${name} is required`);
  return options[name];
}

function run(argv = process.argv.slice(2)) {
  const { command, options } = parse(argv);
  const root = path.resolve(options.root ?? '.');
  const policy = loadPolicy(path.resolve(options.policy ?? defaultPolicyPath));
  const passed = [];
  switch (command) {
    case 'audit':
      passed.push(
        assertGate('commercial connection audit', verifyAudit(root, path.resolve(options.audit ?? defaultAuditPath))),
      );
      passed.push(assertGate('release evidence template integrity', verifyTemplateIntegrity()));
      break;
    case 'graph':
      passed.push(assertGate('prohibited dependency graph', scanDependencyGraph(root, policy)));
      break;
    case 'source':
      passed.push(assertGate('active source imports', scanActiveSource(root, policy)));
      break;
    case 'bundles':
      passed.push(assertGate('built bundle scan', scanBundles(required(options, 'artifacts').split(','), policy)));
      break;
    case 'licenses':
      passed.push(assertGate('license inventory', scanLicenseInventory(required(options, 'inventory'), policy)));
      break;
    case 'network-review':
      passed.push(
        assertGate(
          'runtime outbound network allowlist',
          reviewNetworkCapture(required(options, 'capture'), required(options, 'allowlist')),
        ),
      );
      break;
    case 'network': {
      const [executable, ...args] = options.command ?? [];
      passed.push(
        assertGate(
          'runtime outbound network capture',
          captureNetwork({
            command: executable,
            args,
            capturePath: required(options, 'capture'),
            allowlistPath: required(options, 'allowlist'),
            cwd: root,
          }),
        ),
      );
      break;
    }
    case 'upstream-sync':
      passed.push(
        assertGate('upstream-sync reintroduction', verifyUpstreamSync(root, required(options, 'base'), policy)),
      );
      break;
    case 'evidence':
      passed.push(assertGate('release evidence', verifyEvidence(root, required(options, 'manifest'))));
      break;
    case 'static':
      passed.push(assertGate('commercial connection audit', verifyAudit(root)));
      passed.push(assertGate('release evidence template integrity', verifyTemplateIntegrity()));
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
