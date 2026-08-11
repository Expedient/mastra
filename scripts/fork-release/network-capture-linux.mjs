#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { GateError, readJson, redactOutput, schemaFindings, sha256, sha256Text } from './lib.mjs';

const outputLimit = 64 * 1024;

function explicitEnvironment(policy, temporaryHome) {
  const names = [...policy.environment.passThrough, ...policy.environment.sensitive];
  if (new Set(names).size !== names.length) throw new GateError('Network environment allowlists overlap');
  const environment = {
    HOME: temporaryHome,
    LANG: 'C',
    PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
    ...policy.environment.fixed,
  };
  for (const name of names) {
    if (Object.hasOwn(process.env, name)) environment[name] = process.env[name];
  }
  const secrets = policy.environment.sensitive.map(name => environment[name]).filter(Boolean);
  return { environment, secrets };
}

function parseDestination(line) {
  const operation = line.match(/\b(connect|sendto|sendmsg)\(/)?.[1];
  if (!operation || !/AF_INET6?/.test(line)) return undefined;
  const port = Number(line.match(/sin6?_port=htons\((\d+)\)/)?.[1]);
  const ipv4 = line.match(/inet_addr\("([^"]+)"\)/)?.[1];
  const ipv6 = line.match(/inet_pton\(AF_INET6, "([^"]+)"/)?.[1];
  const host = ipv4 ?? ipv6;
  if (!host || !Number.isInteger(port) || port < 1 || port > 65535) {
    throw new GateError(`Cannot safely convert captured network syscall: ${line.slice(0, 512)}`);
  }
  const protocol = /<UDP/i.test(line) ? 'udp' : /<TCP/i.test(line) ? 'tcp' : operation === 'connect' ? 'tcp' : 'udp';
  return { operation, protocol, host: host.toLowerCase(), port };
}

function recordsFromTraces(directory, prefix, runtimeClass) {
  const records = [];
  const files = readdirSync(directory)
    .filter(name => name === prefix || name.startsWith(`${prefix}.`))
    .sort();
  if (files.length === 0) throw new GateError(`strace did not produce capture files for ${runtimeClass}`);
  for (const name of files) {
    const suffix = name.slice(prefix.length + 1);
    const pid = Number(suffix);
    if (!Number.isInteger(pid) || pid < 1) throw new GateError(`strace capture is missing a process id: ${name}`);
    const lines = readFileSync(path.join(directory, name), 'utf8').split('\n').filter(Boolean);
    for (const line of lines) {
      const destination = parseDestination(line);
      if (!destination) continue;
      records.push({
        type: 'network',
        protocol: destination.protocol,
        host: destination.host,
        port: destination.port,
        source: destination.operation,
        pid,
        runtimeClass,
      });
    }
  }
  return records;
}

export function captureNetworkLinux({ root, artifactPath, capturePath, allowlistPath, exercisesPath }) {
  if (process.platform !== 'linux')
    throw new GateError('Comprehensive release network capture is supported only on Linux');
  const allowlist = readJson(allowlistPath);
  const exercises = readJson(exercisesPath);
  const schemaErrors = [
    ...schemaFindings(allowlist, 'network-allowlist.schema.json', 'network allowlist'),
    ...schemaFindings(exercises, 'network-exercises.schema.json', 'network exercises'),
  ];
  if (schemaErrors.length > 0) throw new GateError('Network capture inputs are invalid', schemaErrors);
  if (allowlist.exerciseId !== exercises.exerciseId)
    throw new GateError('Network exercise identity does not match allowlist');
  if (allowlist.artifactSha256 !== sha256(artifactPath))
    throw new GateError('Network allowlist is not bound to the artifact');
  const exerciseClasses = exercises.exercises.map(exercise => exercise.runtimeClass).sort();
  const requiredClasses = [...allowlist.requiredRuntimeClasses].sort();
  if (JSON.stringify(exerciseClasses) !== JSON.stringify(requiredClasses)) {
    throw new GateError('Network exercises must cover every required runtime class exactly once');
  }

  const temporary = mkdtempSync(path.join(tmpdir(), 'fork-release-network-'));
  chmodSync(temporary, 0o700);
  const header = {
    type: 'header',
    schemaVersion: 2,
    exerciseId: exercises.exerciseId,
    artifactSha256: sha256(artifactPath),
    startedAt: new Date().toISOString(),
    requiredRuntimeClasses: allowlist.requiredRuntimeClasses,
    coverage: {
      mechanism: 'os-syscall',
      platform: 'linux',
      comprehensive: true,
      descendants: true,
      transports: ['tcp', 'udp', 'subprocess', 'native'],
      tool: 'strace -ff -e trace=network',
    },
  };
  writeFileSync(capturePath, `${JSON.stringify(header)}\n`, { mode: 0o600 });
  try {
    const { environment, secrets } = explicitEnvironment(allowlist, temporary);
    const records = [];
    const outputChunks = [];
    let outputTruncated = false;
    for (const [index, exercise] of exercises.exercises.entries()) {
      const prefix = `trace-${index}`;
      const [command, ...args] = exercise.argv;
      const result = spawnSync(
        'strace',
        [
          '-ff',
          '-qq',
          '-yy',
          '-s',
          '256',
          '-e',
          'trace=network',
          '-o',
          path.join(temporary, prefix),
          '--',
          command,
          ...args,
        ],
        {
          cwd: root,
          env: environment,
          encoding: 'utf8',
          timeout: exercise.timeoutMs,
          maxBuffer: outputLimit * 2,
          killSignal: 'SIGKILL',
        },
      );
      const rawOutput = `${result.stdout ?? ''}\n${result.stderr ?? ''}`;
      outputTruncated ||= rawOutput.length > outputLimit;
      const safeOutput = redactOutput(rawOutput, secrets);
      outputChunks.push(safeOutput);
      if (result.error) throw new GateError(`Network exercise could not run: ${exercise.runtimeClass}`, [safeOutput]);
      if (result.status !== 0) {
        throw new GateError(`Network exercise failed: ${exercise.runtimeClass} exited ${result.status}`, [safeOutput]);
      }
      records.push(...recordsFromTraces(temporary, prefix, exercise.runtimeClass));
    }
    for (const record of records) writeFileSync(capturePath, `${JSON.stringify(record)}\n`, { flag: 'a', mode: 0o600 });
    const combinedOutput = outputChunks.join('\n').slice(0, outputLimit);
    const completion = {
      type: 'completion',
      exerciseId: exercises.exerciseId,
      completedAt: new Date().toISOString(),
      status: 'completed',
      exitCode: 0,
      exercisedRuntimeClasses: exercises.exercises.map(exercise => exercise.runtimeClass),
      outputSha256: sha256Text(combinedOutput),
      outputTruncated,
    };
    writeFileSync(capturePath, `${JSON.stringify(completion)}\n`, { flag: 'a', mode: 0o600 });
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
}

function option(argv, name) {
  const index = argv.indexOf(`--${name}`);
  if (index === -1 || !argv[index + 1]) throw new GateError(`--${name} is required`);
  return argv[index + 1];
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname)) {
  try {
    captureNetworkLinux({
      root: path.resolve(option(process.argv, 'root')),
      artifactPath: path.resolve(option(process.argv, 'artifact')),
      capturePath: path.resolve(option(process.argv, 'capture')),
      allowlistPath: path.resolve(option(process.argv, 'allowlist')),
      exercisesPath: path.resolve(option(process.argv, 'exercises')),
    });
    console.log('PASS comprehensive Linux network capture completed');
  } catch (error) {
    if (!(error instanceof GateError)) throw error;
    console.error(`FAIL ${error.message}`);
    for (const finding of error.findings) if (finding) console.error(`  - ${finding}`);
    process.exitCode = 1;
  }
}
