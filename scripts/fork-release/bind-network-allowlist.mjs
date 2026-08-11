#!/usr/bin/env node
import { existsSync, writeFileSync } from 'node:fs';
import path from 'node:path';

import { GateError, readJson, schemaFindings, sha256 } from './lib.mjs';

function option(name) {
  const index = process.argv.indexOf(`--${name}`);
  const value = index === -1 ? undefined : process.argv[index + 1];
  if (!value || value.startsWith('--')) throw new GateError(`--${name} is required`);
  return path.resolve(value);
}
const source = option('source');
const artifact = option('artifact');
const output = option('output');
if (existsSync(output)) throw new GateError('refusing to overwrite a bound network allowlist');
const reviewed = readJson(source);
const findings = schemaFindings(reviewed, 'network-allowlist.schema.json', 'reviewed network allowlist source');
if (findings.length > 0) throw new GateError('reviewed network allowlist source is invalid', findings);
const bound = { ...reviewed, artifactSha256: sha256(artifact) };
writeFileSync(output, `${JSON.stringify(bound, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
console.log(JSON.stringify({ sourceSha256: sha256(source), artifactSha256: bound.artifactSha256, output }));
