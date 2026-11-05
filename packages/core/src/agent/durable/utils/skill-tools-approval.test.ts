/** Generated skill tools are automatic by default, but explicit global approval still applies. */

import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { resolveToolApprovalVerdict } from '../../../loop/workflows/agentic-execution/tool-approval-verdict';
import { CoreToolBuilder } from '../../../tools/tool-builder/builder';
import { toolRequiresApproval } from './resolve-runtime';

function buildSkillTool() {
  return new CoreToolBuilder({
    originalTool: {
      id: 'skill',
      description: 'Activate a skill',
      inputSchema: z.object({ name: z.string() }),
      execute: async () => 'ok',
    } as any,
    options: { name: 'skill', requireApproval: false } as any,
  }).build();
}

const verdict = (tool: unknown, requireToolApproval: any) =>
  resolveToolApprovalVerdict({
    tool,
    requireToolApproval,
    context: { toolName: 'skill', args: { name: 'x' } } as any,
  });

describe('skill tool approval precedence', () => {
  it('runs automatically when no global approval policy is configured', async () => {
    const tool = buildSkillTool();
    await expect(toolRequiresApproval(tool, undefined, { name: 'x' })).resolves.toBe(false);
    await expect(verdict(tool, undefined)).resolves.toBe(false);
  });

  it('honors an explicit global boolean policy in durable and non-durable execution', async () => {
    const tool = buildSkillTool();
    await expect(toolRequiresApproval(tool, true, { name: 'x' })).resolves.toBe(true);
    await expect(verdict(tool, true)).resolves.toBe(true);
  });

  it('honors an explicit global function policy in durable and non-durable execution', async () => {
    const tool = buildSkillTool();
    await expect(toolRequiresApproval(tool, () => true, { name: 'x' })).resolves.toBe(true);
    await expect(verdict(tool, () => true)).resolves.toBe(true);
  });

  it('keeps the global policy effective after a hook-style shallow wrapper', async () => {
    const wrapped = { ...buildSkillTool() };
    await expect(toolRequiresApproval(wrapped as any, true, { name: 'x' })).resolves.toBe(true);
    await expect(verdict(wrapped, true)).resolves.toBe(true);
  });
});
