import * as fs from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import { stepCountIs } from '@internal/ai-sdk-v5';
import { it, expect, beforeEach, afterEach, vi } from 'vitest';
import { LocalFilesystem } from '../../../../workspace/filesystem';
import { Workspace } from '../../../../workspace/workspace';
import { runApprovalScenario, runLoopScenario, useLoopScenarioAimock, describeForAllEngines } from '../aimock-scenario';

/**
 * Regression class: SkillsProcessor integration with agent loop.
 *
 * When a workspace has skills configured (real SKILL.md files on disk),
 * the Agent auto-creates a SkillsProcessor that:
 * 1. Discovers skills from the filesystem
 * 2. Injects skill metadata into the system prompt
 * 3. Auto-injects `skill`, `skill_search`, `skill_read` tools
 *
 * We test the full flow through the real Workspace + LocalFilesystem + SkillsProcessor
 * pipeline, asserting that skill metadata lands in the model request and the skill tool
 * round-trips instructions correctly.
 */

const SKILL_MD = `---
name: code-review
description: Reviews code for quality, style, and potential issues
---

# Code Review

Pinned revision: TASK1493_PINNED_REVISION_1

You are a code reviewer. When reviewing code:

1. Check for bugs and edge cases
2. Verify the code follows the style guide
3. Suggest improvements for readability
`;

describeForAllEngines('AIMock scenario: skills integration', engine => {
  const getMock = useLoopScenarioAimock();
  let tempDir: string;
  let workspace: Workspace;
  let skillIdentifier: string;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'aimock-skills-scenario-'));

    // Two revisions have the same skill name; the path selects the pinned revision.
    const revisionOneDir = path.join(tempDir, 'skills-v1', 'code-review');
    const revisionTwoDir = path.join(tempDir, 'skills-v2', 'code-review');
    await Promise.all([fs.mkdir(revisionOneDir, { recursive: true }), fs.mkdir(revisionTwoDir, { recursive: true })]);
    await Promise.all([
      fs.writeFile(path.join(revisionOneDir, 'SKILL.md'), SKILL_MD),
      fs.writeFile(
        path.join(revisionTwoDir, 'SKILL.md'),
        SKILL_MD.replace('TASK1493_PINNED_REVISION_1', 'TASK1493_PINNED_REVISION_2'),
      ),
    ]);

    // Create a real workspace with LocalFilesystem and both skill revisions.
    workspace = new Workspace({
      filesystem: new LocalFilesystem({ basePath: tempDir }),
      skills: ['skills-v1', 'skills-v2'],
    });
    const skill = (await workspace.skills?.list())?.find(candidate =>
      candidate.path.replace(/\\/g, '/').includes('skills-v1/code-review'),
    );
    if (!skill) throw new Error('Expected the pinned code-review revision to be discovered');
    skillIdentifier = skill.path;
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true }).catch(() => {});
  });

  it('injects skill metadata into system prompt when workspace has skills', async () => {
    const { requests } = await runLoopScenario({
      engine,
      llm: getMock(),
      prompt: 'What skills do you have?',
      workspace,
      stopWhen: stepCountIs(2),
      fixtures: llm => {
        llm.on(
          { endpoint: 'chat', hasToolResult: false },
          {
            content: 'I have access to the code-review skill for quality checks.',
          },
        );
      },
    });

    expect(requests.length).toBeGreaterThanOrEqual(1);

    // The SkillsProcessor injects <available_skills> XML into a system message
    const messages = requests[0]?.body?.messages ?? [];
    const allContent = messages.map((m: any) => JSON.stringify(m.content)).join('\n');
    expect(allContent).toContain('code-review');
    expect(allContent).toContain('<available_skills>');
    expect(allContent).toContain('Reviews code for quality');
  });

  it('loads the pinned skill automatically when no global approval is requested', async () => {
    const beforeToolCall = vi.fn();
    const afterToolCall = vi.fn();
    const { output, requests, chunks } = await runLoopScenario({
      engine,
      llm: getMock(),
      prompt: 'Load the pinned code-review skill and tell me what it does.',
      workspace,
      stopWhen: stepCountIs(4),
      collectChunks: true,
      hooks: { beforeToolCall, afterToolCall },
      fixtures: llm => {
        // Turn 1: Model calls the skill tool by its revision-specific path
        llm.on(
          { endpoint: 'chat', hasToolResult: false },
          {
            toolCalls: [
              {
                id: 'call_skill_1',
                name: 'skill',
                arguments: { name: skillIdentifier },
              },
            ],
          },
        );

        // Turn 2: Model receives the pinned instructions and responds
        llm.on(
          { endpoint: 'chat', hasToolResult: true },
          {
            content: 'The code-review skill reviews code for bugs, style, and readability.',
          },
        );
      },
    });

    expect(requests.length).toBe(2);
    expect(chunks?.some(chunk => chunk.type === 'tool-call-approval')).toBe(false);
    expect(beforeToolCall).toHaveBeenCalledTimes(1);
    expect(beforeToolCall).toHaveBeenCalledWith(
      expect.objectContaining({ toolName: 'skill', input: { name: skillIdentifier } }),
    );
    expect(afterToolCall).toHaveBeenCalledTimes(1);

    const toolResults = await output.toolResults;
    expect(toolResults.filter(result => result.payload.toolName === 'skill')).toHaveLength(1);

    // Cross-turn plumbing carries the pinned revision into the next model request.
    const turn2Messages = requests[1]?.body?.messages ?? [];
    const serializedTurn2 = JSON.stringify(turn2Messages);
    expect(serializedTurn2).toContain('TASK1493_PINNED_REVISION_1');
    expect(serializedTurn2).not.toContain('TASK1493_PINNED_REVISION_2');
    expect(serializedTurn2).toContain('bugs and edge cases');

    const toolMessage = turn2Messages.find((message: any) => message.role === 'tool') as
      | { tool_call_id?: string }
      | undefined;
    expect(toolMessage?.tool_call_id).toBe('call_skill_1');
    expect(await output.text).toContain('code-review');
  });

  it.each([
    ['boolean', true],
    ['function', ({ toolName }: { toolName: string }) => toolName === 'skill'],
  ])('pauses before loading a pinned skill under an explicit global %s approval policy', async (_label, policy) => {
    const beforeToolCall = vi.fn();
    const afterToolCall = vi.fn();
    let beforeHooksAtApproval: number | undefined;
    let afterHooksAtApproval: number | undefined;

    const { output, requests, chunks, approvals } = await runApprovalScenario({
      engine,
      llm: getMock(),
      prompt: 'Load the pinned code-review skill and tell me what it does.',
      workspace,
      requireToolApproval: policy as any,
      agentHooks: { beforeToolCall, afterToolCall },
      stopWhen: stepCountIs(4),
      fixtures: llm => {
        llm.on(
          { endpoint: 'chat', hasToolResult: false },
          {
            toolCalls: [
              {
                id: 'call_skill_pinned',
                name: 'skill',
                arguments: { name: skillIdentifier },
              },
            ],
          },
        );
        llm.on(
          { endpoint: 'chat', hasToolResult: true },
          {
            content: 'Loaded the pinned code-review revision exactly once.',
          },
        );
      },
      decision: ({ toolCallId }) => {
        expect(toolCallId).toBe('call_skill_pinned');
        beforeHooksAtApproval = beforeToolCall.mock.calls.length;
        afterHooksAtApproval = afterToolCall.mock.calls.length;
        return true;
      },
    });

    expect(approvals).toEqual(['approve:call_skill_pinned']);
    expect(beforeHooksAtApproval).toBe(0);
    expect(afterHooksAtApproval).toBe(0);
    expect(beforeToolCall).toHaveBeenCalledTimes(1);
    expect(beforeToolCall).toHaveBeenCalledWith(
      expect.objectContaining({ toolName: 'skill', input: { name: skillIdentifier } }),
    );
    expect(afterToolCall).toHaveBeenCalledTimes(1);

    const approvalIndex = chunks.findIndex(chunk => chunk.type === 'tool-call-approval');
    const skillResultIndex = chunks.findIndex(
      chunk => chunk.type === 'tool-result' && chunk.payload.toolName === 'skill',
    );
    expect(approvalIndex).toBeGreaterThanOrEqual(0);
    expect(skillResultIndex).toBeGreaterThan(approvalIndex);
    expect(chunks.filter(chunk => chunk.type === 'tool-call-approval')).toHaveLength(1);
    expect(chunks.filter(chunk => chunk.type === 'tool-result' && chunk.payload.toolName === 'skill')).toHaveLength(1);

    const toolResults = await output.toolResults;
    expect(toolResults.filter(result => result.payload.toolName === 'skill')).toHaveLength(1);
    expect(requests).toHaveLength(2);
    const serializedTurn2 = JSON.stringify(requests[1]?.body?.messages ?? []);
    expect(serializedTurn2).toContain('TASK1493_PINNED_REVISION_1');
    expect(serializedTurn2).not.toContain('TASK1493_PINNED_REVISION_2');
    expect(await output.text).toContain('pinned code-review revision');
  });

  it('handles missing skill gracefully', async () => {
    const { output, requests } = await runLoopScenario({
      engine,
      llm: getMock(),
      prompt: 'Load the non-existent-skill.',
      workspace,
      stopWhen: stepCountIs(4),
      fixtures: llm => {
        // Model calls a non-existent skill
        llm.on(
          { endpoint: 'chat', hasToolResult: false },
          {
            toolCalls: [
              {
                id: 'call_skill_2',
                name: 'skill',
                arguments: { name: 'non-existent-skill' },
              },
            ],
          },
        );

        // Model receives error and responds
        llm.on(
          { endpoint: 'chat', hasToolResult: true },
          {
            content: 'That skill is not available.',
          },
        );
      },
    });

    // Verify the loop handled the missing skill gracefully
    expect(requests.length).toBe(2);

    // The tool result should indicate skill not found
    const turn2Messages = requests[1]?.body?.messages ?? [];
    const serializedTurn2 = JSON.stringify(turn2Messages);
    expect(serializedTurn2).toMatch(/not found|Available skills/i);

    const text = await output.text;
    expect(text).toMatch(/not available/i);
  });
});
