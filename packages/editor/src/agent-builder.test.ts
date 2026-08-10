import { Mastra } from '@mastra/core';
import { InMemoryStore } from '@mastra/core/storage';
import { describe, expect, it, vi } from 'vitest';

import {
  MastraEditor,
  builderToModelPolicy,
  createBuilderAgent,
  isModelAllowed,
  resolvePickerVisibility,
} from './index';

describe('createBuilderAgent', () => {
  it('preserves its public identity while accepting runtime overrides', async () => {
    const agent = createBuilderAgent({
      id: 'ignored',
      name: 'Ignored',
      description: 'Ignored',
      model: 'openai/gpt-5',
      instructions: 'Deployment-specific builder instructions',
      defaultOptions: {
        maxSteps: 12,
        providerOptions: { anthropic: { thinking: { type: 'enabled', budgetTokens: 1024 } } },
      },
    } as any);

    expect(agent.id).toBe('builder-agent');
    expect(agent.name).toBe('Builder Agent');
    expect(agent.getDescription()).toBeTruthy();
    expect(await agent.getInstructions()).toBe('Deployment-specific builder instructions');
    expect(agent.model).toBe('openai/gpt-5');
    expect(await agent.getDefaultOptions()).toMatchObject({
      maxSteps: 12,
      providerOptions: {
        openai: { reasoningEffort: 'low' },
        anthropic: { thinking: { type: 'enabled', budgetTokens: 1024 } },
      },
    });
  });

  it('merges custom error processors with defaults and lets matching ids replace them', async () => {
    const replacement = { id: 'prefill-error-handler', name: 'Custom prefill handler' } as any;
    const custom = { id: 'deployment-errors', name: 'Deployment errors' } as any;
    const agent = createBuilderAgent({ errorProcessors: [replacement, custom] } as any);

    const processors = await agent.listErrorProcessors();
    expect(processors.map(processor => processor.id)).toEqual([
      'stream-error-retry-processor',
      'prefill-error-handler',
      'provider-history-compat',
      'deployment-errors',
    ]);
    expect(processors[1]).toBe(replacement);
  });

  it('treats an explicit empty processor list as an opt-out', async () => {
    const agent = createBuilderAgent({ errorProcessors: [] });
    await expect(agent.listErrorProcessors()).resolves.toEqual([]);
  });
});

describe('MastraEditor builder configuration', () => {
  it('is dormant unless explicitly enabled and caches the resolved builder', async () => {
    const disabled = new MastraEditor();
    expect(disabled.hasEnabledBuilderConfig()).toBe(false);
    await expect(disabled.resolveBuilder()).resolves.toBeUndefined();

    const editor = new MastraEditor({ builder: { enabled: true } });
    expect(editor.hasEnabledBuilderConfig()).toBe(true);
    const first = await editor.resolveBuilder();
    const second = await editor.resolveBuilder();

    expect(first).toBe(second);
    expect(first?.enabled).toBe(true);
    expect(first?.getConfiguration()).toMatchObject({
      agent: {
        memory: { observationalMemory: { model: 'openai/gpt-5-mini' } },
      },
    });
  });

  it('resolves default-on feature visibility and handles browser prerequisites', async () => {
    const warn = vi.fn();
    const withoutBrowser = new MastraEditor({
      logger: { warn } as any,
      builder: { enabled: true, features: { agent: { browser: true, tools: false } } },
    });
    const unavailable = await withoutBrowser.resolveBuilder();

    expect(unavailable?.getFeatures().agent).toMatchObject({
      tools: false,
      agents: true,
      workflows: true,
      model: true,
      browser: false,
    });
    expect(warn).toHaveBeenCalledOnce();
    expect(warn.mock.calls[0]?.[0]).toContain('browser');

    warn.mockClear();
    const withBrowser = new MastraEditor({
      logger: { warn } as any,
      builder: {
        enabled: true,
        configuration: { agent: { browser: { type: 'inline', config: { provider: 'stagehand' } } } },
      },
    });

    expect((await withBrowser.resolveBuilder())?.getFeatures().agent.browser).toBe(true);
    expect(warn).not.toHaveBeenCalled();
  });

  it('deeply resolves baseline, request, and administrator-pinned agent defaults', async () => {
    const storage = new InMemoryStore();
    const editor = new MastraEditor({
      builder: {
        enabled: true,
        configuration: {
          agent: {
            memory: {
              options: { lastMessages: 9 },
              observationalMemory: { scope: 'thread' },
            },
          },
        },
      },
    });
    const mastra = new Mastra({ storage, editor });

    await editor.agent.create({
      id: 'builder-created',
      name: 'Builder Created',
      instructions: 'Help the user',
      model: { provider: 'openai', name: 'gpt-5-mini' },
      memory: {
        options: { lastMessages: 3, semanticRecall: false },
        observationalMemory: false,
      },
    });

    const stored = await (
      await mastra.getStorage()?.getStore('agents')
    )?.getByIdResolved('builder-created', {
      status: 'draft',
    });
    expect(stored?.memory).toEqual({
      options: { lastMessages: 9, semanticRecall: false },
      observationalMemory: { model: 'openai/gpt-5-mini', scope: 'thread' },
    });
  });
});

describe('builder model and picker policies', () => {
  it('derives an active model policy and supports provider and model filtering', async () => {
    const editor = new MastraEditor({
      builder: {
        enabled: true,
        configuration: {
          agent: {
            models: {
              allowed: [{ provider: 'openai' }, { kind: 'custom', provider: 'acme/hosted', modelId: 'fast' }],
              default: { provider: 'openai', modelId: 'gpt-5-mini' },
            },
          },
        },
      },
    });
    const builder = await editor.resolveBuilder();
    const policy = builderToModelPolicy(builder);

    expect(policy).toMatchObject({ active: true, pickerVisible: true });
    expect(isModelAllowed(policy.allowed, { provider: 'openai.chat', modelId: 'gpt-5' })).toBe(true);
    expect(isModelAllowed(policy.allowed, { provider: 'acme/hosted', modelId: 'fast' })).toBe(true);
    expect(isModelAllowed(policy.allowed, { provider: 'acme/hosted', modelId: 'slow' })).toBe(false);
  });

  it('rejects locked model configuration without a default', async () => {
    const editor = new MastraEditor({
      builder: {
        enabled: true,
        features: { agent: { model: false } },
        configuration: { agent: { models: { allowed: [{ provider: 'openai' }] } } },
      },
    });

    await expect(editor.resolveBuilder()).rejects.toThrow(/default model/i);
  });

  it('filters picker allowlists and reports unknown registered ids', () => {
    const result = resolvePickerVisibility({
      config: {
        tools: { allowed: ['weather', 'missing'] },
        agents: { allowed: [] },
      },
      registeredToolIds: ['weather', 'search'],
      registeredAgentIds: ['support'],
      registeredWorkflowIds: ['onboarding'],
    });

    expect(result.visibleTools).toEqual(['weather']);
    expect(result.visibleAgents).toEqual([]);
    expect(result.visibleWorkflows).toBeNull();
    expect(result.warnings).toHaveLength(1);
    expect(result.warnings[0]).toContain('missing');
  });
});
