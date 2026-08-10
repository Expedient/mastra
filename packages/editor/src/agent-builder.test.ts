import { Mastra } from '@mastra/core';
import { Agent } from '@mastra/core/agent';
import { InMemoryStore } from '@mastra/core/storage';
import { Memory } from '@mastra/memory';
import { describe, expect, it, vi } from 'vitest';

import {
  MastraEditor,
  builderToModelPolicy,
  createBuilderAgent,
  isModelAllowed,
  resolvePickerVisibility,
} from './index';

describe('createBuilderAgent', () => {
  it('restores the native identity, model, memory, and processor defaults', async () => {
    const agent = createBuilderAgent();

    expect(agent.id).toBe('builder-agent');
    expect(agent.name).toBe('Agent Builder');
    expect(agent.model).toBe('openai/gpt-5.6-sol');
    const memory = await agent.getMemory();
    expect(memory).toBeInstanceOf(Memory);
    expect(memory?.getMergedThreadConfig().observationalMemory).toMatchObject({ model: 'openai/gpt-5.4-mini' });
    await expect(agent.listErrorProcessors()).resolves.toMatchObject([
      { id: 'stream-error-retry-processor' },
      { id: 'prefill-error-handler' },
      { id: 'provider-history-compat' },
    ]);
  });

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
    expect(agent.name).toBe('Agent Builder');
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

  it('uses explicit processor arrays verbatim, including an empty array', async () => {
    const replacement = { id: 'prefill-error-handler', name: 'Custom prefill handler' } as any;
    const custom = { id: 'deployment-errors', name: 'Deployment errors' } as any;

    await expect(
      createBuilderAgent({ errorProcessors: [replacement, custom] } as any).listErrorProcessors(),
    ).resolves.toEqual([replacement, custom]);
    await expect(createBuilderAgent({ errorProcessors: [] }).listErrorProcessors()).resolves.toEqual([]);
  });

  it('uses dynamic processor callbacks as replacements rather than merging defaults', async () => {
    const dynamic = { id: 'dynamic-errors', name: 'Dynamic errors' } as any;
    const agent = createBuilderAgent({ errorProcessors: async () => [dynamic] } as any);

    await expect(agent.listErrorProcessors()).resolves.toEqual([dynamic]);
  });
});

describe('MastraEditor builder configuration', () => {
  it('is enabled when configuration is present unless explicitly disabled and caches the builder', async () => {
    const absent = new MastraEditor();
    expect(absent.hasEnabledBuilderConfig()).toBe(false);
    await expect(absent.resolveBuilder()).resolves.toBeUndefined();

    const disabled = new MastraEditor({ builder: { enabled: false } });
    expect(disabled.hasEnabledBuilderConfig()).toBe(false);
    await expect(disabled.resolveBuilder()).resolves.toBeUndefined();

    const editor = new MastraEditor({ builder: {} });
    expect(editor.hasEnabledBuilderConfig()).toBe(true);
    const first = await editor.resolveBuilder();
    const second = await editor.resolveBuilder();

    expect(first).toBe(second);
    expect(first?.enabled).toBe(true);
    expect(first?.getConfiguration()).toMatchObject({
      agent: {
        memory: { observationalMemory: { model: 'openai/gpt-5.4-mini' } },
      },
    });
  });

  it('resolves default-on feature visibility and requires a registered browser provider', async () => {
    const warn = vi.fn();
    const withoutBrowser = new MastraEditor({
      logger: { warn } as any,
      builder: { features: { agent: { browser: true, tools: false } } },
    });
    const unavailable = await withoutBrowser.resolveBuilder();

    expect(unavailable?.getFeatures().agent).toMatchObject({
      tools: false,
      agents: true,
      workflows: true,
      model: true,
      browser: false,
    });
    expect(unavailable?.getModelPolicyWarnings?.()[0]).toContain('browser');
    expect(warn).toHaveBeenCalledOnce();

    warn.mockClear();
    const browserProvider = {
      id: 'stagehand',
      name: 'Stagehand',
      createBrowser: vi.fn(),
    } as any;
    const withBrowser = new MastraEditor({
      logger: { warn } as any,
      browsers: { stagehand: browserProvider },
      builder: {
        configuration: { agent: { browser: { type: 'inline', config: { provider: 'stagehand' } } } },
      },
    });

    expect((await withBrowser.resolveBuilder())?.getFeatures().agent.browser).toBe(true);
    expect(warn).not.toHaveBeenCalled();
  });

  it.each([
    ['malformed', { type: 'inline', config: { provider: '   ' } }],
    ['unregistered', { type: 'inline', config: { provider: 'missing-browser' } }],
  ])('hides %s browser configuration and retains an inspectable warning', async (_label, browser) => {
    const editor = new MastraEditor({
      builder: { configuration: { agent: { browser } as any } },
    });
    const builder = await editor.resolveBuilder();

    expect(builder?.getFeatures().agent.browser).toBe(false);
    expect(builder?.getModelPolicyWarnings?.()).toEqual([expect.stringMatching(/browser/i)]);
  });

  it('deeply resolves baseline, request, and administrator-pinned agent defaults', async () => {
    const storage = new InMemoryStore();
    const editor = new MastraEditor({
      builder: {
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
      observationalMemory: { model: 'openai/gpt-5.4-mini', scope: 'thread' },
    });
  });

  it('keeps a code-agent override partial when Builder is enabled', async () => {
    const storage = new InMemoryStore();
    const editor = new MastraEditor({ builder: {} });
    const codeAgent = new Agent({
      id: 'code-agent',
      name: 'Code Agent',
      instructions: 'Code-owned instructions',
      model: 'openai/gpt-5.4',
      editor: { instructions: true },
    });
    const mastra = new Mastra({ storage, editor, agents: { codeAgent } });

    const created = await editor.agent.create({ id: 'code-agent', instructions: 'Stored override' } as any);
    const stored = await (
      await mastra.getStorage()?.getStore('agents')
    )?.getByIdResolved('code-agent', {
      status: 'draft',
    });

    expect(created).toBe(codeAgent);
    expect(stored?.instructions).toBe('Stored override');
    expect(stored?.model).toBeUndefined();
    expect(stored?.memory).toBeUndefined();
  });
});

describe('builder model and picker policies', () => {
  it('derives an active model policy even without model constraints', async () => {
    const builder = await new MastraEditor({ builder: {} }).resolveBuilder();

    expect(builderToModelPolicy(builder)).toEqual({ active: true, pickerVisible: true });
  });

  it('supports only explicit provider aliases and rejects slash-suffix impersonation', () => {
    const allowed = [{ provider: 'openai' }];

    expect(isModelAllowed(allowed, { provider: 'openai.chat', modelId: 'gpt-5.4' })).toBe(true);
    expect(isModelAllowed(allowed, { provider: 'openai', modelId: 'gpt-5.4' })).toBe(true);
    expect(isModelAllowed(allowed, { provider: 'evil/openai', modelId: 'gpt-5.4' })).toBe(false);
    expect(isModelAllowed([], { provider: 'openai', modelId: 'gpt-5.4' })).toBe(false);
  });

  it('applies and persists the configured default model when direct SDK input omits model', async () => {
    const storage = new InMemoryStore();
    const editor = new MastraEditor({
      builder: {
        configuration: {
          agent: {
            models: {
              allowed: [{ provider: 'openai' }],
              default: { provider: 'openai', modelId: 'gpt-5.4-mini' },
            },
          },
        },
      },
    });
    const mastra = new Mastra({ storage, editor });

    await editor.agent.create({
      id: 'default-model-agent',
      name: 'Default Model Agent',
      instructions: 'Use the configured default',
    } as any);

    const stored = await (
      await mastra.getStorage()?.getStore('agents')
    )?.getByIdResolved('default-model-agent', {
      status: 'draft',
    });
    expect(stored?.model).toEqual({ provider: 'openai', name: 'gpt-5.4-mini' });
  });

  it('enforces allowed and locked model policies for direct SDK creates', async () => {
    const storage = new InMemoryStore();
    const allowedEditor = new MastraEditor({
      builder: {
        configuration: {
          agent: {
            models: {
              allowed: [{ provider: 'openai' }],
              default: { provider: 'openai', modelId: 'gpt-5.4-mini' },
            },
          },
        },
      },
    });
    new Mastra({ storage, editor: allowedEditor });

    await expect(
      allowedEditor.agent.create({
        id: 'evil-provider',
        name: 'Evil Provider',
        instructions: 'Do not persist',
        model: { provider: 'evil/openai', name: 'gpt-5.4-mini' },
      }),
    ).rejects.toThrow(/not allowed/i);
    await expect((await storage.getStore('agents'))?.getById('evil-provider')).resolves.toBeNull();

    const lockedEditor = new MastraEditor({
      builder: {
        features: { agent: { model: false } },
        configuration: {
          agent: {
            models: {
              allowed: [{ provider: 'openai' }],
              default: { provider: 'openai', modelId: 'gpt-5.4-mini' },
            },
          },
        },
      },
    });
    new Mastra({ storage: new InMemoryStore(), editor: lockedEditor });

    await expect(
      lockedEditor.agent.create({
        id: 'locked-model',
        name: 'Locked Model',
        instructions: 'Must use default',
        model: { provider: 'openai', name: 'gpt-5.4' },
      }),
    ).rejects.toThrow(/locked/i);
  });

  it('rejects locked model configuration without a default', async () => {
    const editor = new MastraEditor({
      builder: {
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
