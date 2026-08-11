import { Mastra } from '@mastra/core/mastra';
import { describe, expect, it, vi } from 'vitest';
import { MastraServer } from './index';

class TestMastraServer extends MastraServer<any, any, any> {
  stream = vi.fn();
  getParams = vi.fn();
  sendResponse = vi.fn();
  registerRoute = vi.fn();
  registerContextMiddleware = vi.fn();
  registerAuthMiddleware = vi.fn();
  registerHttpLoggingMiddleware = vi.fn();
}

function createMockEditor(hasEnabledBuilder: boolean) {
  return {
    hasEnabledBuilderConfig: () => hasEnabledBuilder,
    resolveBuilder: vi.fn(),
    agent: {},
    mcp: {},
    mcpServer: {},
    prompt: {},
    scorer: {},
    workspace: {},
    skill: {},
    registerWithMastra: vi.fn(),
  } as any;
}

describe('MastraServer.validateAgentBuilderLicense', () => {
  it.each([false, true])('does not gate open-source Agent Builder (enabled=%s)', async enabled => {
    const mastra = new Mastra({ editor: createMockEditor(enabled) });
    const adapter = new TestMastraServer({ app: {}, mastra });

    await expect(adapter.validateAgentBuilderLicense()).resolves.toBeUndefined();
  });
});
