---
'@mastra/core': minor
---

Added public Agent Builder configuration types for memory, browser, workspace, and picker defaults.

```ts
import type { AgentBuilderOptions, BuilderAgentConfiguration } from '@mastra/core/editor';

const agent: BuilderAgentConfiguration = {
  memory: { options: { lastMessages: 10 } },
  browser: { type: 'inline', config: { provider: 'stagehand' } },
  workspace: { type: 'id', workspaceId: 'workspace-id' },
};

const builder: AgentBuilderOptions = {
  enabled: true,
  configuration: { agent },
};
```
