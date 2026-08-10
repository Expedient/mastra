---
'@mastra/core': major
---

Removed the `@mastra/core/agent-builder/ee` entry point. Import Builder contracts from `@mastra/core/editor` and use the `Builder`-prefixed model entry names.

```ts
// Before
import type { BuilderModelPolicy, DefaultModelEntry, IAgentBuilder } from '@mastra/core/agent-builder/ee';

// After
import type { BuilderDefaultModelEntry, BuilderModelPolicy, IAgentBuilder } from '@mastra/core/editor';
```
