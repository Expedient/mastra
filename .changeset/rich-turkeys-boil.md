---
'@mastra/editor': major
---

Removed the `@mastra/editor/ee` entry point. Import Agent Builder runtime APIs from the package root.

```ts
// Before
import { MastraEditor } from '@mastra/editor';
import { createBuilderAgent } from '@mastra/editor/ee';

// After
import { createBuilderAgent, MastraEditor } from '@mastra/editor';
```
