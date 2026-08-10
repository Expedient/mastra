---
'@mastra/editor': minor
---

Added the public Agent Builder runtime and root exports. `createBuilderAgent` creates a Builder agent with native defaults, while `MastraEditor` accepts Builder configuration.

```ts
import { MastraEditor, createBuilderAgent } from '@mastra/editor';

const builderAgent = createBuilderAgent();
const editor = new MastraEditor({ builder: { enabled: true } });
```
