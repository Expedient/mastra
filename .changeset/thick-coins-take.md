---
'@mastra/playground-ui': major
---

Removed the experimental `@mastra/playground-ui/ee/signals` entry point. The experimental Signals user interface is no longer published by `@mastra/playground-ui`.

```ts
// Before
import * as signalsUi from '@mastra/playground-ui/ee/signals';

// After
// Remove the retired Signals UI import and its usages.
```
