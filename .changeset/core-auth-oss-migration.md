---
'@mastra/core': major
---

Removed the `@mastra/core/auth/ee` export. Import open-source authorization APIs from `@mastra/core/auth/authorization` instead.

**Before**

```ts
import { StaticRBACProvider } from '@mastra/core/auth/ee';
```

**After**

```ts
import { StaticRBACProvider } from '@mastra/core/auth/authorization';
```

Legacy commercial license helpers now fail closed. Provider-configured RBAC, FGA, and Agent Builder remain available without commercial license gates.
