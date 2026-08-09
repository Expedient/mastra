---
'@mastra/core': major
'@mastra/express': patch
'@mastra/fastify': patch
'@mastra/hono': patch
'@mastra/koa': patch
'@mastra/inngest': patch
'@mastra/editor': patch
'@mastra/server': patch
'@mastra/mcp': patch
'@mastra/auth-workos': patch
'@mastra/auth-neon': patch
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

Legacy commercial license helpers now fail closed, while provider-configured RBAC and FGA remain available without license gates.
