import { describe, expect, it } from 'vitest';

import { MastraRBACWorkos } from './rbac-provider';
import type { WorkOSUser } from './types';

const user = {
  id: 'user-1',
  workosId: 'workos-user-1',
  memberships: [{ role: { slug: 'operator' } }],
} as WorkOSUser;

function createProvider() {
  return new MastraRBACWorkos({
    apiKey: 'test-api-key',
    clientId: 'test-client-id',
    roleMapping: {
      operator: ['*:read', 'agents:*:agent-1', '*:write:shared'],
    },
  });
}

describe('MastraRBACWorkos permission matching', () => {
  it('hasPermission supports cross-resource action wildcards and resource IDs', async () => {
    const rbac = createProvider();

    await expect(rbac.hasPermission(user, 'workflows:read')).resolves.toBe(true);
    await expect(rbac.hasPermission(user, 'workflows:read:workflow-1')).resolves.toBe(true);
    await expect(rbac.hasPermission(user, 'agents:execute:agent-1')).resolves.toBe(true);
    await expect(rbac.hasPermission(user, 'agents:execute:agent-2')).resolves.toBe(false);
    await expect(rbac.hasPermission(user, 'workflows:write:shared')).resolves.toBe(true);
    await expect(rbac.hasPermission(user, 'workflows:write:private')).resolves.toBe(false);
  });

  it('hasAllPermissions requires every wildcard and resource-ID match', async () => {
    const rbac = createProvider();

    await expect(rbac.hasAllPermissions(user, ['stored-agents:read:item-1', 'agents:write:agent-1'])).resolves.toBe(
      true,
    );
    await expect(rbac.hasAllPermissions(user, ['stored-agents:read:item-1', 'agents:write:agent-2'])).resolves.toBe(
      false,
    );
  });

  it('hasAnyPermission accepts one matching wildcard without crossing IDs or actions', async () => {
    const rbac = createProvider();

    await expect(rbac.hasAnyPermission(user, ['agents:execute:agent-2', 'tools:read:tool-1'])).resolves.toBe(true);
    await expect(rbac.hasAnyPermission(user, ['agents:execute:agent-2', 'tools:write:private'])).resolves.toBe(false);
  });
});
