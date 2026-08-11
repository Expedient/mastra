import { afterEach, describe, expect, expectTypeOf, it, vi } from 'vitest';

import {
  PERMISSION_PATTERNS,
  STORED_RESOURCE_PERMISSION_ALLOWLIST,
  buildCapabilities,
  isEEEnabled,
  isFeatureEnabled,
  isLicenseValid,
  isValidPermissionPattern,
  matchesPermission,
  requireFGA,
  validateLicense,
  validatePermissions,
} from './authorization';
import type { IFGAProvider, IRBACProvider, PermissionPattern } from './authorization';

const request = new Request('https://studio.example.test/api/auth/capabilities');
const runtimeProcess = (globalThis as unknown as { process: { env: Record<string, string | undefined> } }).process;

function createFGA(requireActor: IFGAProvider['requireActor']): IFGAProvider {
  return {
    check: vi.fn().mockResolvedValue(false),
    filterAccessible: vi.fn().mockImplementation(async (_user, resources) => resources),
    requireActor,
  };
}

function createRBAC(permissions: string[]): IRBACProvider {
  return {
    getRoles: vi.fn().mockResolvedValue(['member']),
    hasRole: vi.fn().mockResolvedValue(false),
    getPermissions: vi.fn().mockResolvedValue(permissions),
    hasPermission: vi.fn().mockResolvedValue(false),
    hasAllPermissions: vi.fn().mockResolvedValue(false),
    hasAnyPermission: vi.fn().mockResolvedValue(false),
    getAvailableRoles: vi.fn().mockResolvedValue([
      { id: 'admin', name: 'Admin', internal: 'do-not-expose' },
      { id: 'member', name: 'Member' },
    ]),
  };
}

describe('legacy license compatibility', () => {
  const originalEnv = { ...runtimeProcess.env };

  afterEach(() => {
    runtimeProcess.env = { ...originalEnv };
  });

  it('fails closed for arbitrary license strings and development environments', () => {
    runtimeProcess.env['MASTRA_EE_LICENSE'] = 'arbitrary-non-empty-license';
    runtimeProcess.env['MASTRA_LICENSE_KEY'] = 'another-arbitrary-license';
    runtimeProcess.env['NODE_ENV'] = 'development';

    expect(isLicenseValid()).toBe(false);
    expect(isEEEnabled()).toBe(false);
    expect(isFeatureEnabled('commercial-feature')).toBe(false);
    expect(validateLicense(runtimeProcess.env['MASTRA_EE_LICENSE'])).toEqual({ valid: false });
  });
});

describe('trusted actor FGA', () => {
  const params = {
    resource: { type: 'agent', id: 'agent-1' },
    permission: 'agents:execute',
    user: null,
    actor: { actorKind: 'system' as const, sourceWorkflow: 'nightly' },
  };

  it('rejects an actor without an organization before provider delegation', async () => {
    const requireActor = vi.fn();
    const provider = createFGA(requireActor);

    await expect(requireFGA({ ...params, fgaProvider: provider })).rejects.toThrow(
      'trusted actor requires an organizationId',
    );
    expect(requireActor).not.toHaveBeenCalled();
  });

  it('delegates a tenant-scoped actor to the configured provider', async () => {
    const requireActor = vi.fn().mockResolvedValue(undefined);
    const provider = createFGA(requireActor);
    const requestContext = new Map<string, unknown>([['organizationId', 'org-1']]);

    await requireFGA({ ...params, fgaProvider: provider, requestContext });

    expect(requireActor).toHaveBeenCalledWith(
      params.actor,
      expect.objectContaining({
        resource: params.resource,
        permission: params.permission,
        context: expect.objectContaining({ requestContext }),
      }),
    );
  });
});

describe('canonical permissions', () => {
  it('exports literal permission types and the canonical stored-resource allowlist', () => {
    expectTypeOf<PermissionPattern>().toEqualTypeOf<keyof typeof PERMISSION_PATTERNS>();
    expect(PERMISSION_PATTERNS['agents:read']).toBe('agents:read');
    expect(PERMISSION_PATTERNS['stored:*']).toBe('stored:*');
    expect(isValidPermissionPattern('agents:read')).toBe(true);
    expect(isValidPermissionPattern('agents:launch')).toBe(false);
    expect(validatePermissions(['agents:read', 'stored:*'])).toBe(true);
    expect(validatePermissions(['agents:read', 'stored-secrets:*'])).toBe(false);
    expect(STORED_RESOURCE_PERMISSION_ALLOWLIST).toEqual([
      'stored-agents',
      'stored-mcp-clients',
      'stored-prompt-blocks',
      'stored-scorers',
      'stored-skills',
      'stored-workspaces',
    ]);
  });

  it('limits compound stored grants to registered stored-resource families', () => {
    expect(matchesPermission('stored:read', 'stored-workflows:read')).toBe(false);
    expect(matchesPermission('stored:*', 'stored-skills:delete')).toBe(true);
    expect(matchesPermission('stored:*', 'stored-secrets:read')).toBe(false);
  });
});

describe('auth capabilities', () => {
  it('uses the server SSO route and projects only safe user fields', async () => {
    const getLoginUrl = vi.fn();
    const capabilities = await buildCapabilities(
      {
        getLoginButtonConfig: () => ({ provider: 'workos', text: 'Sign in with WorkOS' }),
        getLoginUrl,
        getCurrentUser: vi.fn().mockResolvedValue({
          id: 'user-1',
          email: 'user@example.test',
          name: 'User',
          avatarUrl: 'https://example.test/avatar.png',
          accessToken: 'secret',
          organizationMembershipId: 'membership-secret',
        }),
      },
      request,
      { apiPrefix: '/mastra/' },
    );

    expect(capabilities).toMatchObject({
      login: { sso: { url: '/mastra/auth/sso/login' } },
      user: {
        id: 'user-1',
        email: 'user@example.test',
        name: 'User',
        avatarUrl: 'https://example.test/avatar.png',
      },
    });
    expect((capabilities as { user: Record<string, unknown> }).user).not.toHaveProperty('accessToken');
    expect((capabilities as { user: Record<string, unknown> }).user).not.toHaveProperty('organizationMembershipId');
    expect(getLoginUrl).not.toHaveBeenCalled();
  });

  it('only discloses the projected role catalog to admin-bypass users', async () => {
    const auth = { getCurrentUser: vi.fn().mockResolvedValue({ id: 'user-1' }) };
    const memberRBAC = createRBAC(['*:read']);
    const member = await buildCapabilities(auth, request, { rbac: memberRBAC });

    expect(member).not.toHaveProperty('availableRoles');
    expect(memberRBAC.getAvailableRoles).not.toHaveBeenCalled();

    const adminRBAC = createRBAC(['*']);
    const admin = await buildCapabilities(auth, request, { rbac: adminRBAC });

    expect(admin).toHaveProperty('availableRoles', [
      { id: 'admin', name: 'Admin' },
      { id: 'member', name: 'Member' },
    ]);
    expect(adminRBAC.getAvailableRoles).toHaveBeenCalledOnce();
  });
});
