/**
 * OSS authorization compatibility for the public core auth surface.
 *
 * This module is deliberately local and network-free. It exposes the authorization
 * contracts used by core and delegates checks to providers supplied by applications.
 */
import type { User } from '@internal/auth';

export type PermissionPattern = string;
export type MastraFGAPermission = string;
export type MastraFGAPermissionInput = string;
export type Resource = string;
export type Action = string;
export type Permission = PermissionPattern;

export type ActorSignal =
  | true
  | {
      actorKind: 'system';
      sourceWorkflow?: string;
      agentId?: string;
      permissions?: MastraFGAPermissionInput[];
      scope?: Record<string, string>;
    };

export interface EEUser extends User {
  roles?: string[];
  permissions?: string[];
  organizationId?: string;
  organizationMembershipId?: string;
  [key: string]: unknown;
}

export type RoleMapping = Record<string, PermissionPattern[]>;
export type TypedRoleMapping = RoleMapping;

export interface RoleDefinition {
  id: string;
  name: string;
  description?: string;
  permissions: PermissionPattern[];
  inherits?: string[];
}

export interface IRBACProvider<TUser = unknown> {
  roleMapping?: RoleMapping;
  getRoles(user: TUser): Promise<string[]>;
  hasRole(user: TUser, role: string): Promise<boolean>;
  getPermissions(user: TUser): Promise<string[]>;
  hasPermission(user: TUser, permission: string): Promise<boolean>;
  hasAllPermissions(user: TUser, permissions: string[]): Promise<boolean>;
  hasAnyPermission(user: TUser, permissions: string[]): Promise<boolean>;
  getAvailableRoles?(): Promise<{ id: string; name: string }[]>;
  getPermissionsForRole?(roleId: string): Promise<string[]>;
}

export interface IRBACManager<TUser = unknown> extends IRBACProvider<TUser> {
  assignRole(userId: string, roleId: string): Promise<void>;
  removeRole(userId: string, roleId: string): Promise<void>;
  listRoles(): Promise<RoleDefinition[]>;
  createRole?(role: RoleDefinition): Promise<void>;
  deleteRole?(roleId: string): Promise<void>;
}

export interface ResourceIdentifier {
  type: string;
  id: string;
}

export interface ACLGrant {
  subject: { type: 'user' | 'role'; id: string };
  resource: ResourceIdentifier;
  actions: string[];
  grantedAt: Date;
  grantedBy?: string;
}

export interface IACLProvider<TUser = unknown> {
  canAccess(user: TUser, resource: ResourceIdentifier, action: string): Promise<boolean>;
  listAccessible(user: TUser, resourceType: string, action: string): Promise<string[]>;
  filterAccessible<T extends { id: string }>(
    user: TUser,
    resources: T[],
    resourceType: string,
    action: string,
  ): Promise<T[]>;
}

export interface IACLManager<TUser = unknown> extends IACLProvider<TUser> {
  grant(subject: { type: 'user' | 'role'; id: string }, resource: ResourceIdentifier, actions: string[]): Promise<void>;
  revoke(
    subject: { type: 'user' | 'role'; id: string },
    resource: ResourceIdentifier,
    actions?: string[],
  ): Promise<void>;
  listGrants(resource: ResourceIdentifier): Promise<ACLGrant[]>;
  listGrantsForSubject(subject: { type: 'user' | 'role'; id: string }): Promise<ACLGrant[]>;
}

export interface FGACheckContext {
  resourceId?: string;
  requestContext?: { get?(key: string): unknown };
  metadata?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface FGACheckParams {
  resource: ResourceIdentifier;
  permission: MastraFGAPermissionInput | MastraFGAPermissionInput[];
  context?: FGACheckContext;
}

export interface FGARouteConfig {
  resourceType: string;
  resourceIdParam?: string;
  resourceId?:
    | string
    | ((params: Record<string, unknown>, context: { requestContext?: unknown }) => string | undefined);
  permission?: MastraFGAPermissionInput | MastraFGAPermissionInput[];
}

export interface FGARouteInfo {
  path: string;
  method: string;
  requiresAuth?: boolean;
  requiresPermission?: MastraFGAPermissionInput | MastraFGAPermissionInput[];
  fga?: FGARouteConfig;
}

export interface FGARouteResolverContext {
  route: FGARouteInfo;
  params: Record<string, unknown>;
  requestContext?: unknown;
}

export type FGARouteResolver = (
  context: FGARouteResolverContext,
) => FGARouteConfig | null | undefined | Promise<FGARouteConfig | null | undefined>;

export interface FGAResource {
  id: string;
  externalId: string;
  name: string;
  description?: string | null;
  resourceTypeSlug: string;
  organizationId: string;
  parentResourceId?: string | null;
}

export interface FGACreateResourceParams {
  externalId: string;
  name: string;
  description?: string | null;
  resourceTypeSlug: string;
  organizationId: string;
  parentResourceId?: string;
  parentResourceExternalId?: string;
  parentResourceTypeSlug?: string;
}

export interface FGAUpdateResourceParams {
  resourceId: string;
  name?: string;
  description?: string | null;
}

export interface FGADeleteResourceParams {
  resourceId?: string;
  externalId?: string;
  resourceTypeSlug?: string;
  organizationId?: string;
}

export interface FGARoleAssignment {
  id: string;
  role: { slug: string };
  resource: { id: string; externalId: string; resourceTypeSlug: string };
}

export interface FGARoleParams {
  organizationMembershipId: string;
  roleSlug: string;
  resourceId?: string;
  resourceExternalId?: string;
  resourceTypeSlug?: string;
}

export interface FGAListRoleAssignmentsOptions {
  organizationMembershipId: string;
  limit?: number;
  after?: string;
}

export interface FGAListResourcesOptions {
  organizationId?: string;
  resourceTypeSlug?: string;
  parentResourceId?: string;
  search?: string;
  limit?: number;
  after?: string;
}

export interface IFGAProvider<TUser = unknown> {
  requireForProtectedRoutes?: boolean;
  auditProtectedRoutes?: boolean | 'warn' | 'error';
  resolveRouteFGA?: FGARouteResolver;
  validatePermissions?: (permissions: MastraFGAPermissionInput[]) => void | Promise<void>;
  check?(user: TUser, params: FGACheckParams): Promise<boolean>;
  require?(user: TUser, params: FGACheckParams): Promise<void>;
  filterAccessible?<T extends { id: string }>(
    user: TUser,
    resources: T[],
    resourceType: string,
    permission: MastraFGAPermissionInput,
  ): Promise<T[]>;
  requireActor?(actor: ActorSignal, params: FGACheckParams): Promise<void>;
  [key: string]: unknown;
}

export interface IFGAManager<TUser = unknown> extends IFGAProvider<TUser> {
  createResource(params: FGACreateResourceParams): Promise<FGAResource>;
  getResource(resourceId: string): Promise<FGAResource>;
  listResources(options?: FGAListResourcesOptions): Promise<FGAResource[]>;
  updateResource(params: FGAUpdateResourceParams): Promise<FGAResource>;
  deleteResource(params: FGADeleteResourceParams): Promise<void>;
  assignRole(params: FGARoleParams): Promise<FGARoleAssignment>;
  removeRole(params: FGARoleParams): Promise<void>;
  listRoleAssignments(options: FGAListRoleAssignmentsOptions): Promise<FGARoleAssignment[]>;
}

/** Stable permission names used by core's built-in authorization checks. */
export const MastraFGAPermissions = {
  AGENTS_CREATE: 'agents:create',
  AGENTS_DELETE: 'agents:delete',
  AGENTS_EXECUTE: 'agents:execute',
  AGENTS_READ: 'agents:read',
  MEMORY_DELETE: 'memory:delete',
  MEMORY_READ: 'memory:read',
  MEMORY_WRITE: 'memory:write',
  TOOLS_EXECUTE: 'tools:execute',
  TOOLS_READ: 'tools:read',
  WORKFLOWS_EXECUTE: 'workflows:execute',
  WORKFLOWS_READ: 'workflows:read',
} as const;

export const PERMISSIONS = MastraFGAPermissions;
export const PERMISSION_PATTERNS: Record<string, string> = {};
export const RESOURCES: readonly string[] = [];
export const ACTIONS: readonly string[] = [];

export function isValidPermissionPattern(value: unknown): value is PermissionPattern {
  return typeof value === 'string' && value.length > 0;
}

export function validatePermissions(values: unknown[]): values is PermissionPattern[] {
  return values.every(isValidPermissionPattern);
}

/** Match the wildcard permission forms used by core authorization checks. */
export function matchesPermission(granted: string, required: string): boolean {
  if (granted === '*' || granted === required) return true;

  const grantedParts = granted.split(':');
  const requiredParts = required.split(':');
  if (grantedParts.length < 2 || requiredParts.length < 2) return false;

  let grantedResource = grantedParts[0]!;
  const grantedAction = grantedParts[1]!;
  const grantedId = grantedParts[2];
  const requiredResource = requiredParts[0]!;
  const requiredAction = requiredParts[1]!;
  const requiredId = requiredParts[2];

  // Keep the historical compound alias useful without depending on a generated
  // route permission registry that is not part of the OSS core package.
  if (grantedResource === 'stored' && requiredResource.startsWith('stored-')) {
    grantedResource = requiredResource;
  }

  if (grantedResource !== '*' && grantedResource !== requiredResource) return false;
  if (grantedAction !== '*' && grantedAction !== requiredAction) return false;
  if (grantedId === undefined) return true;
  return grantedId === requiredId;
}

export function hasPermission(granted: string[], required: string): boolean {
  return granted.some(permission => matchesPermission(permission, required));
}

export function resolvePermissionsFromMapping(roles: string[], mapping: RoleMapping = {}): string[] {
  const permissions = new Set<string>();
  const defaults = mapping['_default'] ?? [];

  for (const role of roles) {
    for (const permission of mapping[role] ?? defaults) permissions.add(permission);
  }

  return [...permissions];
}

export const DEFAULT_ROLES: RoleDefinition[] = [
  {
    id: 'owner',
    name: 'Owner',
    description: 'Full access to all features and settings',
    permissions: ['*'],
  },
  {
    id: 'admin',
    name: 'Admin',
    description: 'Manage agents, workflows, and team members',
    permissions: ['*:read', '*:write', '*:execute', '*:publish', '*:share'],
  },
  {
    id: 'member',
    name: 'Member',
    description: 'Execute agents and workflows',
    permissions: ['*:read', '*:execute'],
  },
  {
    id: 'viewer',
    name: 'Viewer',
    description: 'Read-only access',
    permissions: ['*:read'],
  },
];

export function getDefaultRole(roleId: string): RoleDefinition | undefined {
  return DEFAULT_ROLES.find(role => role.id === roleId);
}

export function resolvePermissions(roleIds: string[], roles: RoleDefinition[] = DEFAULT_ROLES): string[] {
  const permissions = new Set<string>();
  const visited = new Set<string>();
  const byId = new Map(roles.map(role => [role.id, role]));

  const visit = (roleId: string) => {
    if (visited.has(roleId)) return;
    visited.add(roleId);
    const role = byId.get(roleId);
    if (!role) return;
    for (const permission of role.permissions) permissions.add(permission);
    for (const inheritedRole of role.inherits ?? []) visit(inheritedRole);
  };

  for (const roleId of roleIds) visit(roleId);
  return [...permissions];
}

export interface StaticRBACProviderOptions<TUser = unknown> {
  roles?: RoleDefinition[];
  roleMapping?: RoleMapping;
  getUserRoles?: (user: TUser) => string[] | Promise<string[]>;
}

/** A small, in-memory RBAC provider useful for OSS applications and tests. */
export class StaticRBACProvider<TUser = EEUser> implements IRBACProvider<TUser> {
  readonly roleMapping?: RoleMapping;

  constructor(private readonly options: StaticRBACProviderOptions<TUser> = {}) {
    this.roleMapping = options.roleMapping;
  }

  async getRoles(user: TUser): Promise<string[]> {
    const providedRoles = await this.options.getUserRoles?.(user);
    if (providedRoles) return providedRoles;
    return (user as TUser & { roles?: string[] })?.roles ?? [];
  }

  async hasRole(user: TUser, role: string): Promise<boolean> {
    return (await this.getRoles(user)).includes(role);
  }

  async getPermissions(user: TUser): Promise<string[]> {
    const roles = await this.getRoles(user);
    if (this.roleMapping) return resolvePermissionsFromMapping(roles, this.roleMapping);
    return resolvePermissions(roles, this.options.roles ?? []);
  }

  async hasPermission(user: TUser, permission: string): Promise<boolean> {
    return hasPermission(await this.getPermissions(user), permission);
  }

  async hasAllPermissions(user: TUser, permissions: string[]): Promise<boolean> {
    const granted = await this.getPermissions(user);
    return permissions.every(permission => hasPermission(granted, permission));
  }

  async hasAnyPermission(user: TUser, permissions: string[]): Promise<boolean> {
    const granted = await this.getPermissions(user);
    return permissions.some(permission => hasPermission(granted, permission));
  }

  async getAvailableRoles(): Promise<{ id: string; name: string }[]> {
    if (this.options.roles) return this.options.roles.map(({ id, name }) => ({ id, name }));
    return Object.keys(this.roleMapping ?? {})
      .filter(role => role !== '_default')
      .map(id => ({ id, name: id }));
  }

  async getPermissionsForRole(roleId: string): Promise<string[]> {
    if (this.roleMapping) return resolvePermissionsFromMapping([roleId], this.roleMapping);
    return resolvePermissions([roleId], this.options.roles ?? []);
  }

  clearCache(): void {}

  getRoleDefinitions(): RoleDefinition[] {
    return this.options.roles ?? [];
  }

  getRoleDefinition(roleId: string): RoleDefinition | undefined {
    return this.options.roles?.find(role => role.id === roleId);
  }
}

function mergeFGAContext({
  context,
  requestContext,
  metadata,
}: Pick<RequireFGAOptions, 'context' | 'requestContext' | 'metadata'>): FGACheckContext | undefined {
  const mergedContext: FGACheckContext = { ...context };
  if (requestContext) mergedContext.requestContext = requestContext;
  if (metadata || context?.metadata) {
    mergedContext.metadata = { ...(context?.metadata ?? {}), ...(metadata ?? {}) };
  }
  return Object.keys(mergedContext).length > 0 ? mergedContext : undefined;
}

function isActorSignal(actor: unknown): actor is ActorSignal {
  if (actor === true) return true;
  if (typeof actor !== 'object' || actor === null) return false;
  const candidate = actor as { actorKind?: unknown; sourceWorkflow?: unknown };
  return (
    candidate.actorKind === 'system' &&
    (candidate.sourceWorkflow === undefined || typeof candidate.sourceWorkflow === 'string')
  );
}

export class FGADeniedError extends Error {
  readonly status = 403;

  constructor(
    public readonly user: unknown,
    public readonly resource: ResourceIdentifier,
    public readonly permission: MastraFGAPermissionInput | MastraFGAPermissionInput[],
    reason?: string,
  ) {
    const userId =
      user && typeof user === 'object' && 'id' in user
        ? String((user as { id?: unknown }).id)
        : user && typeof user === 'object' && 'workosId' in user
          ? String((user as { workosId?: unknown }).workosId)
          : 'unknown';
    const permissionLabel = Array.isArray(permission) ? `any of [${permission.join(', ')}]` : permission;
    super(
      reason
        ? `FGA authorization denied: ${reason}`
        : `FGA authorization denied: user ${userId} cannot ${permissionLabel} on ${resource.type}:${resource.id}`,
    );
    this.name = 'FGADeniedError';
  }
}

export interface CheckFGAOptions extends FGACheckParams {
  fgaProvider?: IFGAProvider;
  user: unknown;
  actor?: ActorSignal;
  requestContext?: FGACheckContext['requestContext'];
  metadata?: Record<string, unknown>;
}

export type RequireFGAOptions = CheckFGAOptions;

/** Delegate authorization to an application-provided provider. */
export async function requireFGA(options: RequireFGAOptions): Promise<void> {
  const { fgaProvider, user, resource, permission, context, requestContext, metadata, actor } = options;
  if (!fgaProvider) return;

  const fgaContext = mergeFGAContext({ context, requestContext, metadata });
  const params = fgaContext ? { resource, permission, context: fgaContext } : { resource, permission };

  if (isActorSignal(actor)) {
    if (fgaProvider.requireActor) await fgaProvider.requireActor(actor, params);
    return;
  }

  if (!user) throw new FGADeniedError(user, resource, permission, 'authenticated user is required');
  if (fgaProvider.require) {
    await fgaProvider.require(user, params);
    return;
  }
  if (fgaProvider.check) {
    if (!(await fgaProvider.check(user, params))) throw new FGADeniedError(user, resource, permission);
    return;
  }
  throw new FGADeniedError(user, resource, permission, 'configured FGA provider has no check method');
}

export const checkFGA = requireFGA;
export const getAgentFGAResourceId = (id: string) => id;
export const getWorkflowFGAResourceId = (id: string) => id;
export const getStandaloneToolFGAResourceId = (id: string) => id;
export const getAgentToolFGAResourceId = (agentId: string, toolName: string) => `${agentId}:${toolName}`;
export const getMCPToolFGAResourceId = (serverName: string, toolName: string) => JSON.stringify([serverName, toolName]);

export interface LicenseInfo {
  valid: boolean;
  expiresAt?: Date;
  features?: string[];
  organization?: string;
  tier?: string;
}

export interface SafeLicenseSummary {
  valid: boolean;
  isDevEnvironment: boolean;
  licenseHash?: string;
  anonymousId?: string;
  features?: string[];
  tier?: string;
}

/** OSS compatibility never contacts a license service; it only preserves startup guards. */
function configuredLicenseKey(): string | undefined {
  return process.env['MASTRA_LICENSE_KEY'] || process.env['MASTRA_EE_LICENSE'];
}

export function isDevEnvironment(): boolean {
  const mastraDev = process.env['MASTRA_DEV'];
  const nodeEnv = process.env['NODE_ENV'];
  return mastraDev === 'true' || mastraDev === '1' || !['production', 'prod'].includes(nodeEnv ?? '');
}

export function isLicenseValid(): boolean {
  return Boolean(configuredLicenseKey());
}

export const isEELicenseValid = isLicenseValid;

export function isEEEnabled(): boolean {
  return isDevEnvironment() || isLicenseValid();
}

export function isFeatureEnabled(_feature: string): boolean {
  return isLicenseValid();
}

export function clearLicenseCache(): void {}
export function warnIfDevEENeedsLicense(): void {}
export function startLicenseValidation(): Promise<boolean> {
  return Promise.resolve(isEEEnabled());
}

export function validateLicense(licenseKey: string | undefined = configuredLicenseKey()): LicenseInfo {
  return { valid: isDevEnvironment() || Boolean(licenseKey) };
}

export function getSafeLicenseSummary(): SafeLicenseSummary {
  return { valid: isEEEnabled(), isDevEnvironment: isDevEnvironment() };
}

interface LoginButtonConfig {
  provider: string;
  text: string;
  icon?: string;
  description?: string;
}

export interface PublicAuthCapabilities {
  enabled: boolean;
  login: {
    type: 'sso' | 'credentials' | 'both';
    signUpEnabled?: boolean;
    description?: string;
    sso?: LoginButtonConfig & { url: string };
  } | null;
}

export interface AuthenticatedUser extends User {
  [key: string]: unknown;
}

export interface CapabilityFlags {
  user: boolean;
  session: boolean;
  sso: boolean;
  rbac: boolean;
  acl: boolean;
  fga: boolean;
}

export interface UserAccess {
  roles: string[];
  permissions: string[];
}

export interface AuthenticatedCapabilities extends PublicAuthCapabilities {
  user: AuthenticatedUser;
  capabilities: CapabilityFlags;
  access: UserAccess | null;
  availableRoles?: { id: string; name: string }[];
}

export type AuthCapabilities = PublicAuthCapabilities | AuthenticatedCapabilities;

export function isAuthenticated(caps: AuthCapabilities): caps is AuthenticatedCapabilities {
  return 'user' in caps && caps.user != null;
}

export interface BuildCapabilitiesOptions {
  rbac?: IRBACProvider;
  fga?: IFGAProvider;
  apiPrefix?: string;
}

type AuthCapabilitiesProvider = {
  getLoginButtonConfig?: () => LoginButtonConfig;
  getLoginUrl?: (redirectUri: string, state: string) => string | Promise<string>;
  getCurrentUser?: (request: Request) => Promise<unknown>;
  signIn?: (...args: unknown[]) => unknown;
  isSignUpEnabled?: () => boolean;
  createSession?: (...args: unknown[]) => unknown;
  canAccess?: (...args: unknown[]) => unknown;
};

/** Build the non-enterprise authentication capabilities exposed to Studio. */
export async function buildCapabilities(
  auth: AuthCapabilitiesProvider | null | undefined,
  request: Request,
  options: BuildCapabilitiesOptions = {},
): Promise<AuthCapabilities> {
  if (!auth) return { enabled: false, login: null };

  const loginConfig = auth.getLoginButtonConfig?.();
  const hasSSO = Boolean(loginConfig && auth.getLoginUrl);
  const hasCredentials = typeof auth.signIn === 'function';
  const signUpEnabled = auth.isSignUpEnabled?.() ?? true;
  const loginUrl = hasSSO ? await auth.getLoginUrl!(request.url, '') : '';
  const login = hasSSO
    ? {
        type: hasCredentials ? ('both' as const) : ('sso' as const),
        ...(hasCredentials ? { signUpEnabled } : {}),
        ...(loginConfig?.description ? { description: loginConfig.description } : {}),
        sso: { ...loginConfig!, url: loginUrl },
      }
    : hasCredentials
      ? { type: 'credentials' as const, signUpEnabled }
      : null;

  let user: unknown = null;
  if (auth.getCurrentUser) {
    try {
      user = await auth.getCurrentUser(request);
    } catch {
      user = null;
    }
  }
  if (!user) return { enabled: true, login };

  let access: UserAccess | null = null;
  let availableRoles: { id: string; name: string }[] | undefined;
  if (options.rbac) {
    try {
      const roles = await options.rbac.getRoles(user);
      const permissions = await options.rbac.getPermissions(user);
      access = { roles, permissions };
      if (options.rbac.getAvailableRoles) availableRoles = await options.rbac.getAvailableRoles();
    } catch {
      access = null;
    }
  }

  return {
    enabled: true,
    login,
    user: user as AuthenticatedUser,
    capabilities: {
      user: Boolean(auth.getCurrentUser),
      session: typeof auth.createSession === 'function',
      sso: hasSSO,
      rbac: Boolean(options.rbac),
      acl: typeof auth.canAccess === 'function',
      fga: Boolean(options.fga),
    },
    access,
    ...(availableRoles ? { availableRoles } : {}),
  };
}
