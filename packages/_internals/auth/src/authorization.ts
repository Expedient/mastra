import type { User } from './index';

export type PermissionPattern = string;
export type MastraFGAPermission = string;
export type MastraFGAPermissionInput = string;
export type ActorSignal = true | { actorKind: 'system'; sourceWorkflow?: string };

export interface EEUser extends User {
  roles?: string[];
  permissions?: string[];
  organizationId?: string;
  organizationMembershipId?: string;
}

export type RoleMapping = Record<string, PermissionPattern[]>;
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
  getAvailableRoles?: () => Promise<{ id: string; name: string }[]>;
  getPermissionsForRole?: (roleId: string) => Promise<string[]>;
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
export type IACLProvider<TUser = unknown> = Record<string, unknown>;
export type IACLManager<TUser = unknown> = IACLProvider<TUser>;
export type ResourceIdentifier = { type: string; id: string };
export type ACLGrant = Record<string, unknown>;

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
  resourceId?: string | ((params: Record<string, unknown>, context: { requestContext?: unknown }) => string | undefined);
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

const permissionValue = (key: string) => key.toLowerCase().replaceAll('_', ':');
export const MastraFGAPermissions: Record<string, string> = new Proxy(
  {},
  { get: (_target, key) => permissionValue(String(key)) },
);
export const PERMISSIONS = MastraFGAPermissions;
export const PERMISSION_PATTERNS: Record<string, string> = {};
export const RESOURCES: readonly string[] = [];
export const ACTIONS: readonly string[] = [];

export function isValidPermissionPattern(value: unknown): value is PermissionPattern {
  return typeof value === 'string' && value.length > 0;
}
export function validatePermissions(values: unknown[]): PermissionPattern[] {
  return values.filter(isValidPermissionPattern);
}
export function matchesPermission(granted: string, required: string): boolean {
  if (granted === '*' || granted === required) return true;
  if (granted.endsWith(':*')) return required.startsWith(granted.slice(0, -1));
  return false;
}
export function hasPermission(granted: string[], required: string): boolean {
  return granted.some(permission => matchesPermission(permission, required));
}
export function resolvePermissionsFromMapping(roles: string[], mapping: RoleMapping = {}): string[] {
  return [...new Set(roles.flatMap(role => mapping[role] ?? mapping._default ?? []))];
}

export class StaticRBACProvider<TUser extends { roles?: string[] } = EEUser> implements IRBACProvider<TUser> {
  readonly roleMapping?: RoleMapping;

  constructor(
    private readonly options: {
      roles?: RoleDefinition[];
      roleMapping?: RoleMapping;
      getUserRoles?: (user: TUser) => string[] | Promise<string[]>;
    } = {},
  ) {
    this.roleMapping = options.roleMapping;
  }
  async getRoles(user: TUser): Promise<string[]> {
    return (await this.options.getUserRoles?.(user)) ?? user.roles ?? [];
  }
  async hasRole(user: TUser, role: string): Promise<boolean> {
    return (await this.getRoles(user)).includes(role);
  }
  async getPermissions(user: TUser): Promise<string[]> {
    const roles = await this.getRoles(user);
    if (this.roleMapping) return resolvePermissionsFromMapping(roles, this.roleMapping);
    const definitions = new Map((this.options.roles ?? []).map(role => [role.id, role.permissions]));
    return [...new Set(roles.flatMap(role => definitions.get(role) ?? []))];
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
    return (this.options.roles ?? []).map(({ id, name }) => ({ id, name }));
  }
  async getPermissionsForRole(roleId: string): Promise<string[]> {
    return this.options.roles?.find(role => role.id === roleId)?.permissions ?? [];
  }
}

export const DEFAULT_ROLES: RoleDefinition[] = [];

export class FGADeniedError extends Error {
  readonly status = 403;
  constructor(
    public readonly user: unknown,
    public readonly resource: { type: string; id: string },
    public readonly permission: MastraFGAPermissionInput | MastraFGAPermissionInput[],
    reason = 'commercial FGA is unavailable in this fork',
  ) {
    super(`FGA authorization denied: ${reason}`);
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
export async function requireFGA(options: RequireFGAOptions): Promise<void> {
  if (!options.fgaProvider) return;
  throw new FGADeniedError(options.user, options.resource, options.permission);
}
export const checkFGA = requireFGA;
export const getAgentFGAResourceId = (id: string) => id;
export const getWorkflowFGAResourceId = (id: string) => id;
export const getStandaloneToolFGAResourceId = (id: string) => id;
export const getAgentToolFGAResourceId = (agentId: string, toolName: string) => `${agentId}:${toolName}`;
export const getMCPToolFGAResourceId = (serverName: string, toolName: string) => JSON.stringify([serverName, toolName]);

export function isEEEnabled(): boolean {
  return false;
}
export function isLicenseValid(): boolean {
  return false;
}
export const isEELicenseValid = isLicenseValid;
export function isFeatureEnabled(_feature: string): boolean {
  return false;
}
export function isDevEnvironment(): boolean {
  return false;
}
export function clearLicenseCache(): void {}
export function warnIfDevEENeedsLicense(): void {}
export function startLicenseValidation(): Promise<boolean> {
  return Promise.resolve(false);
}
export function validateLicense(): { valid: false } {
  return { valid: false };
}
export function getSafeLicenseSummary() {
  return { valid: false, isDevEnvironment: false };
}

export async function buildCapabilities(auth: any, request: Request) {
  if (!auth) return { enabled: false, login: null };
  const loginConfig = typeof auth.getLoginButtonConfig === 'function' ? auth.getLoginButtonConfig() : undefined;
  const user = typeof auth.getCurrentUser === 'function' ? await auth.getCurrentUser(request) : null;
  const login = loginConfig
    ? {
        type: 'sso' as const,
        sso: {
          ...loginConfig,
          url: typeof auth.getLoginUrl === 'function' ? await auth.getLoginUrl(request.url, '') : '',
        },
      }
    : null;
  if (!user) return { enabled: true, login };
  return {
    enabled: true,
    login,
    user,
    capabilities: { user: true, session: false, sso: Boolean(loginConfig), rbac: false, acl: false, fga: false },
    access: { roles: [], permissions: [] },
  };
}
