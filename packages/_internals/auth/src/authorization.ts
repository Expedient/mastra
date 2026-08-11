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

export type ResourceIdentifier = { type: string; id: string };

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

const STORED_RESOURCE_FAMILIES = new Set([
  'stored-agents',
  'stored-mcp-clients',
  'stored-prompt-blocks',
  'stored-scorers',
  'stored-skills',
  'stored-workspaces',
]);

type PermissionParts = { resource: string; action: string; id?: string };

function parsePermission(permission: string): PermissionParts | undefined {
  const [resource, action, ...idParts] = permission.split(':');
  if (!resource || !action) return undefined;
  return { resource, action, ...(idParts.length > 0 ? { id: idParts.join(':') } : {}) };
}

export function matchesPermission(granted: string, required: string): boolean {
  if (granted === '*' || granted === required) return true;

  const grantedParts = parsePermission(granted);
  const requiredParts = parsePermission(required);
  if (!grantedParts || !requiredParts) return false;

  const resourceMatches =
    grantedParts.resource === '*' ||
    grantedParts.resource === requiredParts.resource ||
    (grantedParts.resource === 'stored' && STORED_RESOURCE_FAMILIES.has(requiredParts.resource));
  if (!resourceMatches) return false;

  if (grantedParts.action !== '*' && grantedParts.action !== requiredParts.action) return false;
  return grantedParts.id === undefined || grantedParts.id === requiredParts.id;
}

export function hasPermission(granted: string[], required: string): boolean {
  return granted.some(permission => matchesPermission(permission, required));
}

export function resolvePermissionsFromMapping(roles: string[], mapping: RoleMapping = {}): string[] {
  const resolved = new Set<string>();
  for (const role of roles) {
    for (const permission of mapping[role] ?? mapping._default ?? []) resolved.add(permission);
  }
  return [...resolved];
}

export class FGADeniedError extends Error {
  readonly status = 403;

  constructor(
    public readonly user: unknown,
    public readonly resource: ResourceIdentifier,
    public readonly permission: MastraFGAPermissionInput | MastraFGAPermissionInput[],
    reason = 'permission denied',
  ) {
    super(`FGA authorization denied: ${reason}`);
    this.name = 'FGADeniedError';
  }
}
