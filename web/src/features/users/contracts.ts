import type { SelfPasswordChangeResult, UserRole } from '../../api/types';

export interface ManagedUser {
  id: number;
  username: string;
  role: UserRole;
  enabled: boolean;
  lock_until_seconds: number | null;
  created_at_seconds: number;
  password_changed_at_seconds: number;
  last_login_at_seconds: number | null;
}

export interface ManagedUserList {
  users: ManagedUser[];
}

export interface ManagedUserCreateResult {
  user: ManagedUser;
}

export interface ManagementIp {
  id: number;
  address: string;
  role: UserRole;
  created_at_seconds: number;
}

export interface ManagementIpList {
  management_ips: ManagementIp[];
  current_peer_ip: string;
}

export interface ManagementIpCreateResult {
  management_ip: ManagementIp;
}

export interface UpdatedResult {
  updated: true;
}

export interface PasswordResetResult {
  password_reset: true;
}

export interface DeletedResult {
  deleted: true;
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const hasExactKeys = (
  value: unknown,
  keys: readonly string[],
): value is Record<string, unknown> => isRecord(value) &&
  Object.keys(value).length === keys.length &&
  keys.every((key) => Object.prototype.hasOwnProperty.call(value, key));

const isNonemptyString = (value: unknown): value is string =>
  typeof value === 'string' && value.length > 0;

const isSafePositiveInteger = (value: unknown): value is number =>
  Number.isSafeInteger(value) && (value as number) > 0;

const isSafeNonnegativeInteger = (value: unknown): value is number =>
  Number.isSafeInteger(value) && (value as number) >= 0;

const isUserRole = (value: unknown): value is UserRole =>
  value === 'administrator' || value === 'viewer';

function invalidManagedUser(): never {
  throw new Error('Invalid managed user response');
}

function invalidManagementIp(): never {
  throw new Error('Invalid management IP response');
}

function invalidResult(): never {
  throw new Error('Invalid user management response');
}

function isNullableTimestamp(value: unknown): value is number | null {
  return value === null || isSafeNonnegativeInteger(value);
}

function parseManagedUser(value: unknown): ManagedUser {
  if (!hasExactKeys(value, [
    'id', 'username', 'role', 'enabled', 'lock_until_seconds',
    'created_at_seconds', 'password_changed_at_seconds', 'last_login_at_seconds',
  ]) || !isSafePositiveInteger(value.id) || !isNonemptyString(value.username) ||
      !isUserRole(value.role) || typeof value.enabled !== 'boolean' ||
      !isNullableTimestamp(value.lock_until_seconds) ||
      !isSafeNonnegativeInteger(value.created_at_seconds) ||
      !isSafeNonnegativeInteger(value.password_changed_at_seconds) ||
      !isNullableTimestamp(value.last_login_at_seconds)) {
    return invalidManagedUser();
  }
  return {
    id: value.id,
    username: value.username,
    role: value.role,
    enabled: value.enabled,
    lock_until_seconds: value.lock_until_seconds,
    created_at_seconds: value.created_at_seconds,
    password_changed_at_seconds: value.password_changed_at_seconds,
    last_login_at_seconds: value.last_login_at_seconds,
  };
}

function parseManagementIp(value: unknown): ManagementIp {
  if (!hasExactKeys(value, ['id', 'address', 'role', 'created_at_seconds']) ||
      !isSafePositiveInteger(value.id) || !isNonemptyString(value.address) ||
      !isUserRole(value.role) || !isSafeNonnegativeInteger(value.created_at_seconds)) {
    return invalidManagementIp();
  }
  return {
    id: value.id,
    address: value.address,
    role: value.role,
    created_at_seconds: value.created_at_seconds,
  };
}

export function parseManagedUserList(value: unknown): ManagedUserList {
  if (!hasExactKeys(value, ['users']) || !Array.isArray(value.users)) {
    return invalidManagedUser();
  }
  return { users: value.users.map(parseManagedUser) };
}

export function parseManagedUserCreateResult(value: unknown): ManagedUserCreateResult {
  if (!hasExactKeys(value, ['user'])) {
    return invalidManagedUser();
  }
  return { user: parseManagedUser(value.user) };
}

export function parseManagementIpList(value: unknown): ManagementIpList {
  if (!hasExactKeys(value, ['management_ips', 'current_peer_ip']) ||
      !Array.isArray(value.management_ips) || !isNonemptyString(value.current_peer_ip)) {
    return invalidManagementIp();
  }
  return {
    management_ips: value.management_ips.map(parseManagementIp),
    current_peer_ip: value.current_peer_ip,
  };
}

export function parseManagementIpCreateResult(value: unknown): ManagementIpCreateResult {
  if (!hasExactKeys(value, ['management_ip'])) {
    return invalidManagementIp();
  }
  return { management_ip: parseManagementIp(value.management_ip) };
}

export function parseUpdatedResult(value: unknown): UpdatedResult {
  if (!hasExactKeys(value, ['updated']) || value.updated !== true) {
    return invalidResult();
  }
  return { updated: true };
}

export function parsePasswordResetResult(value: unknown): PasswordResetResult {
  if (!hasExactKeys(value, ['password_reset']) || value.password_reset !== true) {
    return invalidResult();
  }
  return { password_reset: true };
}

export function parseDeletedResult(value: unknown): DeletedResult {
  if (!hasExactKeys(value, ['deleted']) || value.deleted !== true) {
    return invalidResult();
  }
  return { deleted: true };
}

export function parseSelfPasswordChangeResult(value: unknown): SelfPasswordChangeResult {
  if (!hasExactKeys(value, ['password_changed', 'logged_out']) ||
      value.password_changed !== true || value.logged_out !== true) {
    return invalidResult();
  }
  return { password_changed: true, logged_out: true };
}
