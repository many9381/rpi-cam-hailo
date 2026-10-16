import { describe, expect, it } from 'vitest';

import {
  parseDeletedResult,
  parseManagementIpCreateResult,
  parseManagementIpList,
  parseManagementIpPolicy,
  parseManagedUserCreateResult,
  parseManagedUserList,
  parsePasswordResetResult,
  parseSelfPasswordChangeResult,
  parseUpdatedResult,
} from './contracts';

const user = {
  id: 7,
  username: 'viewer.one',
  role: 'viewer',
  enabled: true,
  lock_until_seconds: null,
  created_at_seconds: 100,
  password_changed_at_seconds: 101,
  last_login_at_seconds: null,
} as const;

const managementIp = {
  id: 8,
  address: '192.0.2.10',
  role: 'administrator',
  created_at_seconds: 102,
} as const;

function expectRejectedWithoutEcho(
  parser: (value: unknown) => unknown,
  value: unknown,
  message: string,
): void {
  let error: unknown;
  try {
    parser(value);
  } catch (caught) {
    error = caught;
  }

  expect(error).toBeInstanceOf(Error);
  expect((error as Error).message).toBe(message);
  expect((error as Error).message).not.toContain('viewer-secret');
}

describe('managed user contracts', () => {
  it('parses exact list and create wrappers into fresh public values', () => {
    const list = { users: [user] };
    const create = { user };

    const parsedList = parseManagedUserList(list);
    const parsedCreate = parseManagedUserCreateResult(create);

    expect(parsedList).toEqual(list);
    expect(parsedList).not.toBe(list);
    expect(parsedList.users).not.toBe(list.users);
    expect(parsedList.users[0]).not.toBe(user);
    expect(parsedCreate).toEqual(create);
    expect(parsedCreate).not.toBe(create);
    expect(parsedCreate.user).not.toBe(user);
  });

  it.each([
    ['unknown list field', () => ({ users: [user], password: 'viewer-secret' })],
    ['unknown user field', () => ({ users: [{ ...user, hash: 'viewer-secret' }] })],
    ['missing user field', () => ({ users: [{ ...user, enabled: undefined }] })],
    ['invalid user id', () => ({ users: [{ ...user, id: 0 }] })],
    ['unsafe user id', () => ({ users: [{ ...user, id: Number.MAX_SAFE_INTEGER + 1 }] })],
    ['unsupported role', () => ({ users: [{ ...user, role: 'operator' }] })],
    ['negative timestamp', () => ({ users: [{ ...user, created_at_seconds: -1 }] })],
    ['fractional timestamp', () => ({ users: [{ ...user, password_changed_at_seconds: 1.5 }] })],
    ['invalid nullable timestamp', () => ({ users: [{ ...user, last_login_at_seconds: 'never' }] })],
  ])('rejects %s without echoing rejected data', (_name, makeValue) => {
    expectRejectedWithoutEcho(
      parseManagedUserList,
      makeValue(),
      'Invalid managed user response',
    );
  });
});

describe('management IP contracts', () => {
  it('parses exact list and create wrappers into fresh public values', () => {
    const list = {
      management_ips: [managementIp],
      current_peer_ip: '192.0.2.44',
    };
    const create = { management_ip: managementIp };

    const parsedList = parseManagementIpList(list);
    const parsedCreate = parseManagementIpCreateResult(create);

    expect(parsedList).toEqual(list);
    expect(parsedList).not.toBe(list);
    expect(parsedList.management_ips).not.toBe(list.management_ips);
    expect(parsedList.management_ips[0]).not.toBe(managementIp);
    expect(parsedCreate).toEqual(create);
    expect(parsedCreate).not.toBe(create);
    expect(parsedCreate.management_ip).not.toBe(managementIp);
  });

  it.each([
    ['missing peer', () => ({ management_ips: [managementIp] })],
    ['empty peer', () => ({ management_ips: [managementIp], current_peer_ip: '' })],
    ['non-string peer', () => ({ management_ips: [managementIp], current_peer_ip: 44 })],
    ['unknown wrapper field', () => ({
      management_ips: [managementIp], current_peer_ip: '192.0.2.44', salt: 'viewer-secret',
    })],
    ['unknown IP field', () => ({ management_ips: [{ ...managementIp, password: 'viewer-secret' }], current_peer_ip: '192.0.2.44' })],
    ['empty address', () => ({ management_ips: [{ ...managementIp, address: '' }], current_peer_ip: '192.0.2.44' })],
    ['invalid IP id', () => ({ management_ips: [{ ...managementIp, id: -1 }], current_peer_ip: '192.0.2.44' })],
    ['unsupported role', () => ({ management_ips: [{ ...managementIp, role: 'operator' }], current_peer_ip: '192.0.2.44' })],
    ['negative timestamp', () => ({ management_ips: [{ ...managementIp, created_at_seconds: -1 }], current_peer_ip: '192.0.2.44' })],
  ])('rejects %s without echoing rejected data', (_name, makeValue) => {
    expectRejectedWithoutEcho(
      parseManagementIpList,
      makeValue(),
      'Invalid management IP response',
    );
  });
});

describe('user-management mutation contracts', () => {
  it('accepts only the authoritative exact result wrappers', () => {
    expect(parseUpdatedResult({ updated: true })).toEqual({ updated: true });
    expect(parsePasswordResetResult({ password_reset: true }))
      .toEqual({ password_reset: true });
    expect(parseDeletedResult({ deleted: true })).toEqual({ deleted: true });
    expect(parseSelfPasswordChangeResult({ password_changed: true, logged_out: true }))
      .toEqual({ password_changed: true, logged_out: true });
  });

  it.each([
    [parseUpdatedResult, { updated: true, password: 'viewer-secret' }],
    [parsePasswordResetResult, { password_reset: false }],
    [parseDeletedResult, { deleted: true, hash: 'viewer-secret' }],
    [parseSelfPasswordChangeResult, { password_changed: true, logged_out: false }],
  ])('rejects malformed mutation result without echoing rejected data', (parser, value) => {
    expectRejectedWithoutEcho(parser, value, 'Invalid user management response');
  });
});

describe('management IP policy contract', () => {
  it.each([true, false])('preserves the server policy value %s', (enabled) => {
    expect(parseManagementIpPolicy({ enabled })).toEqual({ enabled });
  });

  it.each([null, {}, { enabled: 'false' }, { enabled: 0 }, { enabled: true, unknown: true }])(
    'rejects malformed policy instead of defaulting its enabled state: %j', (value) => {
      expect(() => parseManagementIpPolicy(value)).toThrow('Invalid management IP policy response');
    },
  );
});
