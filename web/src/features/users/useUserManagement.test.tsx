import { act, renderHook, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

import type { CameraApiClient, Parser, UserRole } from '../../api/types';
import {
  parseDeletedResult,
  parseManagedUserCreateResult,
  parseManagementIpCreateResult,
  parsePasswordResetResult,
  parseUpdatedResult,
  type ManagedUserList,
  type ManagementIp,
  type ManagementIpList,
} from './contracts';
import { useUserManagement } from './useUserManagement';

const rawUser = (id: number, username = `viewer.${id}`) => ({
  id,
  username,
  role: 'viewer' as const,
  enabled: true,
  lock_until_seconds: null,
  created_at_seconds: 100 + id,
  password_changed_at_seconds: 200 + id,
  last_login_at_seconds: null,
});

const rawUsers = (...ids: number[]) => ({ users: ids.map((id) => rawUser(id)) });

const rawIp = (id: number, role: UserRole = 'administrator') => ({
  id,
  address: `192.0.2.${id}`,
  role,
  created_at_seconds: 300 + id,
});

const rawIps = (...entries: Array<ReturnType<typeof rawIp>>) => ({
  management_ips: entries,
  current_peer_ip: '192.0.2.254',
});

const deferred = <T,>() => {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
};

const parseWith = <T,>(parser: Parser<T>, value: unknown): T => parser(value);

const makeClient = (): CameraApiClient => ({
  getJson: vi.fn(async (path: string, parser: Parser<unknown>) =>
    parseWith(parser, path === '/api/v1/security/users'
      ? rawUsers(1)
      : rawIps(rawIp(1))),
  ) as CameraApiClient['getJson'],
  deleteJson: vi.fn(async (_path: string, parser: Parser<unknown>) =>
    parseWith(parser, { deleted: true }),
  ) as CameraApiClient['deleteJson'],
  putJson: vi.fn(async (path: string, _body: unknown, parser: Parser<unknown>) =>
    parseWith(parser, path.endsWith('/password')
      ? { password_reset: true }
      : { updated: true }),
  ) as CameraApiClient['putJson'],
  postJson: vi.fn(async (path: string, _body: unknown, parser: Parser<unknown>) =>
    parseWith(parser, path === '/api/v1/security/users'
      ? { user: rawUser(2) }
      : { management_ip: rawIp(2) }),
  ) as CameraApiClient['postJson'],
  getBlob: vi.fn(),
  setUnauthorizedHandler: vi.fn(),
});

const waitUntilReady = async (
  result: { current: ReturnType<typeof useUserManagement> },
) => {
  await waitFor(() => {
    expect(result.current.users.status).toBe('ready');
    expect(result.current.managementIps.status).toBe('ready');
  });
};

describe('useUserManagement', () => {
  it('loads users and management IPs concurrently with independent status', async () => {
    const client = makeClient();
    const users = deferred<ManagedUserList>();
    const ips = deferred<ManagementIpList>();
    vi.mocked(client.getJson).mockImplementation((path, parser) => {
      if (path === '/api/v1/security/users') {
        return users.promise.then((value) => parser(value));
      }
      return ips.promise.then((value) => parser(value));
    });

    const { result } = renderHook(() => useUserManagement(client));

    expect(client.getJson).toHaveBeenCalledTimes(2);
    expect(client.getJson).toHaveBeenCalledWith(
      '/api/v1/security/users', expect.any(Function), expect.any(AbortSignal),
    );
    expect(client.getJson).toHaveBeenCalledWith(
      '/api/v1/security/management-ips', expect.any(Function), expect.any(AbortSignal),
    );
    expect(result.current.users.status).toBe('loading');
    expect(result.current.managementIps.status).toBe('loading');

    await act(async () => {
      users.resolve(rawUsers(3));
      await users.promise;
    });
    expect(result.current.users.status).toBe('ready');
    expect(result.current.users.data.map(({ id }) => id)).toEqual([3]);
    expect(result.current.managementIps.status).toBe('loading');

    await act(async () => {
      ips.resolve(rawIps(rawIp(4, 'viewer')));
      await ips.promise;
    });
    expect(result.current.managementIps.status).toBe('ready');
    expect(result.current.managementIps.data.management_ips[0]?.id).toBe(4);
  });

  it('keeps users ready when the initial IP request fails', async () => {
    const client = makeClient();
    vi.mocked(client.getJson).mockImplementation(async (path, parser) => {
      if (path === '/api/v1/security/users') {
        return parser(rawUsers(1));
      }
      throw new Error('IP service unavailable');
    });

    const { result } = renderHook(() => useUserManagement(client));

    await waitFor(() => expect(result.current.managementIps.status).toBe('error'));
    expect(result.current.users.status).toBe('ready');
    expect(result.current.users.data.map(({ id }) => id)).toEqual([1]);
    expect(result.current.users.error).toBeNull();
    expect(result.current.managementIps.error).toEqual(
      new Error('IP service unavailable'),
    );
  });

  it('aborts superseded refreshes and ignores their late completions', async () => {
    const client = makeClient();
    const { result } = renderHook(() => useUserManagement(client));
    await waitUntilReady(result);
    const older = deferred<ManagedUserList>();
    const newer = deferred<ManagedUserList>();
    vi.mocked(client.getJson)
      .mockImplementationOnce((_path, parser) => older.promise.then(parser))
      .mockImplementationOnce((_path, parser) => newer.promise.then(parser));

    let olderRefresh!: Promise<void>;
    let newerRefresh!: Promise<void>;
    act(() => {
      olderRefresh = result.current.refreshUsers();
      newerRefresh = result.current.refreshUsers();
    });
    const getCalls = vi.mocked(client.getJson).mock.calls;
    const olderSignal = getCalls[getCalls.length - 2]?.[2];
    const newerSignal = getCalls[getCalls.length - 1]?.[2];
    expect(olderSignal?.aborted).toBe(true);
    expect(newerSignal?.aborted).toBe(false);

    await act(async () => {
      newer.resolve(rawUsers(9));
      await newerRefresh;
    });
    await act(async () => {
      older.resolve(rawUsers(8));
      await olderRefresh;
    });

    expect(result.current.users.status).toBe('ready');
    expect(result.current.users.data.map(({ id }) => id)).toEqual([9]);
    expect(result.current.users.error).toBeNull();
  });

  it('posts an exact viewer body then refreshes only users', async () => {
    const client = makeClient();
    const { result } = renderHook(() => useUserManagement(client));
    await waitUntilReady(result);
    const usersGetCount = vi.mocked(client.getJson).mock.calls
      .filter(([path]) => path === '/api/v1/security/users').length;
    const ipGetCount = vi.mocked(client.getJson).mock.calls
      .filter(([path]) => path === '/api/v1/security/management-ips').length;

    let commandResult!: { refreshed: boolean };
    await act(async () => {
      commandResult = await result.current.createViewer('viewer.one', 'ViewerPass9!');
    });

    expect(client.postJson).toHaveBeenCalledWith(
      '/api/v1/security/users',
      { username: 'viewer.one', password: 'ViewerPass9!' },
      parseManagedUserCreateResult,
      expect.any(AbortSignal),
    );
    expect(commandResult).toEqual({ refreshed: true });
    expect(vi.mocked(client.getJson).mock.calls
      .filter(([path]) => path === '/api/v1/security/users')).toHaveLength(usersGetCount + 1);
    expect(vi.mocked(client.getJson).mock.calls
      .filter(([path]) => path === '/api/v1/security/management-ips')).toHaveLength(ipGetCount);
  });

  it('puts enabled and password commands on their exact viewer paths', async () => {
    const client = makeClient();
    const { result } = renderHook(() => useUserManagement(client));
    await waitUntilReady(result);

    await act(async () => {
      await result.current.setViewerEnabled(17, false);
      await result.current.resetViewerPassword(17, 'Replacement9!');
    });

    expect(client.putJson).toHaveBeenNthCalledWith(
      1,
      '/api/v1/security/users/17/enabled',
      { enabled: false },
      parseUpdatedResult,
      expect.any(AbortSignal),
    );
    expect(client.putJson).toHaveBeenNthCalledWith(
      2,
      '/api/v1/security/users/17/password',
      { password: 'Replacement9!' },
      parsePasswordResetResult,
      expect.any(AbortSignal),
    );
  });

  it('deletes a viewer with no JSON body then refreshes users', async () => {
    const client = makeClient();
    const { result } = renderHook(() => useUserManagement(client));
    await waitUntilReady(result);
    const usersGetCount = vi.mocked(client.getJson).mock.calls
      .filter(([path]) => path === '/api/v1/security/users').length;

    await act(async () => {
      await result.current.deleteViewer(23);
    });

    expect(client.deleteJson).toHaveBeenCalledWith(
      '/api/v1/security/users/23',
      parseDeletedResult,
      expect.any(AbortSignal),
    );
    expect(client.deleteJson).toHaveBeenCalledTimes(1);
    expect(vi.mocked(client.getJson).mock.calls
      .filter(([path]) => path === '/api/v1/security/users')).toHaveLength(usersGetCount + 1);
  });

  it('uses role-scoped management IP paths then refreshes only IPs', async () => {
    const client = makeClient();
    const { result } = renderHook(() => useUserManagement(client));
    await waitUntilReady(result);
    const userGetCount = vi.mocked(client.getJson).mock.calls
      .filter(([path]) => path === '/api/v1/security/users').length;
    const ipGetCount = vi.mocked(client.getJson).mock.calls
      .filter(([path]) => path === '/api/v1/security/management-ips').length;
    const administrator = rawIp(31, 'administrator') as ManagementIp;
    const viewer = rawIp(32, 'viewer') as ManagementIp;

    await act(async () => {
      await result.current.createManagementIp('administrator', '192.0.2.31');
      await result.current.createManagementIp('viewer', '192.0.2.32');
      await result.current.updateManagementIp(administrator, '198.51.100.31');
      await result.current.updateManagementIp(viewer, '198.51.100.32');
      await result.current.deleteManagementIp(administrator);
      await result.current.deleteManagementIp(viewer);
    });

    expect(vi.mocked(client.postJson).mock.calls).toEqual([
      ['/api/v1/security/management-ips/administrator', { address: '192.0.2.31' },
        parseManagementIpCreateResult, expect.any(AbortSignal)],
      ['/api/v1/security/management-ips/viewer', { address: '192.0.2.32' },
        parseManagementIpCreateResult, expect.any(AbortSignal)],
    ]);
    expect(vi.mocked(client.putJson).mock.calls).toEqual([
      ['/api/v1/security/management-ips/administrator/31',
        { address: '198.51.100.31' }, parseUpdatedResult, expect.any(AbortSignal)],
      ['/api/v1/security/management-ips/viewer/32',
        { address: '198.51.100.32' }, parseUpdatedResult, expect.any(AbortSignal)],
    ]);
    expect(vi.mocked(client.deleteJson).mock.calls).toEqual([
      ['/api/v1/security/management-ips/administrator/31',
        parseDeletedResult, expect.any(AbortSignal)],
      ['/api/v1/security/management-ips/viewer/32',
        parseDeletedResult, expect.any(AbortSignal)],
    ]);
    expect(vi.mocked(client.getJson).mock.calls
      .filter(([path]) => path === '/api/v1/security/users')).toHaveLength(userGetCount);
    expect(vi.mocked(client.getJson).mock.calls
      .filter(([path]) => path === '/api/v1/security/management-ips'))
      .toHaveLength(ipGetCount + 6);
  });

  it('reports applied with stale data when post-mutation refresh fails', async () => {
    const client = makeClient();
    const { result } = renderHook(() => useUserManagement(client));
    await waitUntilReady(result);
    const retainedUsers = result.current.users.data;
    vi.mocked(client.getJson).mockRejectedValueOnce(new Error('refresh failed'));

    let commandResult!: { refreshed: boolean };
    await act(async () => {
      commandResult = await result.current.createViewer('viewer.two', 'ViewerPass10!');
    });

    expect(commandResult).toEqual({ refreshed: false });
    expect(result.current.users.status).toBe('stale');
    expect(result.current.users.data).toBe(retainedUsers);
    expect(result.current.users.error).toEqual(new Error('refresh failed'));
    expect(result.current.managementIps.status).toBe('ready');
  });

  it('rejects a second mutation while one is active', async () => {
    const client = makeClient();
    const { result } = renderHook(() => useUserManagement(client));
    await waitUntilReady(result);
    const firstResponse = deferred<unknown>();
    vi.mocked(client.postJson).mockImplementationOnce(
      (_path, _body, parser) => firstResponse.promise.then(parser),
    );

    let first!: Promise<{ refreshed: boolean }>;
    act(() => {
      first = result.current.createViewer('viewer.three', 'ViewerPass11!');
    });
    await waitFor(() => expect(result.current.mutation).toBe('create_viewer'));

    await expect(result.current.deleteViewer(1)).rejects.toThrow(
      'A user-management mutation is already active',
    );
    expect(client.deleteJson).not.toHaveBeenCalled();
    expect(client.postJson).toHaveBeenCalledTimes(1);

    await act(async () => {
      firstResponse.resolve({ user: rawUser(3) });
      await first;
    });
    expect(result.current.mutation).toBeNull();
  });

  it('keeps the mutation lock through its authoritative refresh', async () => {
    const client = makeClient();
    const { result } = renderHook(() => useUserManagement(client));
    await waitUntilReady(result);
    const authoritativeRefresh = deferred<ManagedUserList>();
    vi.mocked(client.getJson).mockImplementationOnce(
      (_path, parser) => authoritativeRefresh.promise.then(parser),
    );
    const initialUserGets = vi.mocked(client.getJson).mock.calls
      .filter(([path]) => path === '/api/v1/security/users').length;

    let first!: Promise<{ refreshed: boolean }>;
    act(() => {
      first = result.current.createViewer('viewer.five', 'ViewerPass13!');
    });
    await waitFor(() => expect(vi.mocked(client.getJson).mock.calls
      .filter(([path]) => path === '/api/v1/security/users'))
      .toHaveLength(initialUserGets + 1));

    await expect(result.current.deleteViewer(1)).rejects.toThrow(
      'A user-management mutation is already active',
    );
    expect(client.deleteJson).not.toHaveBeenCalled();
    expect(result.current.mutation).toBe('create_viewer');

    let commandResult!: { refreshed: boolean };
    await act(async () => {
      authoritativeRefresh.resolve(rawUsers(50));
      commandResult = await first;
    });
    expect(commandResult).toEqual({ refreshed: true });
    expect(result.current.mutation).toBeNull();
  });

  it('follows a public refresh that supersedes the mutation refresh', async () => {
    const client = makeClient();
    const { result } = renderHook(() => useUserManagement(client));
    await waitUntilReady(result);
    const mutationRefresh = deferred<ManagedUserList>();
    const publicRefreshResponse = deferred<ManagedUserList>();
    vi.mocked(client.getJson)
      .mockImplementationOnce((_path, parser) => mutationRefresh.promise.then(parser))
      .mockImplementationOnce((_path, parser) => publicRefreshResponse.promise.then(parser));
    const initialUserGets = vi.mocked(client.getJson).mock.calls
      .filter(([path]) => path === '/api/v1/security/users').length;

    let command!: Promise<{ refreshed: boolean }>;
    act(() => {
      command = result.current.createViewer('viewer.six', 'ViewerPass14!');
    });
    await waitFor(() => expect(vi.mocked(client.getJson).mock.calls
      .filter(([path]) => path === '/api/v1/security/users'))
      .toHaveLength(initialUserGets + 1));

    let replacementRefresh!: Promise<void>;
    act(() => {
      replacementRefresh = result.current.refreshUsers();
    });
    const userCalls = vi.mocked(client.getJson).mock.calls
      .filter(([path]) => path === '/api/v1/security/users');
    expect(userCalls[userCalls.length - 2]?.[2]?.aborted).toBe(true);
    expect(userCalls[userCalls.length - 1]?.[2]?.aborted).toBe(false);

    expect(result.current.mutation).toBe('create_viewer');
    await expect(result.current.deleteViewer(1)).rejects.toThrow(
      'A user-management mutation is already active',
    );
    expect(client.deleteJson).not.toHaveBeenCalled();

    let commandResult: { refreshed: boolean } | undefined;
    let commandError: unknown;
    void command.then(
      (value) => {
        commandResult = value;
      },
      (error: unknown) => {
        commandError = error;
      },
    );
    await act(async () => {
      publicRefreshResponse.resolve(rawUsers(61));
      await replacementRefresh;
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(commandError).toBeUndefined();
    expect(commandResult).toEqual({ refreshed: true });
    expect(result.current.users.data.map(({ id }) => id)).toEqual([61]);
    expect(result.current.mutation).toBeNull();

    mutationRefresh.reject(new Error('late superseded refresh failure'));
    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(result.current.users.data.map(({ id }) => id)).toEqual([61]);
  });

  it('reports refresh failure when a superseding public refresh fails', async () => {
    const client = makeClient();
    const { result } = renderHook(() => useUserManagement(client));
    await waitUntilReady(result);
    const retainedUsers = result.current.users.data;
    const mutationRefresh = deferred<ManagedUserList>();
    const publicRefreshResponse = deferred<ManagedUserList>();
    vi.mocked(client.getJson)
      .mockImplementationOnce((_path, parser) => mutationRefresh.promise.then(parser))
      .mockImplementationOnce((_path, parser) => publicRefreshResponse.promise.then(parser));

    let command!: Promise<{ refreshed: boolean }>;
    act(() => {
      command = result.current.createViewer('viewer.seven', 'ViewerPass15!');
    });
    await waitFor(() => expect(result.current.mutation).toBe('create_viewer'));
    await waitFor(() => expect(vi.mocked(client.getJson).mock.calls
      .filter(([path]) => path === '/api/v1/security/users')).toHaveLength(2));

    let replacementRefresh!: Promise<void>;
    act(() => {
      replacementRefresh = result.current.refreshUsers();
    });
    void replacementRefresh.catch(() => undefined);
    expect(result.current.mutation).toBe('create_viewer');

    let commandResult: { refreshed: boolean } | undefined;
    let commandError: unknown;
    void command.then(
      (value) => {
        commandResult = value;
      },
      (error: unknown) => {
        commandError = error;
      },
    );
    await act(async () => {
      publicRefreshResponse.reject(new Error('replacement refresh failed'));
      await expect(replacementRefresh).rejects.toThrow('replacement refresh failed');
      await Promise.resolve();
      await Promise.resolve();
    });

    expect(commandError).toBeUndefined();
    expect(commandResult).toEqual({ refreshed: false });
    expect(result.current.users.status).toBe('stale');
    expect(result.current.users.data).toBe(retainedUsers);
    expect(result.current.users.error).toEqual(
      new Error('replacement refresh failed'),
    );
    expect(result.current.mutation).toBeNull();

    mutationRefresh.resolve(rawUsers(70));
    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(result.current.users.status).toBe('stale');
    expect(result.current.users.data).toBe(retainedUsers);
  });

  it('rethrows mutation failures without changing resource data', async () => {
    const client = makeClient();
    const { result } = renderHook(() => useUserManagement(client));
    await waitUntilReady(result);
    const retainedUsers = result.current.users.data;
    const retainedIps = result.current.managementIps.data;
    vi.mocked(client.putJson).mockRejectedValueOnce(new Error('mutation failed'));

    await expect(result.current.setViewerEnabled(1, false)).rejects.toThrow(
      'mutation failed',
    );

    expect(result.current.users).toEqual({
      status: 'ready', data: retainedUsers, error: null,
    });
    expect(result.current.managementIps).toEqual({
      status: 'ready', data: retainedIps, error: null,
    });
    expect(result.current.mutation).toBeNull();
  });

  it('aborts both resources and an active mutation on unmount', async () => {
    const client = makeClient();
    const users = deferred<unknown>();
    const ips = deferred<unknown>();
    const mutation = deferred<unknown>();
    vi.mocked(client.getJson).mockImplementation((path, parser) =>
      (path === '/api/v1/security/users' ? users.promise : ips.promise).then(parser),
    );
    vi.mocked(client.postJson).mockImplementation(
      (_path, _body, parser) => mutation.promise.then(parser),
    );
    const { result, unmount } = renderHook(() => useUserManagement(client));
    let command!: Promise<{ refreshed: boolean }>;
    act(() => {
      command = result.current.createViewer('viewer.four', 'ViewerPass12!');
    });
    let commandResult: { refreshed: boolean } | undefined;
    let commandError: unknown;
    void command.then(
      (value) => {
        commandResult = value;
      },
      (error: unknown) => {
        commandError = error;
      },
    );
    const usersSignal = vi.mocked(client.getJson).mock.calls[0]?.[2];
    const ipsSignal = vi.mocked(client.getJson).mock.calls[1]?.[2];
    const mutationSignal = vi.mocked(client.postJson).mock.calls[0]?.[3];

    unmount();

    expect(usersSignal?.aborted).toBe(true);
    expect(ipsSignal?.aborted).toBe(true);
    expect(mutationSignal?.aborted).toBe(true);
    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(commandError).toBeUndefined();
    expect(commandResult).toEqual({ refreshed: false });

    users.reject(new Error('late users failure'));
    ips.reject(new Error('late IP failure'));
    mutation.reject(new Error('late mutation failure'));
    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(client.getJson).toHaveBeenCalledTimes(2);
  });
});
