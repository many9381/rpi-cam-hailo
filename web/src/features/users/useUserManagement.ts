import { useCallback, useEffect, useRef, useState } from 'react';

import type { CameraApiClient, UserRole } from '../../api/types';
import {
  parseDeletedResult,
  parseManagedUserCreateResult,
  parseManagedUserList,
  parseManagementIpCreateResult,
  parseManagementIpList,
  parsePasswordResetResult,
  parseUpdatedResult,
  type ManagedUser,
  type ManagementIp,
  type ManagementIpList,
} from './contracts';

export type UserManagementResourceStatus = 'loading' | 'ready' | 'stale' | 'error';

export interface UserManagementResource<T> {
  status: UserManagementResourceStatus;
  data: T;
  error: unknown | null;
}

export type UserManagementMutation =
  | 'create_viewer'
  | 'set_viewer_enabled'
  | 'reset_viewer_password'
  | 'delete_viewer'
  | 'create_management_ip'
  | 'update_management_ip'
  | 'delete_management_ip';

export interface UserManagementCommandResult {
  refreshed: boolean;
}

export interface UserManagementController {
  users: UserManagementResource<ManagedUser[]>;
  managementIps: UserManagementResource<ManagementIpList>;
  mutation: UserManagementMutation | null;
  refreshUsers(): Promise<void>;
  refreshManagementIps(): Promise<void>;
  refreshAll(): Promise<void>;
  createViewer(username: string, password: string): Promise<UserManagementCommandResult>;
  setViewerEnabled(id: number, enabled: boolean): Promise<UserManagementCommandResult>;
  resetViewerPassword(id: number, password: string): Promise<UserManagementCommandResult>;
  deleteViewer(id: number): Promise<UserManagementCommandResult>;
  createManagementIp(role: UserRole, address: string): Promise<UserManagementCommandResult>;
  updateManagementIp(
    entry: ManagementIp,
    address: string,
  ): Promise<UserManagementCommandResult>;
  deleteManagementIp(entry: ManagementIp): Promise<UserManagementCommandResult>;
}

interface ActiveMutation {
  kind: UserManagementMutation;
  controller: AbortController;
}

type RefreshOutcome =
  | { status: 'ready' }
  | { status: 'failed'; error: unknown }
  | { status: 'superseded' };

interface RefreshAttempt {
  generation: number;
  completion: Promise<RefreshOutcome>;
}

type AbortAwareResult<T> =
  | { aborted: true }
  | { aborted: false; value: T };

const settleOnAbort = <T,>(
  clientPromise: Promise<T>,
  signal: AbortSignal,
): Promise<AbortAwareResult<T>> => {
  if (signal.aborted) {
    void clientPromise.then(
      () => undefined,
      () => undefined,
    );
    return Promise.resolve({ aborted: true });
  }

  return new Promise<AbortAwareResult<T>>((resolve, reject) => {
    let settled = false;
    const removeAbortListener = () => {
      signal.removeEventListener('abort', handleAbort);
    };
    const handleAbort = () => {
      if (settled) {
        return;
      }
      settled = true;
      removeAbortListener();
      resolve({ aborted: true });
    };

    signal.addEventListener('abort', handleAbort, { once: true });
    void clientPromise.then(
      (value) => {
        if (settled) {
          return;
        }
        settled = true;
        removeAbortListener();
        resolve({ aborted: false, value });
      },
      (error: unknown) => {
        if (settled) {
          return;
        }
        settled = true;
        removeAbortListener();
        reject(error);
      },
    );
  });
};

const followAuthoritativeRefresh = async (
  initial: RefreshAttempt,
  latest: () => RefreshAttempt | null,
  isMounted: () => boolean,
): Promise<boolean> => {
  let attempt = initial;
  while (true) {
    const outcome = await attempt.completion;
    if (outcome.status === 'ready') {
      return true;
    }
    if (outcome.status === 'failed' || !isMounted()) {
      return false;
    }
    const replacement = latest();
    if (replacement === null || replacement.generation <= attempt.generation) {
      return false;
    }
    attempt = replacement;
  }
};

const initialManagementIps: ManagementIpList = {
  management_ips: [],
  current_peer_ip: '',
};

export function useUserManagement(
  client: CameraApiClient,
): UserManagementController {
  const [users, setUsers] = useState<UserManagementResource<ManagedUser[]>>({
    status: 'loading',
    data: [],
    error: null,
  });
  const [managementIps, setManagementIps] = useState<
    UserManagementResource<ManagementIpList>
  >({
    status: 'loading',
    data: initialManagementIps,
    error: null,
  });
  const [mutation, setMutation] = useState<UserManagementMutation | null>(null);
  const mounted = useRef(true);
  const usersLoaded = useRef(false);
  const managementIpsLoaded = useRef(false);
  const usersGeneration = useRef(0);
  const managementIpsGeneration = useRef(0);
  const activeUsersRefresh = useRef<AbortController | null>(null);
  const activeManagementIpsRefresh = useRef<AbortController | null>(null);
  const latestUsersRefresh = useRef<RefreshAttempt | null>(null);
  const latestManagementIpsRefresh = useRef<RefreshAttempt | null>(null);
  const activeMutation = useRef<ActiveMutation | null>(null);

  const startUsersRefresh = useCallback((): RefreshAttempt => {
    const generation = usersGeneration.current + 1;
    usersGeneration.current = generation;
    activeUsersRefresh.current?.abort();
    const controller = new AbortController();
    activeUsersRefresh.current = controller;

    if (!usersLoaded.current && mounted.current) {
      setUsers((current) => ({ ...current, status: 'loading', error: null }));
    }

    const completion = (async (): Promise<RefreshOutcome> => {
      try {
        const response = await settleOnAbort(
          client.getJson(
            '/api/v1/security/users',
            parseManagedUserList,
            controller.signal,
          ),
          controller.signal,
        );
        if (response.aborted || !mounted.current || controller.signal.aborted ||
            generation !== usersGeneration.current) {
          return { status: 'superseded' };
        }
        usersLoaded.current = true;
        setUsers({ status: 'ready', data: response.value.users, error: null });
        return { status: 'ready' };
      } catch (caught) {
        if (!mounted.current || controller.signal.aborted ||
            generation !== usersGeneration.current) {
          return { status: 'superseded' };
        }
        setUsers((current) => ({
          ...current,
          status: usersLoaded.current ? 'stale' : 'error',
          error: caught,
        }));
        return { status: 'failed', error: caught };
      } finally {
        if (activeUsersRefresh.current === controller) {
          activeUsersRefresh.current = null;
        }
      }
    })();
    const attempt = { generation, completion };
    latestUsersRefresh.current = attempt;
    return attempt;
  }, [client]);

  const refreshUsers = useCallback(async () => {
    const outcome = await startUsersRefresh().completion;
    if (outcome.status === 'failed') {
      throw outcome.error;
    }
  }, [startUsersRefresh]);

  const startManagementIpsRefresh = useCallback((): RefreshAttempt => {
    const generation = managementIpsGeneration.current + 1;
    managementIpsGeneration.current = generation;
    activeManagementIpsRefresh.current?.abort();
    const controller = new AbortController();
    activeManagementIpsRefresh.current = controller;

    if (!managementIpsLoaded.current && mounted.current) {
      setManagementIps((current) => ({ ...current, status: 'loading', error: null }));
    }

    const completion = (async (): Promise<RefreshOutcome> => {
      try {
        const response = await settleOnAbort(
          client.getJson(
            '/api/v1/security/management-ips',
            parseManagementIpList,
            controller.signal,
          ),
          controller.signal,
        );
        if (response.aborted || !mounted.current || controller.signal.aborted ||
            generation !== managementIpsGeneration.current) {
          return { status: 'superseded' };
        }
        managementIpsLoaded.current = true;
        setManagementIps({ status: 'ready', data: response.value, error: null });
        return { status: 'ready' };
      } catch (caught) {
        if (!mounted.current || controller.signal.aborted ||
            generation !== managementIpsGeneration.current) {
          return { status: 'superseded' };
        }
        setManagementIps((current) => ({
          ...current,
          status: managementIpsLoaded.current ? 'stale' : 'error',
          error: caught,
        }));
        return { status: 'failed', error: caught };
      } finally {
        if (activeManagementIpsRefresh.current === controller) {
          activeManagementIpsRefresh.current = null;
        }
      }
    })();
    const attempt = { generation, completion };
    latestManagementIpsRefresh.current = attempt;
    return attempt;
  }, [client]);

  const refreshManagementIps = useCallback(async () => {
    const outcome = await startManagementIpsRefresh().completion;
    if (outcome.status === 'failed') {
      throw outcome.error;
    }
  }, [startManagementIpsRefresh]);

  const refreshUsersAuthoritatively = useCallback(() =>
    followAuthoritativeRefresh(
      startUsersRefresh(),
      () => latestUsersRefresh.current,
      () => mounted.current,
    ), [startUsersRefresh]);

  const refreshManagementIpsAuthoritatively = useCallback(() =>
    followAuthoritativeRefresh(
      startManagementIpsRefresh(),
      () => latestManagementIpsRefresh.current,
      () => mounted.current,
    ), [startManagementIpsRefresh]);

  const refreshAll = useCallback(async () => {
    await Promise.all([refreshUsers(), refreshManagementIps()]);
  }, [refreshManagementIps, refreshUsers]);

  const abortAll = useCallback(() => {
    mounted.current = false;
    usersGeneration.current += 1;
    managementIpsGeneration.current += 1;
    activeUsersRefresh.current?.abort();
    activeManagementIpsRefresh.current?.abort();
    activeMutation.current?.controller.abort();
  }, []);

  useEffect(() => {
    mounted.current = true;
    void refreshUsers().catch(() => undefined);
    void refreshManagementIps().catch(() => undefined);
    return abortAll;
  }, [abortAll, refreshManagementIps, refreshUsers]);

  const runMutation = useCallback(async (
    kind: UserManagementMutation,
    request: (signal: AbortSignal) => Promise<unknown>,
    refresh: () => Promise<boolean>,
  ): Promise<UserManagementCommandResult> => {
    if (activeMutation.current !== null) {
      throw new Error('A user-management mutation is already active');
    }

    const controller = new AbortController();
    const ownership: ActiveMutation = { kind, controller };
    activeMutation.current = ownership;
    if (mounted.current) {
      setMutation(kind);
    }

    try {
      const requestResult = await settleOnAbort(
        request(controller.signal),
        controller.signal,
      );
      if (requestResult.aborted || !mounted.current || controller.signal.aborted) {
        return { refreshed: false };
      }
      try {
        const refreshed = await refresh();
        return {
          refreshed: refreshed && mounted.current && !controller.signal.aborted,
        };
      } catch {
        return { refreshed: false };
      }
    } finally {
      if (activeMutation.current === ownership) {
        activeMutation.current = null;
        if (mounted.current) {
          setMutation(null);
        }
      }
    }
  }, []);

  const createViewer = useCallback((username: string, password: string) =>
    runMutation(
      'create_viewer',
      (signal) => client.postJson(
        '/api/v1/security/users',
        { username, password },
        parseManagedUserCreateResult,
        signal,
      ),
      refreshUsersAuthoritatively,
    ), [client, refreshUsersAuthoritatively, runMutation]);

  const setViewerEnabled = useCallback((id: number, enabled: boolean) =>
    runMutation(
      'set_viewer_enabled',
      (signal) => client.putJson(
        `/api/v1/security/users/${id}/enabled`,
        { enabled },
        parseUpdatedResult,
        signal,
      ),
      refreshUsersAuthoritatively,
    ), [client, refreshUsersAuthoritatively, runMutation]);

  const resetViewerPassword = useCallback((id: number, password: string) =>
    runMutation(
      'reset_viewer_password',
      (signal) => client.putJson(
        `/api/v1/security/users/${id}/password`,
        { password },
        parsePasswordResetResult,
        signal,
      ),
      refreshUsersAuthoritatively,
    ), [client, refreshUsersAuthoritatively, runMutation]);

  const deleteViewer = useCallback((id: number) =>
    runMutation(
      'delete_viewer',
      (signal) => client.deleteJson(
        `/api/v1/security/users/${id}`,
        parseDeletedResult,
        signal,
      ),
      refreshUsersAuthoritatively,
    ), [client, refreshUsersAuthoritatively, runMutation]);

  const createManagementIp = useCallback((role: UserRole, address: string) =>
    runMutation(
      'create_management_ip',
      (signal) => client.postJson(
        `/api/v1/security/management-ips/${role}`,
        { address },
        parseManagementIpCreateResult,
        signal,
      ),
      refreshManagementIpsAuthoritatively,
    ), [client, refreshManagementIpsAuthoritatively, runMutation]);

  const updateManagementIp = useCallback((entry: ManagementIp, address: string) =>
    runMutation(
      'update_management_ip',
      (signal) => client.putJson(
        `/api/v1/security/management-ips/${entry.role}/${entry.id}`,
        { address },
        parseUpdatedResult,
        signal,
      ),
      refreshManagementIpsAuthoritatively,
    ), [client, refreshManagementIpsAuthoritatively, runMutation]);

  const deleteManagementIp = useCallback((entry: ManagementIp) =>
    runMutation(
      'delete_management_ip',
      (signal) => client.deleteJson(
        `/api/v1/security/management-ips/${entry.role}/${entry.id}`,
        parseDeletedResult,
        signal,
      ),
      refreshManagementIpsAuthoritatively,
    ), [client, refreshManagementIpsAuthoritatively, runMutation]);

  return {
    users,
    managementIps,
    mutation,
    refreshUsers,
    refreshManagementIps,
    refreshAll,
    createViewer,
    setViewerEnabled,
    resetViewerPassword,
    deleteViewer,
    createManagementIp,
    updateManagementIp,
    deleteManagementIp,
  };
}
