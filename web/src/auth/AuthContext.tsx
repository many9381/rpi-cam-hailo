import {
  createContext,
  type ReactNode,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';

import { parseLoginResult, parseLogoutResult, parsePrincipal } from '../api/contracts';
import type { CameraApiClient, Principal } from '../api/types';
import { parseSelfPasswordChangeResult } from '../features/users/contracts';

export interface AuthContextValue {
  state: 'checking' | 'anonymous' | 'authenticated';
  principal: Principal | null;
  login(username: string, password: string): Promise<void>;
  logout(): Promise<void>;
  changePassword(
    currentPassword: string,
    replacementPassword: string,
    signal?: AbortSignal,
  ): Promise<void>;
}

interface AuthProviderProps {
  client: CameraApiClient;
  children: ReactNode;
}

interface PendingLogout {
  controller: AbortController;
  promise: Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ client, children }: AuthProviderProps) {
  const [state, setState] = useState<AuthContextValue['state']>('checking');
  const [principal, setPrincipal] = useState<Principal | null>(null);
  const epoch = useRef(0);
  const pendingLogout = useRef<PendingLogout | null>(null);

  const invalidate = useCallback(() => {
    epoch.current += 1;
    setPrincipal(null);
    setState('anonymous');
  }, []);

  useEffect(() => {
    let cancelled = false;
    const controller = new AbortController();
    const recoveryEpoch = epoch.current;

    client.setUnauthorizedHandler(invalidate);
    client.getJson('/api/v1/auth/me', parsePrincipal, controller.signal)
      .then((recovered) => {
        if (!cancelled && epoch.current === recoveryEpoch) {
          setPrincipal(recovered);
          setState('authenticated');
        }
      })
      .catch(() => {
        if (!cancelled && epoch.current === recoveryEpoch) {
          setPrincipal(null);
          setState('anonymous');
        }
      });

    return () => {
      cancelled = true;
      controller.abort();
      pendingLogout.current?.controller.abort();
      client.setUnauthorizedHandler(null);
    };
  }, [client, invalidate]);

  const login = useCallback(async (username: string, password: string) => {
    const previousLogout = pendingLogout.current;
    if (previousLogout !== null) {
      previousLogout.controller.abort();
      await previousLogout.promise;
    }
    const loginEpoch = ++epoch.current;
    await client.postJson(
      '/api/v1/auth/login',
      { username, password },
      parseLoginResult,
    );
    const recovered = await client.getJson('/api/v1/auth/me', parsePrincipal);
    if (epoch.current === loginEpoch) {
      setPrincipal(recovered);
      setState('authenticated');
    }
  }, [client]);

  const logout = useCallback(async () => {
    invalidate();
    pendingLogout.current?.controller.abort();
    const controller = new AbortController();
    let entry: PendingLogout;
    const promise = client.postJson(
      '/api/v1/auth/logout',
      {},
      parseLogoutResult,
      controller.signal,
    ).then(() => undefined).catch(() => undefined).finally(() => {
      if (pendingLogout.current === entry) {
        pendingLogout.current = null;
      }
    });
    entry = { controller, promise };
    pendingLogout.current = entry;
    try {
      await promise;
    } finally {
      if (pendingLogout.current === entry) {
        pendingLogout.current = null;
      }
    }
  }, [client, invalidate]);

  const changePassword = useCallback(async (
    currentPassword: string,
    replacementPassword: string,
    signal?: AbortSignal,
  ) => {
    await client.putJson(
      '/api/v1/auth/password',
      {
        current_password: currentPassword,
        replacement_password: replacementPassword,
      },
      parseSelfPasswordChangeResult,
      signal,
    );
    invalidate();
  }, [client, invalidate]);

  const value = useMemo<AuthContextValue>(() => ({
    state,
    principal,
    login,
    logout,
    changePassword,
  }), [changePassword, login, logout, principal, state]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const value = useContext(AuthContext);
  if (value === null) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return value;
}
