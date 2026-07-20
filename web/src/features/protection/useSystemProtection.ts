import { useCallback, useEffect, useRef, useState } from 'react';

import { ApiError } from '../../api/client';
import type { CameraApiClient } from '../../api/types';
import { parseProtectionSnapshot, type ProtectionSnapshot } from './contracts';

export type ProtectionCommand = 'self_test' | 'integrity';

export interface SystemProtectionController {
  state: 'loading' | 'ready' | 'stale' | 'unavailable';
  snapshot: ProtectionSnapshot | null;
  publicMessage: string | null;
  activeCommand: ProtectionCommand | null;
  refresh(): Promise<void>;
  runSelfTest(): Promise<void>;
  runIntegrityCheck(): Promise<void>;
}

const POLL_INTERVAL_MS = 30_000;

const publicMessageFor = (error: unknown): string =>
  error instanceof ApiError && error.status === 409
    ? 'Protection check is already running.'
    : 'System protection is temporarily unavailable.';

export function useSystemProtection(
  client: CameraApiClient,
): SystemProtectionController {
  const [state, setState] = useState<SystemProtectionController['state']>('loading');
  const [snapshot, setSnapshot] = useState<ProtectionSnapshot | null>(null);
  const [publicMessage, setPublicMessage] = useState<string | null>(null);
  const [activeCommand, setActiveCommand] = useState<ProtectionCommand | null>(null);
  const mounted = useRef(true);
  const snapshotRef = useRef<ProtectionSnapshot | null>(null);
  const activeRequest = useRef<AbortController | null>(null);

  const adoptSnapshot = useCallback((next: ProtectionSnapshot) => {
    snapshotRef.current = next;
    setSnapshot(next);
    if (!next.check_running) {
      setActiveCommand(null);
    }
    setState('ready');
  }, []);

  const refresh = useCallback(async () => {
    if (!mounted.current || activeRequest.current !== null) {
      return;
    }
    const controller = new AbortController();
    activeRequest.current = controller;
    setState('loading');
    setPublicMessage(null);

    try {
      const next = await client.getJson(
        '/api/v1/system/protection',
        parseProtectionSnapshot,
        controller.signal,
      );
      if (!mounted.current || activeRequest.current !== controller) {
        return;
      }
      adoptSnapshot(next);
    } catch (error) {
      if (!mounted.current || activeRequest.current !== controller) {
        return;
      }
      setState(snapshotRef.current === null ? 'unavailable' : 'stale');
      setPublicMessage(publicMessageFor(error));
      throw error;
    } finally {
      if (activeRequest.current === controller) {
        activeRequest.current = null;
      }
    }
  }, [adoptSnapshot, client]);

  const runCheck = useCallback(async (
    path: string,
    command: ProtectionCommand,
  ) => {
    if (!mounted.current || activeRequest.current !== null ||
        snapshotRef.current?.check_running) {
      return;
    }
    const controller = new AbortController();
    activeRequest.current = controller;
    setActiveCommand(command);
    setState('loading');
    setPublicMessage(null);

    try {
      const next = await client.postJson(
        path,
        {},
        parseProtectionSnapshot,
        controller.signal,
      );
      if (!mounted.current || activeRequest.current !== controller) {
        return;
      }
      adoptSnapshot(next);
    } catch (error) {
      if (!mounted.current || activeRequest.current !== controller) {
        return;
      }
      setActiveCommand(null);
      setPublicMessage(publicMessageFor(error));
      setState(snapshotRef.current === null ? 'unavailable' : 'ready');
    } finally {
      if (activeRequest.current === controller) {
        activeRequest.current = null;
      }
    }
  }, [adoptSnapshot, client]);

  const runSelfTest = useCallback(async () => {
    await runCheck('/api/v1/system/self-tests', 'self_test');
  }, [runCheck]);

  const runIntegrityCheck = useCallback(async () => {
    await runCheck('/api/v1/system/integrity-checks', 'integrity');
  }, [runCheck]);

  useEffect(() => {
    mounted.current = true;
    let pollTimer: number | null = null;

    const stopPolling = () => {
      if (pollTimer !== null) {
        window.clearInterval(pollTimer);
        pollTimer = null;
      }
    };
    const startPolling = () => {
      if (document.visibilityState === 'visible' && pollTimer === null) {
        pollTimer = window.setInterval(() => {
          void refresh().catch(() => undefined);
        }, POLL_INTERVAL_MS);
      }
    };
    const handleVisibilityChange = () => {
      if (document.visibilityState !== 'visible') {
        stopPolling();
        return;
      }
      void refresh().catch(() => undefined);
      startPolling();
    };

    void refresh().catch(() => undefined);
    startPolling();
    document.addEventListener('visibilitychange', handleVisibilityChange);

    return () => {
      mounted.current = false;
      activeRequest.current?.abort();
      activeRequest.current = null;
      stopPolling();
      document.removeEventListener('visibilitychange', handleVisibilityChange);
    };
  }, [refresh]);

  return {
    state,
    snapshot,
    publicMessage,
    activeCommand,
    refresh,
    runSelfTest,
    runIntegrityCheck,
  };
}
