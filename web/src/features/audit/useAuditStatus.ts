import { useCallback, useEffect, useRef, useState } from 'react';

import type { CameraApiClient } from '../../api/types';
import { parseAuditStatus, type AuditStatus } from './contracts';

export interface AuditStatusController {
  state: 'loading' | 'ready' | 'stale' | 'unavailable';
  data: AuditStatus | null;
  refresh(): Promise<void>;
}

const POLL_INTERVAL_MS = 30_000;

export function useAuditStatus(client: CameraApiClient): AuditStatusController {
  const [state, setState] = useState<AuditStatusController['state']>('loading');
  const [data, setData] = useState<AuditStatus | null>(null);
  const mounted = useRef(true);
  const dataRef = useRef<AuditStatus | null>(null);
  const generationRef = useRef(0);
  const activeRequest = useRef<AbortController | null>(null);

  const refresh = useCallback(async () => {
    if (!mounted.current) {
      return;
    }
    const generation = generationRef.current + 1;
    generationRef.current = generation;
    activeRequest.current?.abort();
    const controller = new AbortController();
    activeRequest.current = controller;
    if (dataRef.current === null) {
      setState('loading');
    }

    try {
      const next = await client.getJson(
        '/api/v1/audit/status',
        parseAuditStatus,
        controller.signal,
      );
      if (!mounted.current || generation !== generationRef.current) {
        return;
      }
      dataRef.current = next;
      setData(next);
      setState('ready');
    } catch (error) {
      if (!mounted.current || generation !== generationRef.current) {
        return;
      }
      setState(dataRef.current === null ? 'unavailable' : 'stale');
      throw error;
    } finally {
      if (activeRequest.current === controller) {
        activeRequest.current = null;
      }
    }
  }, [client]);

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
      generationRef.current += 1;
      activeRequest.current?.abort();
      activeRequest.current = null;
      stopPolling();
      document.removeEventListener('visibilitychange', handleVisibilityChange);
    };
  }, [refresh]);

  return { state, data, refresh };
}
