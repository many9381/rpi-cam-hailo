import { useCallback, useEffect, useRef, useState } from 'react';

import { parseMonitoringCameras } from '../api/contracts';
import type { CameraApiClient, MonitoringCamera } from '../api/types';

export interface MonitoringController {
  state: 'loading' | 'ready' | 'stale' | 'error';
  cameras: MonitoringCamera[];
  selectedCameraId: string;
  selectCamera(id: string): void;
  refresh(): Promise<void>;
}

const selectAvailableCamera = (
  selected: string,
  cameras: MonitoringCamera[],
): string => cameras.some(({ id }) => id === selected)
  ? selected
  : (cameras[0]?.id ?? '');

export function useMonitoringData(client: CameraApiClient): MonitoringController {
  const [state, setState] = useState<MonitoringController['state']>('loading');
  const [cameras, setCameras] = useState<MonitoringCamera[]>([]);
  const [selectedCameraId, setSelectedCameraId] = useState('');
  const mounted = useRef(true);
  const currentCameras = useRef<MonitoringCamera[] | null>(null);
  const refreshGeneration = useRef(0);
  const activeRefresh = useRef<AbortController | null>(null);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const refresh = useCallback(async () => {
    const generation = refreshGeneration.current + 1;
    refreshGeneration.current = generation;
    activeRefresh.current?.abort();
    const controller = new AbortController();
    activeRefresh.current = controller;

    try {
      const response = await client.getJson(
        '/api/v1/monitoring/cameras',
        parseMonitoringCameras,
        controller.signal,
      );
      if (!mounted.current || generation !== refreshGeneration.current) {
        return;
      }
      currentCameras.current = response.cameras;
      setCameras(response.cameras);
      setSelectedCameraId((selected) =>
        selectAvailableCamera(selected, response.cameras));
      setState('ready');
    } catch (error) {
      if (!mounted.current || generation !== refreshGeneration.current) {
        return;
      }
      setState(currentCameras.current === null ? 'error' : 'stale');
      throw error;
    } finally {
      if (activeRefresh.current === controller) {
        activeRefresh.current = null;
      }
    }
  }, [client]);

  useEffect(() => {
    void refresh().catch(() => undefined);
    const timer = window.setInterval(() => {
      void refresh().catch(() => undefined);
    }, 5000);

    return () => {
      refreshGeneration.current += 1;
      activeRefresh.current?.abort();
      activeRefresh.current = null;
      window.clearInterval(timer);
    };
  }, [refresh]);

  return {
    state,
    cameras,
    selectedCameraId,
    selectCamera: setSelectedCameraId,
    refresh,
  };
}
