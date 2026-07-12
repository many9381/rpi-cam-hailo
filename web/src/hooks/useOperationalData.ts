import { useCallback, useEffect, useRef, useState } from 'react';

import {
  parseCameraInventory,
  parseDetectionSnapshot,
  parseHealth,
  parseStream,
} from '../api/contracts';
import type {
  AiStatus,
  CameraApiClient,
  CameraStatus,
  DetectionSnapshot,
  HealthStatus,
  StreamStatus,
} from '../api/types';

export interface OperationalData {
  health: HealthStatus;
  cameras: CameraStatus[];
  ai: AiStatus;
  stream: StreamStatus;
  detections: DetectionSnapshot;
}

export interface OperationalController {
  state: 'loading' | 'ready' | 'stale' | 'error';
  data: OperationalData | null;
  selectedCameraId: string;
  selectCamera(id: string): void;
  replaceDetections(snapshot: DetectionSnapshot): void;
  replaceAiStatus(ai: AiStatus): void;
  refresh(): Promise<void>;
}

const selectAvailableCamera = (
  selected: string,
  cameras: CameraStatus[],
): string => cameras.some(({ id }) => id === selected)
  ? selected
  : (cameras[0]?.id ?? '');

export function useOperationalData(client: CameraApiClient): OperationalController {
  const [state, setState] = useState<OperationalController['state']>('loading');
  const [data, setData] = useState<OperationalData | null>(null);
  const [selectedCameraId, setSelectedCameraId] = useState('');
  const mounted = useRef(true);
  const currentData = useRef<OperationalData | null>(null);
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
      const needsCompleteLoad = currentData.current === null;
      const healthRequest = client.getJson(
        '/api/v1/health', parseHealth, controller.signal);
      const camerasRequest = client.getJson(
        '/api/v1/cameras', parseCameraInventory, controller.signal);
      const streamRequest = client.getJson(
        '/api/v1/stream', parseStream, controller.signal);
      const detectionsRequest = needsCompleteLoad
        ? client.getJson(
          '/api/v1/ai/detections',
          parseDetectionSnapshot,
          controller.signal,
        )
        : Promise.resolve(currentData.current!.detections);
      const [health, inventory, stream, loadedDetections] = await Promise.all([
        healthRequest,
        camerasRequest,
        streamRequest,
        detectionsRequest,
      ]);
      if (!mounted.current || generation !== refreshGeneration.current) {
        return;
      }
      const nextData: OperationalData = {
        health,
        cameras: inventory.cameras,
        ai: inventory.ai,
        stream,
        detections: needsCompleteLoad
          ? loadedDetections
          : (currentData.current?.detections ?? loadedDetections),
      };
      currentData.current = nextData;
      setData(nextData);
      setSelectedCameraId((selected) =>
        selectAvailableCamera(selected, inventory.cameras));
      setState('ready');
    } catch (error) {
      if (!mounted.current || generation !== refreshGeneration.current) {
        return;
      }
      setState(currentData.current === null ? 'error' : 'stale');
      throw error;
    } finally {
      if (activeRefresh.current === controller) {
        activeRefresh.current = null;
      }
    }
  }, [client]);

  const replaceDetections = useCallback((detections: DetectionSnapshot) => {
    const current = currentData.current;
    if (current === null || current.detections === detections) {
      return;
    }
    const next = { ...current, detections };
    currentData.current = next;
    setData(next);
  }, []);

  const replaceAiStatus = useCallback((ai: AiStatus) => {
    const current = currentData.current;
    if (current === null || current.ai === ai) {
      return;
    }
    const next = { ...current, ai };
    currentData.current = next;
    setData(next);
  }, []);

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
  }, [client, refresh]);

  return {
    state,
    data,
    selectedCameraId,
    selectCamera: setSelectedCameraId,
    replaceDetections,
    replaceAiStatus,
    refresh,
  };
}
