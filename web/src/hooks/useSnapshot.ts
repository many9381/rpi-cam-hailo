import { useCallback, useEffect, useRef, useState } from 'react';

import type { CameraApiClient } from '../api/types';

export type SnapshotState = 'loading' | 'ready' | 'unavailable';

export interface SnapshotController {
  state: SnapshotState;
  objectUrl: string | null;
  refresh(): Promise<void>;
}

interface SnapshotResource {
  cameraId: string;
  state: SnapshotState;
  objectUrl: string | null;
}

export function useSnapshot(
  client: CameraApiClient,
  cameraId: string,
): SnapshotController {
  const [resource, setResource] = useState<SnapshotResource>({
    cameraId,
    state: cameraId.length > 0 ? 'loading' : 'unavailable',
    objectUrl: null,
  });
  const generation = useRef(0);
  const activeRequest = useRef<AbortController | null>(null);
  const ownedUrl = useRef<string | null>(null);

  const releaseOwnedUrl = useCallback(() => {
    if (ownedUrl.current !== null) {
      URL.revokeObjectURL(ownedUrl.current);
      ownedUrl.current = null;
    }
  }, []);

  const refresh = useCallback(async () => {
    const requestGeneration = generation.current + 1;
    generation.current = requestGeneration;
    activeRequest.current?.abort();
    releaseOwnedUrl();

    if (cameraId.length === 0) {
      activeRequest.current = null;
      setResource({ cameraId, state: 'unavailable', objectUrl: null });
      return;
    }

    const controller = new AbortController();
    activeRequest.current = controller;
    setResource({ cameraId, state: 'loading', objectUrl: null });

    try {
      const blob = await client.getBlob(
        `/api/v1/cameras/${encodeURIComponent(cameraId)}/snapshot.jpg`,
        controller.signal,
      );
      if (generation.current !== requestGeneration) {
        return;
      }

      const nextUrl = URL.createObjectURL(blob);
      ownedUrl.current = nextUrl;
      setResource({ cameraId, state: 'ready', objectUrl: nextUrl });
    } catch (error) {
      if (generation.current !== requestGeneration) {
        return;
      }
      releaseOwnedUrl();
      setResource({ cameraId, state: 'unavailable', objectUrl: null });
      throw error;
    } finally {
      if (activeRequest.current === controller) {
        activeRequest.current = null;
      }
    }
  }, [cameraId, client, releaseOwnedUrl]);

  useEffect(() => {
    void refresh().catch(() => undefined);
    return () => {
      generation.current += 1;
      activeRequest.current?.abort();
      activeRequest.current = null;
    };
  }, [refresh]);

  useEffect(() => () => releaseOwnedUrl(), [releaseOwnedUrl]);

  if (resource.cameraId !== cameraId) {
    return {
      state: cameraId.length > 0 ? 'loading' : 'unavailable',
      objectUrl: null,
      refresh,
    };
  }
  return { state: resource.state, objectUrl: resource.objectUrl, refresh };
}
