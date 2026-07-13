import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';

export type MjpegPreviewState = 'connecting' | 'live' | 'reconnecting' | 'unavailable';

export interface MjpegPreviewController {
  state: MjpegPreviewState;
  streamUrl: string;
  onLoad(streamUrl: string): boolean;
  onError(streamUrl: string): boolean;
  reconnect(): void;
}

interface MjpegPreviewResource {
  cameraId: string;
  state: MjpegPreviewState;
  streamUrl: string;
}

const retryDelay = (attempt: number) => Math.min(1_000 * 2 ** attempt, 5_000);

const streamUrl = (cameraId: string, generation: number) =>
  `/api/v1/cameras/${encodeURIComponent(cameraId)}/preview.mjpeg?generation=${generation}`;

export function useMjpegPreview(cameraId: string): MjpegPreviewController {
  const [resource, setResource] = useState<MjpegPreviewResource>(() => ({
    cameraId,
    state: cameraId.length > 0 ? 'connecting' : 'unavailable',
    streamUrl: cameraId.length > 0 ? streamUrl(cameraId, 1) : '',
  }));
  const generation = useRef(cameraId.length > 0 ? 1 : 0);
  const currentCameraId = useRef(cameraId);
  const currentStreamUrl = useRef(resource.streamUrl);
  const retryAttempt = useRef(0);
  const retryTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const cancelRetry = useCallback(() => {
    if (retryTimer.current !== null) {
      clearTimeout(retryTimer.current);
      retryTimer.current = null;
    }
  }, []);

  const openStream = useCallback((nextCameraId: string, state: MjpegPreviewState) => {
    cancelRetry();
    generation.current += 1;
    currentCameraId.current = nextCameraId;

    if (nextCameraId.length === 0) {
      currentStreamUrl.current = '';
      setResource({ cameraId: nextCameraId, state: 'unavailable', streamUrl: '' });
      return;
    }

    const nextStreamUrl = streamUrl(nextCameraId, generation.current);
    currentStreamUrl.current = nextStreamUrl;
    setResource({ cameraId: nextCameraId, state, streamUrl: nextStreamUrl });
  }, [cancelRetry]);

  useLayoutEffect(() => {
    if (currentCameraId.current !== cameraId) {
      retryAttempt.current = 0;
      openStream(cameraId, 'connecting');
    }
  }, [cameraId, openStream]);

  useEffect(() => () => cancelRetry(), [cancelRetry]);

  const onLoad = useCallback((loadedUrl: string) => {
    if (loadedUrl !== currentStreamUrl.current || loadedUrl.length === 0) {
      return false;
    }
    retryAttempt.current = 0;
    setResource((current) => current.streamUrl === loadedUrl
      ? { ...current, state: 'live' }
      : current);
    return true;
  }, []);

  const onError = useCallback((failedUrl: string) => {
    if (failedUrl !== currentStreamUrl.current || failedUrl.length === 0) {
      return false;
    }
    currentStreamUrl.current = '';
    setResource((current) => current.streamUrl === failedUrl
      ? { ...current, state: 'reconnecting', streamUrl: '' }
      : current);

    const delay = retryDelay(retryAttempt.current);
    retryAttempt.current += 1;
    retryTimer.current = setTimeout(() => {
      retryTimer.current = null;
      if (currentCameraId.current.length > 0) {
        openStream(currentCameraId.current, 'reconnecting');
      }
    }, delay);
    return true;
  }, [openStream]);

  const reconnect = useCallback(() => {
    retryAttempt.current = 0;
    openStream(currentCameraId.current, 'connecting');
  }, [openStream]);

  if (resource.cameraId !== cameraId) {
    return {
      state: cameraId.length > 0 ? 'connecting' : 'unavailable',
      streamUrl: '',
      onLoad,
      onError,
      reconnect,
    };
  }
  return { ...resource, onLoad, onError, reconnect };
}
