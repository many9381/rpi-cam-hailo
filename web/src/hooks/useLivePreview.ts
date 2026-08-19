import { useCallback, useEffect, useRef, useState, type RefObject } from 'react';

export const LIVE_MP4_MIME_TYPE = 'video/mp4; codecs="avc1.42C02A"';

export type LivePreviewState = 'connecting' | 'live' | 'reconnecting' | 'unavailable';

export interface LivePreviewController {
  state: LivePreviewState;
  generation: number;
  videoRef: RefObject<HTMLVideoElement>;
  reconnect(): void;
}

interface PreviewResource {
  cameraId: string;
  state: LivePreviewState;
  generation: number;
}

interface ActiveSession {
  generation: number;
  mediaSource: MediaSource;
  objectUrl: string;
  abortController: AbortController;
  sourceBuffer: SourceBuffer | null;
  reader: ReadableStreamDefaultReader<Uint8Array> | null;
  closed: boolean;
  failed: boolean;
}

const maximumBufferSeconds = 8;
const backBufferSeconds = 3;
// Must stay above the server fragment duration (500ms, http.live
// fragment_duration_ms): riding closer to the live edge than one fragment
// drains the buffer before the next fragment lands, which shows up as
// periodic waiting stalls and emergency-seek jumps.
const liveEdgeTargetSeconds = 1;
// Drift between the target and this threshold is left alone; past it the
// video plays slightly fast until the target is reached again. The band
// keeps the rate from flapping around a single boundary.
const catchUpThresholdSeconds = 1.25;
// 5% is invisible on a preview with no audio track, and converges from the
// threshold back to the target in a few seconds.
const catchUpPlaybackRate = 1.05;
// A hard seek is visible, so it is reserved for drift the catch-up rate
// would take too long to absorb — a stall, a suspended tab, a burst append.
const emergencySeekSeconds = 3;
const retryDelay = (attempt: number) => Math.min(1_000 * 2 ** attempt, 5_000);

const endpointUrl = (cameraId: string, generation: number) =>
  `/api/v1/cameras/${encodeURIComponent(cameraId)}/live.mp4?generation=${generation}`;

const abortError = () => new DOMException('operation aborted', 'AbortError');

function updateSourceBuffer(
  sourceBuffer: SourceBuffer,
  signal: AbortSignal,
  update: () => void,
): Promise<void> {
  if (signal.aborted) {
    return Promise.reject(abortError());
  }
  return new Promise((resolve, reject) => {
    const cleanup = () => {
      sourceBuffer.removeEventListener('updateend', onUpdateEnd);
      sourceBuffer.removeEventListener('error', onError);
      signal.removeEventListener('abort', onAbort);
    };
    const onUpdateEnd = () => {
      cleanup();
      resolve();
    };
    const onError = () => {
      cleanup();
      reject(new Error('source buffer update failed'));
    };
    const onAbort = () => {
      cleanup();
      reject(abortError());
    };

    sourceBuffer.addEventListener('updateend', onUpdateEnd, { once: true });
    sourceBuffer.addEventListener('error', onError, { once: true });
    signal.addEventListener('abort', onAbort, { once: true });
    try {
      update();
    } catch (error) {
      cleanup();
      reject(error);
    }
  });
}

async function maintainLiveBuffer(
  sourceBuffer: SourceBuffer,
  video: HTMLVideoElement,
  signal: AbortSignal,
) {
  const { buffered } = sourceBuffer;
  if (buffered.length === 0) {
    return;
  }
  const start = buffered.start(0);
  const end = buffered.end(buffered.length - 1);
  if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start) {
    return;
  }

  if (video.readyState > HTMLMediaElement.HAVE_NOTHING) {
    const drift = end - video.currentTime;
    if (video.currentTime < start || drift > emergencySeekSeconds) {
      video.currentTime = Math.max(start, end - liveEdgeTargetSeconds);
      video.playbackRate = 1;
    } else if (drift > catchUpThresholdSeconds) {
      video.playbackRate = catchUpPlaybackRate;
    } else if (drift <= liveEdgeTargetSeconds && video.playbackRate !== 1) {
      video.playbackRate = 1;
    }
  }

  const durationBound = end - maximumBufferSeconds;
  const playbackBound = video.readyState > HTMLMediaElement.HAVE_NOTHING
    ? video.currentTime - backBufferSeconds
    : durationBound;
  const removeBefore = Math.max(start, durationBound, playbackBound);
  if (removeBefore > start + 0.25) {
    await updateSourceBuffer(sourceBuffer, signal, () => {
      sourceBuffer.remove(start, removeBefore);
    });
  }
}

export function useLivePreview(cameraId: string): LivePreviewController {
  const videoRef = useRef<HTMLVideoElement>(null);
  const [restartToken, setRestartToken] = useState(0);
  const [resource, setResource] = useState<PreviewResource>(() => ({
    cameraId,
    state: cameraId.length > 0 ? 'connecting' : 'unavailable',
    generation: 0,
  }));
  const generation = useRef(0);
  const currentCameraId = useRef(cameraId);
  const activeSession = useRef<ActiveSession | null>(null);
  const retryAttempt = useRef(0);
  const retryTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  currentCameraId.current = cameraId;

  const cancelRetry = useCallback(() => {
    if (retryTimer.current !== null) {
      clearTimeout(retryTimer.current);
      retryTimer.current = null;
    }
  }, []);

  const closeSession = useCallback((session: ActiveSession) => {
    if (session.closed) {
      return;
    }
    session.closed = true;
    session.abortController.abort();
    if (session.reader !== null) {
      void session.reader.cancel().catch(() => undefined);
      session.reader = null;
    }
    if (session.sourceBuffer?.updating) {
      try {
        session.sourceBuffer.abort();
      } catch {
        // The MediaSource may already have detached the SourceBuffer.
      }
    }
    const video = videoRef.current;
    if (video?.getAttribute('src') === session.objectUrl) {
      video.removeAttribute('src');
    }
    URL.revokeObjectURL(session.objectUrl);
  }, []);

  useEffect(() => {
    cancelRetry();
    if (resource.cameraId !== cameraId) {
      retryAttempt.current = 0;
    }

    if (cameraId.length === 0) {
      setResource({ cameraId, state: 'unavailable', generation: 0 });
      return undefined;
    }
    if (typeof MediaSource === 'undefined' ||
        !MediaSource.isTypeSupported(LIVE_MP4_MIME_TYPE)) {
      setResource({ cameraId, state: 'unavailable', generation: 0 });
      return undefined;
    }
    const video = videoRef.current;
    if (video === null) {
      setResource({ cameraId, state: 'unavailable', generation: 0 });
      return undefined;
    }

    generation.current += 1;
    const sessionGeneration = generation.current;
    const state: LivePreviewState = retryAttempt.current === 0
      ? 'connecting' : 'reconnecting';
    setResource({ cameraId, state, generation: sessionGeneration });

    const mediaSource = new MediaSource();
    const objectUrl = URL.createObjectURL(mediaSource);
    const session: ActiveSession = {
      generation: sessionGeneration,
      mediaSource,
      objectUrl,
      abortController: new AbortController(),
      sourceBuffer: null,
      reader: null,
      closed: false,
      failed: false,
    };
    activeSession.current = session;
    video.src = objectUrl;

    const isCurrent = () => activeSession.current === session && !session.closed;
    const markLive = () => {
      if (!isCurrent()) {
        return;
      }
      retryAttempt.current = 0;
      setResource((current) => current.generation === session.generation
        ? { ...current, state: 'live' }
        : current);
    };
    const fail = (retryable: boolean, immediate = false) => {
      if (!isCurrent() || session.failed) {
        return;
      }
      session.failed = true;
      closeSession(session);
      activeSession.current = null;
      if (!retryable || currentCameraId.current.length === 0) {
        setResource((current) => current.generation === session.generation
          ? { ...current, state: 'unavailable' }
          : current);
        return;
      }

      setResource((current) => current.generation === session.generation
        ? { ...current, state: 'reconnecting' }
        : current);
      const delay = immediate ? 0 : retryDelay(retryAttempt.current);
      retryAttempt.current += 1;
      retryTimer.current = setTimeout(() => {
        retryTimer.current = null;
        setRestartToken((value) => value + 1);
      }, delay);
    };

    const pump = async () => {
      try {
        const sourceBuffer = mediaSource.addSourceBuffer(LIVE_MP4_MIME_TYPE);
        session.sourceBuffer = sourceBuffer;
        const response = await fetch(endpointUrl(cameraId, sessionGeneration), {
          method: 'GET',
          credentials: 'same-origin',
          cache: 'no-store',
          signal: session.abortController.signal,
        });
        if (!response.ok) {
          fail(response.status !== 401 && response.status !== 403);
          return;
        }
        if (response.body === null) {
          fail(true);
          return;
        }
        const reader = response.body.getReader();
        session.reader = reader;

        while (isCurrent()) {
          const next = await reader.read();
          if (next.done) {
            fail(true, true);
            return;
          }
          if (next.value.byteLength === 0) {
            continue;
          }
          await updateSourceBuffer(sourceBuffer, session.abortController.signal,
            () => sourceBuffer.appendBuffer(next.value));
          await maintainLiveBuffer(sourceBuffer, video,
            session.abortController.signal);
          if (video.readyState >= HTMLMediaElement.HAVE_CURRENT_DATA) {
            markLive();
          }
          void video.play().catch(() => undefined);
        }
      } catch {
        if (!session.abortController.signal.aborted) {
          fail(true);
        }
      }
    };

    const onSourceOpen = () => { void pump(); };
    const onMediaReady = () => markLive();
    const onMediaError = () => fail(true);
    mediaSource.addEventListener('sourceopen', onSourceOpen, { once: true });
    video.addEventListener('loadeddata', onMediaReady);
    video.addEventListener('playing', onMediaReady);
    video.addEventListener('error', onMediaError);

    return () => {
      mediaSource.removeEventListener('sourceopen', onSourceOpen);
      video.removeEventListener('loadeddata', onMediaReady);
      video.removeEventListener('playing', onMediaReady);
      video.removeEventListener('error', onMediaError);
      if (activeSession.current === session) {
        activeSession.current = null;
      }
      closeSession(session);
    };
  }, [cameraId, restartToken, cancelRetry, closeSession]);

  useEffect(() => () => {
    cancelRetry();
    if (activeSession.current !== null) {
      closeSession(activeSession.current);
      activeSession.current = null;
    }
  }, [cancelRetry, closeSession]);

  const reconnect = useCallback(() => {
    cancelRetry();
    retryAttempt.current = 0;
    setResource((current) => currentCameraId.current.length > 0
      ? { ...current, cameraId: currentCameraId.current, state: 'connecting' }
      : { cameraId: '', state: 'unavailable', generation: 0 });
    setRestartToken((value) => value + 1);
  }, [cancelRetry]);

  if (resource.cameraId !== cameraId) {
    return {
      state: cameraId.length > 0 ? 'connecting' : 'unavailable',
      generation: 0,
      videoRef,
      reconnect,
    };
  }
  return { ...resource, videoRef, reconnect };
}
