import { act, renderHook, waitFor } from '@testing-library/react';
import { StrictMode, type ReactNode } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { UnauthorizedError } from '../api/client';
import type { CameraApiClient, DetectionSnapshot } from '../api/types';
import { useOperationalData } from './useOperationalData';

const health = { status: 'ok' };
const stream = {
  url: 'rtsps://camera.local:8555/imx708/main', control_tls: true,
  media_srtp: true, secure_media: {
    control_scheme: 'rtsps', media_profile: 'RTP/SAVPF',
    keying: 'SDES-over-RTSPS', requires_tls_control_channel: true,
    per_media_key_zeroize_count: 4,
  },
};
const disabledAi = {
  enabled: false, backend: 'disabled', state: 'disabled', model_count: 0,
  runner_count: 0, reason: 'disabled by config', models: [], runners: [],
};
const inventory = (ids: string[]) => ({
  cameras: ids.map((id) => ({ id, state: 'streaming', snapshot_available: true })),
  ai: disabledAi,
});
const detections: DetectionSnapshot = { events: [] };

const deferred = <T,>() => {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
};

const makeClient = (): CameraApiClient => ({
  getJson: vi.fn(async (path: string, parser: (value: unknown) => unknown) => {
    const values: Record<string, unknown> = {
      '/api/v1/health': health,
      '/api/v1/cameras': inventory(['cam-a', 'cam-b']),
      '/api/v1/stream': stream,
      '/api/v1/ai/detections': detections,
    };
    return parser(values[path]);
  }) as CameraApiClient['getJson'],
  putJson: vi.fn(),
  postJson: vi.fn(),
  getBlob: vi.fn(),
  setUnauthorizedHandler: vi.fn(),
});

afterEach(() => {
  vi.useRealTimers();
});

describe('useOperationalData', () => {
  it('loads all initial resources in parallel and selects the first camera', async () => {
    const client = makeClient();
    const { result } = renderHook(() => useOperationalData(client));

    expect(result.current.state).toBe('loading');
    await waitFor(() => expect(result.current.state).toBe('ready'));

    expect(vi.mocked(client.getJson).mock.calls.map(([path]) => path)).toEqual([
      '/api/v1/health', '/api/v1/cameras', '/api/v1/stream',
      '/api/v1/ai/detections',
    ]);
    expect(result.current.selectedCameraId).toBe('cam-a');
    expect(result.current.data?.detections).toEqual(detections);
  });

  it('polls status after 5000ms without refreshing detections and cleans up', async () => {
    vi.useFakeTimers();
    const client = makeClient();
    const { result, unmount } = renderHook(() => useOperationalData(client));
    await act(async () => Promise.resolve());
    expect(result.current.state).toBe('ready');

    await act(async () => vi.advanceTimersByTimeAsync(4999));
    expect(client.getJson).toHaveBeenCalledTimes(4);
    await act(async () => vi.advanceTimersByTimeAsync(1));
    expect(client.getJson).toHaveBeenCalledTimes(7);
    expect(vi.mocked(client.getJson).mock.calls.filter(
      ([path]) => path === '/api/v1/ai/detections',
    )).toHaveLength(1);

    unmount();
    await vi.advanceTimersByTimeAsync(5000);
    expect(client.getJson).toHaveBeenCalledTimes(7);
  });

  it('manually refreshes status and retains or falls back selected camera', async () => {
    const client = makeClient();
    const { result } = renderHook(() => useOperationalData(client));
    await waitFor(() => expect(result.current.state).toBe('ready'));
    act(() => result.current.selectCamera('cam-b'));

    await act(async () => result.current.refresh());
    expect(result.current.selectedCameraId).toBe('cam-b');

    vi.mocked(client.getJson).mockImplementation(async (path, parser) => {
      const value = path === '/api/v1/cameras' ? inventory(['cam-c'])
        : path === '/api/v1/health' ? health : stream;
      return parser(value);
    });
    await act(async () => result.current.refresh());
    expect(result.current.selectedCameraId).toBe('cam-c');
    expect(result.current.data?.detections).toEqual(detections);
  });

  it('replaces live detections and returned AI status without disturbing other data', async () => {
    const client = makeClient();
    const { result } = renderHook(() => useOperationalData(client));
    await waitFor(() => expect(result.current.state).toBe('ready'));
    const liveDetections = { events: [{
      camera_id: 'cam-a', model_id: 'pose', model_kind: 'pose',
      result_state: 'decoded', frame_sequence: 12, frame_timestamp_ns: 120,
      detections: [],
    }] };
    const restartedAi = { ...disabledAi, enabled: true, backend: 'hailo',
      state: 'ready', reason: 'AI runtime ready' };

    act(() => result.current.replaceDetections(liveDetections));
    act(() => result.current.replaceAiStatus(restartedAi));

    expect(result.current.data?.detections).toEqual(liveDetections);
    expect(result.current.data?.ai).toEqual(restartedAi);
    expect(result.current.data?.health).toEqual(health);
    expect(result.current.data?.stream).toEqual(stream);
  });

  it('keeps the newer refresh data and camera selection when an older refresh resolves last', async () => {
    const client = makeClient();
    const { result } = renderHook(() => useOperationalData(client));
    await waitFor(() => expect(result.current.state).toBe('ready'));

    const oldRefresh = {
      health: deferred<{ status: string }>(),
      cameras: deferred<ReturnType<typeof inventory>>(),
      stream: deferred<typeof stream>(),
    };
    const newRefresh = {
      health: deferred<{ status: string }>(),
      cameras: deferred<ReturnType<typeof inventory>>(),
      stream: deferred<typeof stream>(),
    };
    const refreshes = [oldRefresh, newRefresh];
    let requestIndex = 0;
    vi.mocked(client.getJson).mockImplementation((path, parser) => {
      const refresh = refreshes[Math.floor(requestIndex / 3)];
      requestIndex += 1;
      const response = path === '/api/v1/health' ? refresh.health
        : path === '/api/v1/cameras' ? refresh.cameras : refresh.stream;
      return response.promise.then(parser);
    });

    const olderRequest = result.current.refresh();
    const newerRequest = result.current.refresh();

    await act(async () => {
      newRefresh.health.resolve({ status: 'new' });
      newRefresh.cameras.resolve(inventory(['cam-new']));
      newRefresh.stream.resolve({ ...stream, url: 'rtsps://camera.local:8555/new' });
      await newerRequest;
    });

    await act(async () => {
      oldRefresh.health.resolve({ status: 'old' });
      oldRefresh.cameras.resolve(inventory(['cam-old']));
      oldRefresh.stream.resolve({ ...stream, url: 'rtsps://camera.local:8555/old' });
      await olderRequest;
    });

    expect(result.current.state).toBe('ready');
    expect(result.current.data?.health.status).toBe('new');
    expect(result.current.data?.cameras.map(({ id }) => id)).toEqual(['cam-new']);
    expect(result.current.data?.stream.url).toBe('rtsps://camera.local:8555/new');
    expect(result.current.selectedCameraId).toBe('cam-new');
  });

  it('aborts an in-flight status refresh when unmounted', async () => {
    const client = makeClient();
    const { result, unmount } = renderHook(() => useOperationalData(client));
    await waitFor(() => expect(result.current.state).toBe('ready'));

    const signals: AbortSignal[] = [];
    vi.mocked(client.getJson).mockImplementation(async (_path, _parser, signal) => {
      if (signal !== undefined) {
        signals.push(signal);
      }
      return new Promise(() => {});
    });

    act(() => {
      void result.current.refresh();
    });
    expect(signals).toHaveLength(3);

    unmount();
    expect(signals.every((signal) => signal.aborted)).toBe(true);
  });

  it('propagates a 401 from manual refresh while retaining stale data', async () => {
    const client = makeClient();
    const { result } = renderHook(() => useOperationalData(client));
    await waitFor(() => expect(result.current.state).toBe('ready'));
    vi.mocked(client.getJson).mockRejectedValue(new UnauthorizedError());

    await expect(result.current.refresh()).rejects.toBeInstanceOf(UnauthorizedError);
    await waitFor(() => expect(result.current.state).toBe('stale'));
    expect(result.current.data?.health.status).toBe('ok');
  });

  it('retries all resources after an initial failure and becomes ready', async () => {
    const client = makeClient();
    vi.mocked(client.getJson).mockRejectedValue(new Error('offline'));
    const { result } = renderHook(() => useOperationalData(client));
    await waitFor(() => expect(result.current.state).toBe('error'));

    vi.mocked(client.getJson).mockImplementation(async (path, parser) => {
      const values: Record<string, unknown> = {
        '/api/v1/health': { status: 'recovered' },
        '/api/v1/cameras': inventory(['cam-recovered']),
        '/api/v1/stream': { ...stream, url: 'rtsps://camera.local/recovered' },
        '/api/v1/ai/detections': detections,
      };
      return parser(values[path]);
    });

    await act(async () => result.current.refresh());

    expect(result.current.state).toBe('ready');
    expect(result.current.data?.health.status).toBe('recovered');
    expect(result.current.data?.detections).toEqual(detections);
    expect(result.current.selectedCameraId).toBe('cam-recovered');
    expect(vi.mocked(client.getJson).mock.calls.slice(-4).map(([path]) => path))
      .toEqual(['/api/v1/health', '/api/v1/cameras', '/api/v1/stream',
        '/api/v1/ai/detections']);
  });

  it('ignores a stale initial generation after a complete retry succeeds', async () => {
    const client = makeClient();
    const generations = Array.from({ length: 2 }, () => ({
      health: deferred<{ status: string }>(),
      cameras: deferred<ReturnType<typeof inventory>>(),
      stream: deferred<typeof stream>(),
      detections: deferred<typeof detections>(),
    }));
    let requestIndex = 0;
    vi.mocked(client.getJson).mockImplementation((path, parser) => {
      const generation = generations[Math.floor(requestIndex / 4)];
      requestIndex += 1;
      const response = path === '/api/v1/health' ? generation.health
        : path === '/api/v1/cameras' ? generation.cameras
          : path === '/api/v1/stream' ? generation.stream
            : generation.detections;
      return response.promise.then(parser);
    });
    const { result } = renderHook(() => useOperationalData(client));

    const retry = result.current.refresh();
    await act(async () => {
      generations[1].health.resolve({ status: 'new' });
      generations[1].cameras.resolve(inventory(['cam-new']));
      generations[1].stream.resolve({ ...stream, url: 'rtsps://camera.local/new' });
      generations[1].detections.resolve(detections);
      await retry;
    });
    await act(async () => {
      generations[0].health.resolve({ status: 'old' });
      generations[0].cameras.resolve(inventory(['cam-old']));
      generations[0].stream.resolve({ ...stream, url: 'rtsps://camera.local/old' });
      generations[0].detections.resolve({ events: [{
        camera_id: 'cam-old', model_id: 'old', model_kind: 'old',
        result_state: 'old', frame_sequence: 1, frame_timestamp_ns: 1,
        detections: [],
      }] });
      await Promise.resolve();
    });

    expect(result.current.state).toBe('ready');
    expect(result.current.data?.health.status).toBe('new');
    expect(result.current.data?.cameras.map(({ id }) => id)).toEqual(['cam-new']);
    expect(result.current.data?.detections).toEqual(detections);
  });

  it('continues to refresh after the Strict Mode effect replay', async () => {
    const client = makeClient();
    const wrapper = ({ children }: { children: ReactNode }) => (
      <StrictMode>{children}</StrictMode>
    );
    const { result } = renderHook(() => useOperationalData(client), { wrapper });
    await waitFor(() => expect(result.current.state).toBe('ready'));
    vi.mocked(client.getJson).mockImplementation(async (path, parser) => {
      const value = path === '/api/v1/cameras' ? inventory(['cam-c'])
        : path === '/api/v1/health' ? { status: 'degraded' } : stream;
      return parser(value);
    });

    await act(async () => result.current.refresh());

    expect(result.current.data?.health.status).toBe('degraded');
    expect(result.current.selectedCameraId).toBe('cam-c');
  });

  it('completes a newer manual load while the initial generation is pending', async () => {
    const client = makeClient();
    let requestCount = 0;
    vi.mocked(client.getJson).mockImplementation(async (path, parser) => {
      requestCount += 1;
      if (requestCount <= 4) {
        return new Promise(() => {});
      }
      const value = path === '/api/v1/cameras' ? inventory(['cam-c'])
        : path === '/api/v1/health' ? health
          : path === '/api/v1/stream' ? stream : detections;
      return parser(value);
    });
    const { result } = renderHook(() => useOperationalData(client));

    await act(async () => result.current.refresh());

    expect(result.current.state).toBe('ready');
    expect(result.current.selectedCameraId).toBe('cam-c');
    expect(result.current.data?.detections).toEqual(detections);
  });
});
