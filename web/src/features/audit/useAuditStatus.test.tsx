import { act, renderHook } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { CameraApiClient, Parser } from '../../api/types';
import type { AuditStatus } from './contracts';
import { useAuditStatus } from './useAuditStatus';

const rawStatus = (currentEvents = 45): AuditStatus => ({
  current_events: currentEvents,
  max_events: 50,
  usage_percent: Math.min(100, currentEvents * 2),
  warning: currentEvents >= 45,
  rotated_event_count: 7,
  last_rotation_at_seconds: 1_234,
  last_rotated_sequence: 91,
});

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
  getJson: vi.fn(async (_path: string, parser: Parser<unknown>) =>
    parser(rawStatus()),
  ) as CameraApiClient['getJson'],
  deleteJson: vi.fn(),
  putJson: vi.fn(),
  postJson: vi.fn(),
  getBlob: vi.fn(),
  setUnauthorizedHandler: vi.fn(),
});

const flush = async () => {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
  });
};

let visibility: DocumentVisibilityState;

beforeEach(() => {
  vi.useFakeTimers();
  visibility = 'visible';
  Object.defineProperty(document, 'visibilityState', {
    configurable: true,
    get: () => visibility,
  });
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
  delete (document as { visibilityState?: DocumentVisibilityState }).visibilityState;
});

describe('useAuditStatus', () => {
  it('requests status immediately and adopts the strict parsed response', async () => {
    const client = makeClient();
    const { result } = renderHook(() => useAuditStatus(client));

    expect(result.current.state).toBe('loading');
    expect(client.getJson).toHaveBeenCalledWith(
      '/api/v1/audit/status', expect.any(Function), expect.any(AbortSignal),
    );
    await flush();

    expect(result.current.state).toBe('ready');
    expect(result.current.data).toEqual(rawStatus());
    expect(vi.mocked(client.getJson).mock.calls.every(
      ([path]) => path === '/api/v1/audit/status',
    )).toBe(true);
  });

  it('polls exactly once every 30 seconds while visible', async () => {
    const client = makeClient();
    const { unmount } = renderHook(() => useAuditStatus(client));
    await flush();

    await act(async () => vi.advanceTimersByTimeAsync(29_999));
    expect(client.getJson).toHaveBeenCalledTimes(1);
    await act(async () => vi.advanceTimersByTimeAsync(1));
    expect(client.getJson).toHaveBeenCalledTimes(2);
    await act(async () => vi.advanceTimersByTimeAsync(30_000));
    expect(client.getJson).toHaveBeenCalledTimes(3);

    unmount();
    await act(async () => vi.advanceTimersByTimeAsync(30_000));
    expect(client.getJson).toHaveBeenCalledTimes(3);
  });

  it('does not poll while hidden and refreshes immediately when visible again', async () => {
    visibility = 'hidden';
    const client = makeClient();
    renderHook(() => useAuditStatus(client));
    await flush();

    expect(client.getJson).toHaveBeenCalledTimes(1);
    await act(async () => vi.advanceTimersByTimeAsync(90_000));
    expect(client.getJson).toHaveBeenCalledTimes(1);

    visibility = 'visible';
    act(() => document.dispatchEvent(new Event('visibilitychange')));
    await flush();
    expect(client.getJson).toHaveBeenCalledTimes(2);
    await act(async () => vi.advanceTimersByTimeAsync(30_000));
    expect(client.getJson).toHaveBeenCalledTimes(3);

    visibility = 'hidden';
    act(() => document.dispatchEvent(new Event('visibilitychange')));
    await act(async () => vi.advanceTimersByTimeAsync(60_000));
    expect(client.getJson).toHaveBeenCalledTimes(3);
  });

  it('gives the newest manual refresh sole generation ownership', async () => {
    const client = makeClient();
    const { result } = renderHook(() => useAuditStatus(client));
    await flush();
    const older = deferred<AuditStatus>();
    const newer = deferred<AuditStatus>();
    vi.mocked(client.getJson)
      .mockReturnValueOnce(older.promise)
      .mockReturnValueOnce(newer.promise);

    let olderRefresh!: Promise<void>;
    let newerRefresh!: Promise<void>;
    act(() => {
      olderRefresh = result.current.refresh();
      newerRefresh = result.current.refresh();
    });
    const calls = vi.mocked(client.getJson).mock.calls;
    expect(calls[calls.length - 2]?.[2]?.aborted).toBe(true);
    expect(calls[calls.length - 1]?.[2]?.aborted).toBe(false);

    await act(async () => {
      newer.resolve(rawStatus(49));
      await newerRefresh;
    });
    await act(async () => {
      older.resolve(rawStatus(10));
      await olderRefresh;
    });

    expect(result.current.state).toBe('ready');
    expect(result.current.data?.current_events).toBe(49);
  });

  it('ignores an older late rejection after a newer refresh succeeds', async () => {
    const client = makeClient();
    const { result } = renderHook(() => useAuditStatus(client));
    await flush();
    const older = deferred<AuditStatus>();
    const newer = deferred<AuditStatus>();
    vi.mocked(client.getJson)
      .mockReturnValueOnce(older.promise)
      .mockReturnValueOnce(newer.promise);

    let olderRefresh!: Promise<void>;
    let newerRefresh!: Promise<void>;
    act(() => {
      olderRefresh = result.current.refresh();
      newerRefresh = result.current.refresh();
    });
    await act(async () => {
      newer.resolve(rawStatus(49));
      await newerRefresh;
    });
    await act(async () => {
      older.reject(new Error('late private failure'));
      await expect(olderRefresh).resolves.toBeUndefined();
    });

    expect(result.current.state).toBe('ready');
    expect(result.current.data?.current_events).toBe(49);
  });

  it('keeps committed data when the authoritative newer refresh fails', async () => {
    const client = makeClient();
    const { result } = renderHook(() => useAuditStatus(client));
    await flush();
    const retained = result.current.data;
    const older = deferred<AuditStatus>();
    const newer = deferred<AuditStatus>();
    vi.mocked(client.getJson)
      .mockReturnValueOnce(older.promise)
      .mockReturnValueOnce(newer.promise);

    let olderRefresh!: Promise<void>;
    let newerRefresh!: Promise<void>;
    act(() => {
      olderRefresh = result.current.refresh();
      newerRefresh = result.current.refresh();
    });
    await act(async () => {
      older.resolve(rawStatus(10));
      await olderRefresh;
    });
    await act(async () => {
      newer.reject(new Error('newest refresh failed'));
      await expect(newerRefresh).rejects.toThrow('newest refresh failed');
    });

    expect(result.current.state).toBe('stale');
    expect(result.current.data).toBe(retained);
  });

  it('aborts the active request on logout-driven shell unmount', async () => {
    const client = makeClient();
    const pending = deferred<AuditStatus>();
    vi.mocked(client.getJson).mockReturnValue(pending.promise);
    const { unmount } = renderHook(() => useAuditStatus(client));
    const signal = vi.mocked(client.getJson).mock.calls[0]?.[2];
    const onAbort = vi.fn();
    signal?.addEventListener('abort', onAbort);

    unmount();

    expect(signal?.aborted).toBe(true);
    expect(onAbort).toHaveBeenCalledOnce();
    await act(async () => pending.reject(new DOMException('Aborted', 'AbortError')));
  });

  it('removes visibility and polling work after unmount', async () => {
    const addListener = vi.spyOn(document, 'addEventListener');
    const removeListener = vi.spyOn(document, 'removeEventListener');
    const client = makeClient();
    const { unmount } = renderHook(() => useAuditStatus(client));
    await flush();
    const registration = addListener.mock.calls.find(
      ([type]) => type === 'visibilitychange',
    );
    const listener = registration?.[1];

    expect(listener).toEqual(expect.any(Function));
    unmount();

    expect(removeListener).toHaveBeenCalledWith('visibilitychange', listener);
    visibility = 'hidden';
    act(() => document.dispatchEvent(new Event('visibilitychange')));
    visibility = 'visible';
    act(() => document.dispatchEvent(new Event('visibilitychange')));
    await act(async () => vi.advanceTimersByTimeAsync(60_000));
    expect(client.getJson).toHaveBeenCalledTimes(1);
  });

  it('keeps the last known status stale after an authoritative refresh fails', async () => {
    const client = makeClient();
    const { result } = renderHook(() => useAuditStatus(client));
    await flush();
    const retained = result.current.data;
    vi.mocked(client.getJson).mockRejectedValueOnce(new Error('private offline detail'));

    await act(async () => {
      await expect(result.current.refresh()).rejects.toThrow('private offline detail');
    });

    expect(result.current.state).toBe('stale');
    expect(result.current.data).toBe(retained);
  });

  it('reports unavailable when no status has ever succeeded', async () => {
    const client = makeClient();
    vi.mocked(client.getJson).mockRejectedValue(new Error('offline'));
    const { result } = renderHook(() => useAuditStatus(client));

    await flush();

    expect(result.current.state).toBe('unavailable');
    expect(result.current.data).toBeNull();
  });
});
