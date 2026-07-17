import { act, renderHook, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { CameraApiClient, MonitoringCameraList } from '../api/types';
import { useMonitoringData } from './useMonitoringData';

const cameras = (ids: string[]): MonitoringCameraList => ({
  cameras: ids.map((id) => ({
    id,
    state: 'streaming',
    width: 1920,
    height: 1080,
    snapshot_available: true,
  })),
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
  getJson: vi.fn(async (_path: string, parser: (value: unknown) => unknown) =>
    parser(cameras(['cam-a', 'cam-b'])),
  ) as CameraApiClient['getJson'],
  deleteJson: vi.fn(),
  putJson: vi.fn(),
  postJson: vi.fn(),
  getBlob: vi.fn(),
  setUnauthorizedHandler: vi.fn(),
});

afterEach(() => {
  vi.useRealTimers();
});

describe('useMonitoringData', () => {
  it('loads only monitoring cameras and selects the first camera', async () => {
    const client = makeClient();
    const { result } = renderHook(() => useMonitoringData(client));

    expect(result.current.state).toBe('loading');
    await waitFor(() => expect(result.current.state).toBe('ready'));

    expect(client.getJson).toHaveBeenCalledTimes(1);
    expect(client.getJson).toHaveBeenCalledWith(
      '/api/v1/monitoring/cameras', expect.any(Function), expect.any(AbortSignal),
    );
    expect(result.current.cameras.map(({ id }) => id)).toEqual(['cam-a', 'cam-b']);
    expect(result.current.selectedCameraId).toBe('cam-a');
  });

  it('preserves a selected camera or falls back when it disappears', async () => {
    const client = makeClient();
    const { result } = renderHook(() => useMonitoringData(client));
    await waitFor(() => expect(result.current.state).toBe('ready'));
    act(() => result.current.selectCamera('cam-b'));

    await act(async () => result.current.refresh());
    expect(result.current.selectedCameraId).toBe('cam-b');

    vi.mocked(client.getJson).mockImplementation(async (_path, parser) =>
      parser(cameras(['cam-c'])),
    );
    await act(async () => result.current.refresh());
    expect(result.current.selectedCameraId).toBe('cam-c');
  });

  it('keeps newer refresh data when an older request resolves last', async () => {
    const client = makeClient();
    const { result } = renderHook(() => useMonitoringData(client));
    await waitFor(() => expect(result.current.state).toBe('ready'));
    const older = deferred<MonitoringCameraList>();
    const newer = deferred<MonitoringCameraList>();
    vi.mocked(client.getJson)
      .mockReturnValueOnce(older.promise)
      .mockReturnValueOnce(newer.promise);

    const olderRefresh = result.current.refresh();
    const newerRefresh = result.current.refresh();
    const calls = vi.mocked(client.getJson).mock.calls;
    const olderSignal = calls[calls.length - 2]?.[2];
    expect(olderSignal?.aborted).toBe(true);

    await act(async () => {
      newer.resolve(cameras(['cam-new']));
      await newerRefresh;
    });
    await act(async () => {
      older.resolve(cameras(['cam-old']));
      await olderRefresh;
    });

    expect(result.current.cameras.map(({ id }) => id)).toEqual(['cam-new']);
    expect(result.current.selectedCameraId).toBe('cam-new');
  });

  it('ignores a superseded rejection after a newer refresh succeeds', async () => {
    const client = makeClient();
    const { result } = renderHook(() => useMonitoringData(client));
    await waitFor(() => expect(result.current.state).toBe('ready'));
    const older = deferred<MonitoringCameraList>();
    vi.mocked(client.getJson)
      .mockReturnValueOnce(older.promise)
      .mockResolvedValueOnce(cameras(['cam-new']));

    const olderRefresh = result.current.refresh();
    await act(async () => result.current.refresh());
    await act(async () => {
      older.reject(new Error('stale request'));
      await olderRefresh;
    });

    expect(result.current.state).toBe('ready');
    expect(result.current.cameras.map(({ id }) => id)).toEqual(['cam-new']);
  });

  it('aborts its request on unmount and ignores a stale rejection', async () => {
    const client = makeClient();
    const pending = deferred<MonitoringCameraList>();
    vi.mocked(client.getJson).mockReturnValue(pending.promise);
    const { result, unmount } = renderHook(() => useMonitoringData(client));
    const signal = vi.mocked(client.getJson).mock.calls[0][2]!;

    unmount();
    expect(signal.aborted).toBe(true);
    await act(async () => pending.reject(new DOMException('Aborted', 'AbortError')));
    expect(result.current.state).toBe('loading');
  });

  it('retains the last successful cameras after a failed refresh', async () => {
    const client = makeClient();
    const { result } = renderHook(() => useMonitoringData(client));
    await waitFor(() => expect(result.current.state).toBe('ready'));
    vi.mocked(client.getJson).mockRejectedValue(new Error('offline'));

    await expect(result.current.refresh()).rejects.toThrow('offline');
    await waitFor(() => expect(result.current.state).toBe('stale'));
    expect(result.current.cameras.map(({ id }) => id)).toEqual(['cam-a', 'cam-b']);
    expect(result.current.selectedCameraId).toBe('cam-a');
  });

  it('reports error before a successful response', async () => {
    const client = makeClient();
    vi.mocked(client.getJson).mockRejectedValue(new Error('offline'));
    const { result } = renderHook(() => useMonitoringData(client));

    await waitFor(() => expect(result.current.state).toBe('error'));
    expect(result.current.cameras).toEqual([]);
    expect(result.current.selectedCameraId).toBe('');
  });

  it('refreshes once every five seconds and clears the interval on unmount', async () => {
    vi.useFakeTimers();
    const client = makeClient();
    const { result, unmount } = renderHook(() => useMonitoringData(client));
    await act(async () => Promise.resolve());
    expect(result.current.state).toBe('ready');

    await act(async () => vi.advanceTimersByTimeAsync(4999));
    expect(client.getJson).toHaveBeenCalledTimes(1);
    await act(async () => vi.advanceTimersByTimeAsync(1));
    expect(client.getJson).toHaveBeenCalledTimes(2);

    unmount();
    await act(async () => vi.advanceTimersByTimeAsync(5000));
    expect(client.getJson).toHaveBeenCalledTimes(2);
  });
});
