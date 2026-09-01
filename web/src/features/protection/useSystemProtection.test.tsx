import { act, renderHook } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { ApiError } from '../../api/client';
import type { CameraApiClient, Parser } from '../../api/types';
import type { ProtectionSnapshot } from './contracts';
import { useSystemProtection } from './useSystemProtection';

const idleSnapshot = (): ProtectionSnapshot => ({
  state: 'operational',
  check_running: false,
  next_periodic_at_seconds: 1_721_444_800,
  self_test: null,
  integrity: null,
});

const runningSnapshot = (): ProtectionSnapshot => ({
  ...idleSnapshot(),
  state: 'checking',
  check_running: true,
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
  getJson: (vi.fn(async (_path: string, parser: Parser<unknown>) =>
    parser(idleSnapshot()),
  ) as CameraApiClient['getJson']),
  deleteJson: vi.fn(),
  putJson: vi.fn(),
  postJson: (vi.fn(async (_path: string, _body: unknown, parser: Parser<unknown>) =>
    parser(runningSnapshot()),
  ) as CameraApiClient['postJson']),
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

describe('useSystemProtection', () => {
  it('loads the administrator protection snapshot without any role input', async () => {
    const client = makeClient();
    const { result } = renderHook(() => useSystemProtection(client));

    expect(result.current.state).toBe('loading');
    expect(client.getJson).toHaveBeenCalledWith(
      '/api/v1/system/protection', expect.any(Function), expect.any(AbortSignal),
    );
    await flush();

    expect(result.current.state).toBe('ready');
    expect(result.current.snapshot).toEqual(idleSnapshot());
    expect(result.current.publicMessage).toBeNull();
    expect(result.current.activeCommand).toBeNull();
  });

  it('polls exactly once every 30 seconds only while the tab is visible', async () => {
    const client = makeClient();
    renderHook(() => useSystemProtection(client));
    await flush();

    await act(async () => vi.advanceTimersByTimeAsync(29_999));
    expect(client.getJson).toHaveBeenCalledTimes(1);
    await act(async () => vi.advanceTimersByTimeAsync(1));
    expect(client.getJson).toHaveBeenCalledTimes(2);

    visibility = 'hidden';
    act(() => document.dispatchEvent(new Event('visibilitychange')));
    await act(async () => vi.advanceTimersByTimeAsync(60_000));
    expect(client.getJson).toHaveBeenCalledTimes(2);

    visibility = 'visible';
    act(() => document.dispatchEvent(new Event('visibilitychange')));
    await flush();
    expect(client.getJson).toHaveBeenCalledTimes(3);
  });

  it('aborts its one active request on unmount', () => {
    const client = makeClient();
    const pending = deferred<ProtectionSnapshot>();
    vi.mocked(client.getJson).mockReturnValue(pending.promise);
    const { unmount } = renderHook(() => useSystemProtection(client));
    const signal = vi.mocked(client.getJson).mock.calls[0]?.[2];

    unmount();

    expect(signal?.aborted).toBe(true);
  });

  it('does not start a command or overlapping refresh while a request is active', async () => {
    const client = makeClient();
    const pending = deferred<ProtectionSnapshot>();
    vi.mocked(client.getJson).mockReturnValue(pending.promise);
    const { result } = renderHook(() => useSystemProtection(client));

    await act(async () => {
      await result.current.refresh();
      await result.current.runSelfTest();
      await result.current.runIntegrityCheck();
    });

    expect(client.getJson).toHaveBeenCalledOnce();
    expect(client.postJson).not.toHaveBeenCalled();
    await act(async () => pending.reject(new DOMException('Aborted', 'AbortError')));
  });

  it('does not start commands while the snapshot reports a running check', async () => {
    const client = makeClient();
    vi.mocked(client.getJson).mockResolvedValueOnce(runningSnapshot());
    const { result } = renderHook(() => useSystemProtection(client));
    await flush();

    await act(async () => {
      await result.current.runSelfTest();
      await result.current.runIntegrityCheck();
    });

    expect(client.postJson).not.toHaveBeenCalled();
  });

  it('reports loading while a command request is active for panel command disabling', async () => {
    const client = makeClient();
    const pending = deferred<ProtectionSnapshot>();
    const { result } = renderHook(() => useSystemProtection(client));
    await flush();
    vi.mocked(client.postJson).mockReturnValueOnce(pending.promise);

    let run!: Promise<void>;
    act(() => {
      run = result.current.runSelfTest();
    });

    expect(result.current.state).toBe('loading');
    await act(async () => {
      pending.resolve(runningSnapshot());
      await run;
    });
    expect(result.current.state).toBe('ready');
  });

  it('publishes the accepted self-test snapshot and polls it on the bounded cadence', async () => {
    const client = makeClient();
    const { result } = renderHook(() => useSystemProtection(client));
    await flush();

    await act(async () => result.current.runSelfTest());

    expect(client.postJson).toHaveBeenCalledWith(
      '/api/v1/system/self-tests', {}, expect.any(Function), expect.any(AbortSignal),
    );
    expect(result.current.state).toBe('ready');
    expect(result.current.snapshot).toEqual(runningSnapshot());
    expect(result.current.activeCommand).toBe('self_test');

    await act(async () => vi.advanceTimersByTimeAsync(29_999));
    expect(client.getJson).toHaveBeenCalledOnce();
    await act(async () => vi.advanceTimersByTimeAsync(1));
    expect(client.getJson).toHaveBeenCalledTimes(2);
    expect(result.current.snapshot).toEqual(idleSnapshot());
    expect(result.current.activeCommand).toBeNull();
  });

  it('maps a conflict to the stable public message without private details', async () => {
    const client = makeClient();
    const { result } = renderHook(() => useSystemProtection(client));
    await flush();
    vi.mocked(client.postJson).mockRejectedValueOnce(new ApiError(
      409, 'E_PROTECTION_CHECK_RUNNING', '/private/check id=123',
    ));

    await act(async () => result.current.runIntegrityCheck());

    expect(result.current.publicMessage).toBe('protection.checkAlreadyRunning');
    expect(result.current.publicMessage).not.toContain('/private');
    expect(result.current.state).toBe('ready');
    expect(result.current.activeCommand).toBeNull();
  });

  it('retains the last accepted snapshot as stale when refresh fails', async () => {
    const client = makeClient();
    const { result } = renderHook(() => useSystemProtection(client));
    await flush();
    const retained = result.current.snapshot;
    vi.mocked(client.getJson).mockRejectedValueOnce(new Error('/private/offline'));

    await act(async () => {
      await expect(result.current.refresh()).rejects.toThrow('/private/offline');
    });

    expect(result.current.state).toBe('stale');
    expect(result.current.snapshot).toBe(retained);
  });
});
