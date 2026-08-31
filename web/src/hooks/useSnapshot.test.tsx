import { act, renderHook, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { UnauthorizedError } from '../api/client';
import type { CameraApiClient } from '../api/types';
import { useSnapshot } from './useSnapshot';

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
  getJson: vi.fn(),
  deleteJson: vi.fn(),
  putJson: vi.fn(),
  postJson: vi.fn(),
  getBlob: vi.fn(),
  setUnauthorizedHandler: vi.fn(),
});

describe('useSnapshot', () => {
  beforeEach(() => {
    vi.stubGlobal('URL', {
      ...URL,
      createObjectURL: vi.fn((blob: Blob) => `blob:${blob.size}`),
      revokeObjectURL: vi.fn(),
    });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('loads an encoded camera snapshot through the authenticated blob client', async () => {
    const client = makeClient();
    vi.mocked(client.getBlob).mockResolvedValue(new Blob(['frame']));

    const { result } = renderHook(() => useSnapshot(client, 'imx708/main'));

    expect(result.current.state).toBe('loading');
    expect(client.getBlob).toHaveBeenCalledWith(
      '/api/v1/cameras/imx708%2Fmain/snapshot.jpg',
      expect.any(AbortSignal),
    );
    await waitFor(() => expect(result.current.state).toBe('ready'));
    expect(result.current.objectUrl).toBe('blob:5');
  });

  it('suppresses stale camera responses and aborts the superseded request', async () => {
    const client = makeClient();
    const first = deferred<Blob>();
    const second = deferred<Blob>();
    vi.mocked(client.getBlob)
      .mockReturnValueOnce(first.promise)
      .mockReturnValueOnce(second.promise);

    const { result, rerender } = renderHook(
      ({ id }) => useSnapshot(client, id),
      { initialProps: { id: 'cam/old' } },
    );
    const firstSignal = vi.mocked(client.getBlob).mock.calls[0][1]!;
    rerender({ id: 'cam/new' });

    expect(firstSignal.aborted).toBe(true);
    await act(async () => second.resolve(new Blob(['new'])));
    await waitFor(() => expect(result.current.objectUrl).toBe('blob:3'));
    await act(async () => first.resolve(new Blob(['stale-value'])));
    expect(result.current.objectUrl).toBe('blob:3');
    expect(URL.createObjectURL).toHaveBeenCalledOnce();
  });

  it('synchronously hides a ready camera URL when switching to a pending camera', async () => {
    const client = makeClient();
    const next = deferred<Blob>();
    vi.mocked(client.getBlob)
      .mockResolvedValueOnce(new Blob(['camera-a']))
      .mockReturnValueOnce(next.promise);
    vi.mocked(URL.createObjectURL).mockReturnValueOnce('blob:camera-a');

    const { result, rerender } = renderHook(
      ({ id }) => useSnapshot(client, id),
      { initialProps: { id: 'cam-a' } },
    );
    await waitFor(() => expect(result.current.state).toBe('ready'));
    expect(result.current.objectUrl).toBe('blob:camera-a');

    rerender({ id: 'cam-b' });

    expect(result.current.state).toBe('loading');
    expect(result.current.objectUrl).toBeNull();
  });

  it('replaces and revokes exactly its one owned object URL', async () => {
    const client = makeClient();
    vi.mocked(client.getBlob)
      .mockResolvedValueOnce(new Blob(['first']))
      .mockResolvedValueOnce(new Blob(['second-frame']));
    vi.mocked(URL.createObjectURL)
      .mockReturnValueOnce('blob:first')
      .mockReturnValueOnce('blob:second');

    const { result, unmount } = renderHook(() => useSnapshot(client, 'cam-a'));
    await waitFor(() => expect(result.current.objectUrl).toBe('blob:first'));
    await act(async () => result.current.refresh());

    expect(result.current.objectUrl).toBe('blob:second');
    expect(URL.revokeObjectURL).toHaveBeenCalledWith('blob:first');
    unmount();
    expect(URL.revokeObjectURL).toHaveBeenCalledWith('blob:second');
    expect(URL.revokeObjectURL).toHaveBeenCalledTimes(2);
  });

  it('aborts on unmount and exposes unavailable state for failed loads', async () => {
    const client = makeClient();
    const request = deferred<Blob>();
    vi.mocked(client.getBlob).mockReturnValue(request.promise);
    const { result, unmount } = renderHook(() => useSnapshot(client, 'cam-a'));
    const signal = vi.mocked(client.getBlob).mock.calls[0][1]!;

    unmount();
    expect(signal.aborted).toBe(true);
    await act(async () => request.reject(new DOMException('Aborted', 'AbortError')));

    const failedClient = makeClient();
    vi.mocked(failedClient.getBlob).mockRejectedValue(new Error('offline'));
    const failed = renderHook(() => useSnapshot(failedClient, 'cam-b'));
    await waitFor(() => expect(failed.result.current.state).toBe('unavailable'));
    expect(failed.result.current.objectUrl).toBeNull();
    failed.unmount();
  });

  it('propagates a manual refresh 401 after marking the snapshot unavailable', async () => {
    const client = makeClient();
    vi.mocked(client.getBlob)
      .mockResolvedValueOnce(new Blob(['frame']))
      .mockRejectedValueOnce(new UnauthorizedError());
    const { result } = renderHook(() => useSnapshot(client, 'cam-a'));
    await waitFor(() => expect(result.current.state).toBe('ready'));

    let rejection: unknown;
    await act(async () => {
      try {
        await result.current.refresh();
      } catch (error) {
        rejection = error;
      }
    });
    expect(rejection).toBeInstanceOf(UnauthorizedError);
    expect(result.current.state).toBe('unavailable');
    expect(result.current.objectUrl).toBeNull();
  });

  it('does not request a snapshot when no camera is selected', () => {
    const client = makeClient();
    const { result } = renderHook(() => useSnapshot(client, ''));

    expect(result.current.state).toBe('unavailable');
    expect(client.getBlob).not.toHaveBeenCalled();
  });
});
