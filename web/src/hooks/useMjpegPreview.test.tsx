import { act, cleanup, render, renderHook } from '@testing-library/react';
import { StrictMode, type ReactNode, useLayoutEffect } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { useMjpegPreview } from './useMjpegPreview';

const streamUrl = (cameraId: string, generation: number) =>
  `/api/v1/cameras/${encodeURIComponent(cameraId)}/preview.mjpeg?generation=${generation}`;

function StrictWrapper({ children }: { children: ReactNode }) {
  return <StrictMode>{children}</StrictMode>;
}

afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

describe('useMjpegPreview', () => {
  it('starts connecting with an encoded camera URL and first generation', () => {
    const { result } = renderHook(() => useMjpegPreview('front/main camera'));

    expect(result.current.state).toBe('connecting');
    expect(result.current.streamUrl).toBe(streamUrl('front/main camera', 1));
  });

  it('accepts the initial image load after StrictMode mount replay', () => {
    const { result } = renderHook(() => useMjpegPreview('cam-a'), {
      wrapper: StrictWrapper,
    });
    const initialUrl = result.current.streamUrl;
    let accepted: unknown;

    act(() => { accepted = result.current.onLoad(initialUrl); });

    expect(accepted).toBe(true);
    expect(result.current).toMatchObject({ state: 'live', streamUrl: initialUrl });
  });

  it('retries the initial image error after StrictMode mount replay', () => {
    vi.useFakeTimers();
    const { result } = renderHook(() => useMjpegPreview('cam-a'), {
      wrapper: StrictWrapper,
    });

    let accepted: unknown;
    act(() => { accepted = result.current.onError(result.current.streamUrl); });
    expect(accepted).toBe(true);
    expect(result.current).toMatchObject({ state: 'reconnecting', streamUrl: '' });
    act(() => vi.advanceTimersByTime(1_000));

    expect(result.current).toMatchObject({
      state: 'reconnecting', streamUrl: streamUrl('cam-a', 2),
    });
  });

  it('becomes live on load and resets retry backoff after success', () => {
    vi.useFakeTimers();
    const { result } = renderHook(() => useMjpegPreview('cam-a'));
    const firstUrl = result.current.streamUrl;

    act(() => result.current.onError(firstUrl));
    act(() => vi.advanceTimersByTime(1_000));
    const retryUrl = result.current.streamUrl;
    act(() => result.current.onLoad(retryUrl));
    expect(result.current.state).toBe('live');

    act(() => result.current.onError(retryUrl));
    act(() => vi.advanceTimersByTime(999));
    expect(result.current.streamUrl).toBe('');
    act(() => vi.advanceTimersByTime(1));
    expect(result.current.streamUrl).toBe(streamUrl('cam-a', 3));
  });

  it('removes a failed URL and retries with bounded exponential backoff', () => {
    vi.useFakeTimers();
    const { result } = renderHook(() => useMjpegPreview('cam-a'));

    for (const [delay, generation] of [[1_000, 2], [2_000, 3], [4_000, 4], [5_000, 5], [5_000, 6]]) {
      const failedUrl = result.current.streamUrl;
      act(() => result.current.onError(failedUrl));
      expect(result.current).toMatchObject({ state: 'reconnecting', streamUrl: '' });
      act(() => vi.advanceTimersByTime(delay - 1));
      expect(result.current.streamUrl).toBe('');
      act(() => vi.advanceTimersByTime(1));
      expect(result.current.streamUrl).toBe(streamUrl('cam-a', generation));
    }
  });

  it('ignores stale load and error callbacks from replaced URLs', () => {
    vi.useFakeTimers();
    const { result, rerender } = renderHook(({ cameraId }) => useMjpegPreview(cameraId), {
      initialProps: { cameraId: 'cam-a' },
    });
    const oldUrl = result.current.streamUrl;

    act(() => result.current.reconnect());
    const currentUrl = result.current.streamUrl;
    let staleLoadAccepted: unknown;
    let staleErrorAccepted: unknown;
    act(() => { staleLoadAccepted = result.current.onLoad(oldUrl); });
    act(() => { staleErrorAccepted = result.current.onError(oldUrl); });
    expect(staleLoadAccepted).toBe(false);
    expect(staleErrorAccepted).toBe(false);
    expect(result.current).toMatchObject({ state: 'connecting', streamUrl: currentUrl });

    rerender({ cameraId: 'cam-b' });
    const cameraUrl = result.current.streamUrl;
    act(() => result.current.onLoad(currentUrl));
    act(() => result.current.onError(currentUrl));
    expect(result.current).toMatchObject({ state: 'connecting', streamUrl: cameraUrl });
  });

  it('reconnects immediately and cancels a pending retry', () => {
    vi.useFakeTimers();
    const { result } = renderHook(() => useMjpegPreview('cam-a'));
    const failedUrl = result.current.streamUrl;
    act(() => result.current.onError(failedUrl));
    act(() => result.current.reconnect());

    expect(result.current).toMatchObject({
      state: 'connecting', streamUrl: streamUrl('cam-a', 2),
    });
    act(() => vi.advanceTimersByTime(5_000));
    expect(result.current.streamUrl).toBe(streamUrl('cam-a', 2));
  });

  it('replaces the stream and cancels the old timer when the camera changes', () => {
    vi.useFakeTimers();
    const { result, rerender } = renderHook(({ cameraId }) => useMjpegPreview(cameraId), {
      initialProps: { cameraId: 'cam-a' },
    });
    act(() => result.current.onError(result.current.streamUrl));
    rerender({ cameraId: 'cam-b/main' });

    expect(result.current).toMatchObject({
      state: 'connecting', streamUrl: streamUrl('cam-b/main', 2),
    });
    act(() => vi.advanceTimersByTime(5_000));
    expect(result.current.streamUrl).toBe(streamUrl('cam-b/main', 2));
  });

  it('synchronizes a camera switch before exposing its URL or running an old retry', () => {
    vi.useFakeTimers();
    const renders: Array<{ cameraId: string; state: string; streamUrl: string }> = [];
    let current!: ReturnType<typeof useMjpegPreview>;

    function Probe({ cameraId, advanceOldRetry = false }: {
      cameraId: string;
      advanceOldRetry?: boolean;
    }) {
      current = useMjpegPreview(cameraId);
      renders.push({ cameraId, state: current.state, streamUrl: current.streamUrl });
      useLayoutEffect(() => {
        if (advanceOldRetry) {
          vi.advanceTimersByTime(1_000);
        }
      }, [advanceOldRetry]);
      return <span>{current.streamUrl}</span>;
    }

    const view = render(<Probe cameraId="cam-a" />);
    act(() => current.onError(current.streamUrl));
    const switchRenderStart = renders.length;

    view.rerender(<Probe cameraId="cam-b/main" advanceOldRetry />);

    const switchRenders = renders.slice(switchRenderStart);
    expect(switchRenders[0]).toEqual({
      cameraId: 'cam-b/main', state: 'connecting', streamUrl: '',
    });
    expect(switchRenders[switchRenders.length - 1]).toEqual({
      cameraId: 'cam-b/main',
      state: 'connecting',
      streamUrl: streamUrl('cam-b/main', 2),
    });
    expect(vi.getTimerCount()).toBe(0);
  });

  it('cleans up retry timers on unmount', () => {
    vi.useFakeTimers();
    const { result, unmount } = renderHook(() => useMjpegPreview('cam-a'));
    act(() => result.current.onError(result.current.streamUrl));
    unmount();
    act(() => vi.advanceTimersByTime(5_000));

    expect(vi.getTimerCount()).toBe(0);
  });

  it('returns no URL or retry timer without an available camera', () => {
    vi.useFakeTimers();
    const { result } = renderHook(() => useMjpegPreview(''));

    expect(result.current).toMatchObject({ state: 'unavailable', streamUrl: '' });
    expect(vi.getTimerCount()).toBe(0);
  });
});
