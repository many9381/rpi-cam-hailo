import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { LIVE_MP4_MIME_TYPE, useLivePreview } from './useLivePreview';

class MockSourceBuffer extends EventTarget {
  updating = false;
  appended: Uint8Array[] = [];
  removed: Array<[number, number]> = [];
  abort = vi.fn();
  ranges: Array<[number, number]> = [];

  get buffered(): TimeRanges {
    return {
      length: this.ranges.length,
      start: (index: number) => this.ranges[index][0],
      end: (index: number) => this.ranges[index][1],
    };
  }

  appendBuffer(bytes: BufferSource) {
    const view = bytes instanceof ArrayBuffer
      ? new Uint8Array(bytes)
      : new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    this.appended.push(new Uint8Array(view));
    this.updating = true;
    queueMicrotask(() => {
      this.updating = false;
      this.dispatchEvent(new Event('updateend'));
    });
  }

  remove(start: number, end: number) {
    this.removed.push([start, end]);
    this.updating = true;
    queueMicrotask(() => {
      this.updating = false;
      this.dispatchEvent(new Event('updateend'));
    });
  }
}

class MockMediaSource extends EventTarget {
  static instances: MockMediaSource[] = [];
  static supported = true;
  static isTypeSupported = vi.fn(() => MockMediaSource.supported);

  readyState: ReadyState = 'closed';
  readonly sourceBuffer = new MockSourceBuffer();
  addedMimeType = '';
  endOfStream = vi.fn();

  constructor() {
    super();
    MockMediaSource.instances.push(this);
  }

  addSourceBuffer(mimeType: string) {
    this.addedMimeType = mimeType;
    return this.sourceBuffer as unknown as SourceBuffer;
  }

  open() {
    this.readyState = 'open';
    this.dispatchEvent(new Event('sourceopen'));
  }
}

interface MockReader {
  read: ReturnType<typeof vi.fn>;
  cancel: ReturnType<typeof vi.fn>;
}

const pendingRead = () => new Promise<ReadableStreamReadResult<Uint8Array>>(() => undefined);

function responseWithReader(results: ReadableStreamReadResult<Uint8Array>[]): MockReader {
  const queue = [...results];
  const reader: MockReader = {
    read: vi.fn(() => queue.length > 0
      ? Promise.resolve(queue.shift()!)
      : pendingRead()),
    cancel: vi.fn(() => Promise.resolve()),
  };
  vi.mocked(fetch).mockResolvedValue({
    ok: true,
    body: { getReader: () => reader },
  } as unknown as Response);
  return reader;
}

function Probe({ cameraId }: { cameraId: string }) {
  const preview = useLivePreview(cameraId);
  return (
    <div>
      <video ref={preview.videoRef} data-testid="video" />
      <span role="status">{preview.state}</span>
      <span data-testid="generation">{preview.generation}</span>
      <button type="button" onClick={preview.reconnect}>Reconnect</button>
    </div>
  );
}

beforeEach(() => {
  MockMediaSource.instances = [];
  MockMediaSource.supported = true;
  MockMediaSource.isTypeSupported.mockClear();
  vi.stubGlobal('MediaSource', MockMediaSource);
  vi.stubGlobal('fetch', vi.fn());
  Object.defineProperty(URL, 'createObjectURL', {
    configurable: true,
    value: vi.fn((source: MockMediaSource) =>
      `blob:live-${MockMediaSource.instances.indexOf(source) + 1}`),
  });
  Object.defineProperty(URL, 'revokeObjectURL', {
    configurable: true,
    value: vi.fn(),
  });
  vi.spyOn(HTMLMediaElement.prototype, 'play').mockResolvedValue();
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe('useLivePreview', () => {
  it('opens the authenticated live MP4 endpoint after MediaSource is ready', async () => {
    responseWithReader([]);
    render(<Probe cameraId="front/main camera" />);

    expect(screen.getByRole('status')).toHaveTextContent('connecting');
    expect(screen.getByTestId('video')).toHaveAttribute('src', 'blob:live-1');
    expect(fetch).not.toHaveBeenCalled();

    act(() => MockMediaSource.instances[0].open());
    await waitFor(() => expect(fetch).toHaveBeenCalledOnce());

    expect(MockMediaSource.isTypeSupported).toHaveBeenCalledWith(LIVE_MP4_MIME_TYPE);
    expect(MockMediaSource.instances[0].addedMimeType).toBe(LIVE_MP4_MIME_TYPE);
    expect(fetch).toHaveBeenCalledWith(
      '/api/v1/cameras/front%2Fmain%20camera/live.mp4?generation=1',
      expect.objectContaining({ credentials: 'same-origin', cache: 'no-store' }),
    );
    expect((vi.mocked(fetch).mock.calls[0][1] as RequestInit).signal)
      .toBeInstanceOf(AbortSignal);
  });

  it('appends response chunks in order and becomes live on loaded data', async () => {
    responseWithReader([
      { done: false, value: new Uint8Array([1, 2, 3]) },
      { done: false, value: new Uint8Array([4, 5]) },
    ]);
    render(<Probe cameraId="cam-a" />);

    act(() => MockMediaSource.instances[0].open());
    await waitFor(() => {
      expect(MockMediaSource.instances[0].sourceBuffer.appended).toHaveLength(2);
    });
    expect(MockMediaSource.instances[0].sourceBuffer.appended)
      .toEqual([new Uint8Array([1, 2, 3]), new Uint8Array([4, 5])]);

    fireEvent.loadedData(screen.getByTestId('video'));
    expect(screen.getByRole('status')).toHaveTextContent('live');
  });

  it('trims buffered media behind playback to keep memory bounded', async () => {
    responseWithReader([
      { done: false, value: new Uint8Array([1, 2, 3]) },
    ]);
    render(<Probe cameraId="cam-a" />);
    const video = screen.getByTestId('video');
    Object.defineProperties(video, {
      readyState: { configurable: true, value: HTMLMediaElement.HAVE_ENOUGH_DATA },
      currentTime: { configurable: true, writable: true, value: 11.5 },
    });
    MockMediaSource.instances[0].sourceBuffer.ranges = [[0, 12]];

    act(() => MockMediaSource.instances[0].open());

    await waitFor(() => {
      expect(MockMediaSource.instances[0].sourceBuffer.removed)
        .toEqual([[0, 8.5]]);
    });
  });

  it('reconnects with backoff after the HTTP stream ends', async () => {
    vi.useFakeTimers();
    responseWithReader([{ done: true, value: undefined }]);
    render(<Probe cameraId="cam-a" />);

    act(() => MockMediaSource.instances[0].open());
    await act(async () => { await Promise.resolve(); });
    await act(async () => { await Promise.resolve(); });
    expect(screen.getByRole('status')).toHaveTextContent('reconnecting');
    expect(MockMediaSource.instances).toHaveLength(1);

    act(() => vi.advanceTimersByTime(999));
    expect(MockMediaSource.instances).toHaveLength(1);
    act(() => vi.advanceTimersByTime(1));
    expect(MockMediaSource.instances).toHaveLength(2);
    expect(screen.getByTestId('generation')).toHaveTextContent('2');
  });

  it('aborts and releases the previous stream on manual reconnect', async () => {
    const firstReader = responseWithReader([]);
    const user = userEvent.setup();
    render(<Probe cameraId="cam-a" />);
    act(() => MockMediaSource.instances[0].open());
    await waitFor(() => expect(fetch).toHaveBeenCalledOnce());

    await user.click(screen.getByRole('button', { name: 'Reconnect' }));

    expect(firstReader.cancel).toHaveBeenCalledOnce();
    expect(URL.revokeObjectURL).toHaveBeenCalledWith('blob:live-1');
    expect(MockMediaSource.instances).toHaveLength(2);
    expect(screen.getByTestId('generation')).toHaveTextContent('2');
    expect(screen.getByRole('status')).toHaveTextContent('connecting');
  });

  it('fails closed without fetching when the required codec is unsupported', () => {
    MockMediaSource.supported = false;
    render(<Probe cameraId="cam-a" />);

    expect(screen.getByRole('status')).toHaveTextContent('unavailable');
    expect(fetch).not.toHaveBeenCalled();
    expect(MockMediaSource.instances).toHaveLength(0);
  });

  it('does not allocate a stream without a selected camera', () => {
    render(<Probe cameraId="" />);

    expect(screen.getByRole('status')).toHaveTextContent('unavailable');
    expect(MockMediaSource.instances).toHaveLength(0);
    expect(fetch).not.toHaveBeenCalled();
  });
});
