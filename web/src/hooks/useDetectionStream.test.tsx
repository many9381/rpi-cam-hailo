import { act, cleanup, render, renderHook, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { DetectionSnapshot } from '../api/types';
import { useDetectionStream } from './useDetectionStream';

class FakeEventSource {
  static instances: FakeEventSource[] = [];

  readonly listeners = new Map<string, EventListener>();
  readonly close = vi.fn();
  onopen: ((event: Event) => void) | null = null;
  onerror: ((event: Event) => void) | null = null;

  constructor(readonly url: string) {
    FakeEventSource.instances.push(this);
  }

  addEventListener(type: string, listener: EventListener): void {
    this.listeners.set(type, listener);
  }

  emit(type: string, data: string): void {
    this.listeners.get(type)?.(new MessageEvent(type, { data }));
  }
}

const initial: DetectionSnapshot = { events: [{
  camera_id: 'cam-a', model_id: 'objects', model_kind: 'object_detection',
  result_state: 'decoded', frame_sequence: 10, frame_timestamp_ns: 100,
  detections: [],
}] };

const live: DetectionSnapshot = { events: [
  {
    camera_id: 'cam-a', model_id: 'objects', model_kind: 'object_detection',
    result_state: 'decoded', frame_sequence: 11, frame_timestamp_ns: 110,
    detections: [{ class_id: 0, label: 'person', confidence: 0.9,
      box: { x: 0.1, y: 0.2, width: 0.3, height: 0.4 }, keypoints: [] }],
  },
  {
    camera_id: 'cam-a', model_id: 'pose', model_kind: 'pose',
    result_state: 'decoded', frame_sequence: 11, frame_timestamp_ns: 110,
    detections: [{ class_id: 0, label: 'person', confidence: 0.8,
      box: { x: 0.2, y: 0.1, width: 0.2, height: 0.5 },
      keypoints: [{ name: 'nose', x: 0.3, y: 0.2, confidence: 0.95 }] }],
  },
] };

describe('useDetectionStream', () => {
  beforeEach(() => {
    FakeEventSource.instances = [];
    vi.stubGlobal('EventSource', FakeEventSource);
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('opens the exact detection stream once and starts from the initial snapshot', () => {
    const { result } = renderHook(() => useDetectionStream(initial, true));

    expect(FakeEventSource.instances).toHaveLength(1);
    expect(FakeEventSource.instances[0].url).toBe('/api/v1/ai/detections/stream');
    expect(result.current).toEqual({ status: 'connecting', snapshot: initial });
  });

  it('seeds the first active render when initial data arrives after mount', () => {
    const empty: DetectionSnapshot = { events: [] };
    const renders: DetectionSnapshot[] = [];
    function Probe({ active, snapshot }: {
      active: boolean;
      snapshot: DetectionSnapshot;
    }) {
      renders.push(useDetectionStream(snapshot, active).snapshot);
      return null;
    }
    const view = render(<Probe active={false} snapshot={empty} />);
    renders.length = 0;

    view.rerender(<Probe active snapshot={initial} />);

    expect(renders[0]).toBe(initial);
  });

  it('parses only named detections events and preserves pose keypoints', async () => {
    const { result } = renderHook(() => useDetectionStream(initial, true));
    const source = FakeEventSource.instances[0];

    act(() => source.emit('message', JSON.stringify({ events: [] })));
    expect(result.current.snapshot).toBe(initial);

    act(() => source.emit('detections', JSON.stringify(live)));
    await waitFor(() => expect(result.current.snapshot).toEqual(live));
    expect(result.current.snapshot.events[1].detections[0].keypoints[0].name)
      .toBe('nose');
  });

  it('keeps the last valid snapshot when a named event is malformed', async () => {
    const { result } = renderHook(() => useDetectionStream(initial, true));
    const source = FakeEventSource.instances[0];
    act(() => source.emit('detections', JSON.stringify(live)));
    await waitFor(() => expect(result.current.snapshot).toEqual(live));

    act(() => source.emit('detections', '{broken json'));
    expect(result.current.snapshot).toEqual(live);
    act(() => source.emit('detections', JSON.stringify({ events: 'invalid' })));
    expect(result.current.snapshot).toEqual(live);
  });

  it('reports browser connection state without creating a reconnect timer or source', () => {
    const setTimeoutSpy = vi.spyOn(window, 'setTimeout');
    const { result } = renderHook(() => useDetectionStream(initial, true));
    const source = FakeEventSource.instances[0];

    act(() => source.onopen?.(new Event('open')));
    expect(result.current.status).toBe('live');
    act(() => source.onerror?.(new Event('error')));
    expect(result.current.status).toBe('reconnecting');
    expect(FakeEventSource.instances).toHaveLength(1);
    expect(setTimeoutSpy).not.toHaveBeenCalled();
  });

  it('closes on disable and unmount and replaces the source when enabled again', () => {
    const { result, rerender, unmount } = renderHook(
      ({ active }) => useDetectionStream(initial, active),
      { initialProps: { active: true } },
    );
    const first = FakeEventSource.instances[0];

    rerender({ active: false });
    expect(first.close).toHaveBeenCalledOnce();
    expect(result.current.status).toBe('closed');

    rerender({ active: true });
    expect(FakeEventSource.instances).toHaveLength(2);
    const second = FakeEventSource.instances[1];
    unmount();
    expect(second.close).toHaveBeenCalledOnce();
  });
});
