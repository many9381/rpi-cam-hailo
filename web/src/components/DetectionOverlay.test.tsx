import { act, render } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { DetectionSnapshot } from '../api/types';
import { DetectionOverlay } from './DetectionOverlay';

let resizeCallback: ResizeObserverCallback;
let resizeObserver: ResizeObserverMock;

class ResizeObserverMock {
  constructor(callback: ResizeObserverCallback) {
    resizeCallback = callback;
    resizeObserver = this;
  }
  observe = vi.fn();
  disconnect = vi.fn();
  unobserve = vi.fn();
}

const snapshot: DetectionSnapshot = { events: [{
  camera_id: 'cam-a', model_id: 'detector', model_kind: 'object_detection',
  result_state: 'ready', frame_sequence: 1, frame_timestamp_ns: 2,
  detections: [{
    label: 'person', confidence: 0.75,
    box: { x: 0.1, y: 0.2, width: 0.5, height: 0.5 },
    keypoints: [
      { name: 'left_shoulder', x: 0.2, y: 0.3, confidence: 0.9 },
      { name: 'right_shoulder', x: 0.4, y: 0.3, confidence: 0.8 },
    ],
  }],
}] };

describe('DetectionOverlay', () => {
  const context = {
    setTransform: vi.fn(), clearRect: vi.fn(), scale: vi.fn(),
    beginPath: vi.fn(), moveTo: vi.fn(), lineTo: vi.fn(), stroke: vi.fn(),
    strokeRect: vi.fn(), fillRect: vi.fn(), fillText: vi.fn(), arc: vi.fn(), fill: vi.fn(),
    strokeStyle: '', fillStyle: '', lineWidth: 0, font: '', textBaseline: '',
  };

  beforeEach(() => {
    vi.stubGlobal('ResizeObserver', ResizeObserverMock);
    vi.stubGlobal('devicePixelRatio', 2);
    vi.spyOn(HTMLCanvasElement.prototype, 'getContext')
      .mockReturnValue(context as unknown as CanvasRenderingContext2D);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
    Object.values(context).forEach((value) => {
      if (typeof value === 'function' && 'mockClear' in value) {
        value.mockClear();
      }
    });
  });

  it('sizes its backing store by DPR, resets the transform, and draws pixel primitives', () => {
    const { container, unmount } = render(
      <DetectionOverlay snapshot={snapshot} cameraId="cam-a"
        imageWidth={320} imageHeight={180} />,
    );
    const canvas = container.querySelector('canvas')!;

    act(() => resizeCallback([{
      target: canvas,
      contentRect: { width: 320, height: 180 },
    } as unknown as ResizeObserverEntry], {} as ResizeObserver));

    expect(canvas.width).toBe(640);
    expect(canvas.height).toBe(360);
    expect(context.setTransform).toHaveBeenLastCalledWith(1, 0, 0, 1, 0, 0);
    expect(context.clearRect).toHaveBeenLastCalledWith(0, 0, 640, 360);
    expect(context.scale).toHaveBeenLastCalledWith(2, 2);
    const [x, y, width, height] = context.strokeRect.mock.calls[0];
    expect(x).toBeCloseTo(32);
    expect(y).toBeCloseTo(36);
    expect(width).toBeCloseTo(160);
    expect(height).toBeCloseTo(90);
    expect(context.fillText).toHaveBeenCalledWith('person 75%', 36, 40);
    expect(context.moveTo).toHaveBeenCalledWith(64, 54);
    expect(context.lineTo).toHaveBeenCalledWith(128, 54);
    unmount();
    expect(resizeObserver.disconnect).toHaveBeenCalledOnce();
  });

  it('resets the transform again before every redraw', () => {
    const view = render(<DetectionOverlay snapshot={snapshot} cameraId="cam-a"
      imageWidth={100} imageHeight={100} />);
    const canvas = view.container.querySelector('canvas')!;
    act(() => resizeCallback([{
      target: canvas, contentRect: { width: 100, height: 100 },
    } as unknown as ResizeObserverEntry], {} as ResizeObserver));
    const initialCalls = context.setTransform.mock.calls.length;

    view.rerender(<DetectionOverlay snapshot={{ events: [] }} cameraId="cam-a"
      imageWidth={100} imageHeight={100} />);

    expect(context.setTransform.mock.calls.length).toBe(initialCalls + 1);
    expect(context.setTransform).toHaveBeenLastCalledWith(1, 0, 0, 1, 0, 0);
  });

  it('draws into the object-contain rectangle while the canvas fills the stage', () => {
    const { container } = render(
      <DetectionOverlay snapshot={snapshot} cameraId="cam-a"
        imageWidth={800} imageHeight={800} />,
    );
    const canvas = container.querySelector('canvas')!;

    act(() => resizeCallback([{
      target: canvas,
      contentRect: { width: 1600, height: 900 },
    } as unknown as ResizeObserverEntry], {} as ResizeObserver));

    expect(canvas).not.toHaveAttribute('style');
    const [x, y, width, height] = context.strokeRect.mock.lastCall!;
    expect(x).toBeCloseTo(440);
    expect(y).toBeCloseTo(180);
    expect(width).toBeCloseTo(450);
    expect(height).toBeCloseTo(450);
    expect(context.moveTo).toHaveBeenLastCalledWith(530, 270);
    expect(context.lineTo).toHaveBeenLastCalledWith(710, 270);
  });
});
