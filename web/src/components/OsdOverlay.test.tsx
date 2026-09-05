import { act, cleanup, render } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { OsdItem, OsdRuntimeSettings } from '../features/settings/contracts';
import { OsdOverlay } from './OsdOverlay';

let resizeCallback: ResizeObserverCallback;

class ResizeObserverMock {
  constructor(callback: ResizeObserverCallback) {
    resizeCallback = callback;
  }
  observe = vi.fn();
  disconnect = vi.fn();
  unobserve = vi.fn();
}

const item = (overrides: Partial<OsdItem>): OsdItem => ({
  type: 'custom_text', text: '', position: 'top_left', ...overrides,
});

const osd = (items: OsdItem[], enabled = true): OsdRuntimeSettings => ({ enabled, items });

const corner = (container: HTMLElement, position: string): HTMLElement | null =>
  container.querySelector(`.osd-corner-${position}`);

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe('OsdOverlay', () => {
  it('renders nothing while OSD is disabled', () => {
    const { container } = render(
      <OsdOverlay osd={osd([item({ text: 'Front door' })], false)} cameraId="cam-a" />,
    );

    expect(container).toBeEmptyDOMElement();
  });

  it('places each item in its corner and stacks same-corner items in order', () => {
    const { container } = render(
      <OsdOverlay osd={osd([
        item({ text: 'Front door', position: 'bottom_right' }),
        item({ type: 'camera_name', position: 'top_left' }),
        item({ text: 'Zone 2', position: 'bottom_right' }),
      ])} cameraId="cam-a" />,
    );

    expect(corner(container, 'top_left')).toHaveTextContent('cam-a');
    const stacked = Array.from(corner(container, 'bottom_right')!.querySelectorAll('.osd-item'))
      .map((node) => node.textContent);
    expect(stacked).toEqual(['Front door', 'Zone 2']);
    expect(corner(container, 'top_right')).toBeNull();
    expect(corner(container, 'bottom_left')).toBeNull();
  });

  it('advances timestamp items once per second', () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(2026, 8, 5, 14, 30, 7));
    const { container } = render(
      <OsdOverlay osd={osd([item({ type: 'timestamp', position: 'top_right' })])} cameraId="cam-a" />,
    );
    expect(corner(container, 'top_right')).toHaveTextContent('2026-09-05 14:30:07');

    act(() => { vi.advanceTimersByTime(1_000); });

    expect(corner(container, 'top_right')).toHaveTextContent('2026-09-05 14:30:08');
  });

  it('anchors the frame to the letterboxed video rect and scales text from its height', () => {
    vi.stubGlobal('ResizeObserver', ResizeObserverMock);
    const { container } = render(
      <OsdOverlay osd={osd([item({ text: 'Front door' })])} cameraId="cam-a"
        imageWidth={1600} imageHeight={1200} />,
    );

    act(() => {
      resizeCallback([{ contentRect: { width: 800, height: 450 } } as ResizeObserverEntry],
        {} as ResizeObserver);
    });

    const frame = container.querySelector<HTMLElement>('.osd-frame')!;
    expect(frame.style.left).toBe('100px');
    expect(frame.style.top).toBe('0px');
    expect(frame.style.width).toBe('600px');
    expect(frame.style.height).toBe('450px');
    expect(frame.style.fontSize).toBe('15.75px');
    expect(frame.style.padding).toBe('9px');
  });

  it('fills the whole stage before the video reports its frame size', () => {
    vi.stubGlobal('ResizeObserver', ResizeObserverMock);
    const { container } = render(
      <OsdOverlay osd={osd([item({ text: 'Front door' })])} cameraId="cam-a" />,
    );

    act(() => {
      resizeCallback([{ contentRect: { width: 800, height: 450 } } as ResizeObserverEntry],
        {} as ResizeObserver);
    });

    const frame = container.querySelector<HTMLElement>('.osd-frame')!;
    expect(frame.style.left).toBe('0px');
    expect(frame.style.width).toBe('800px');
    expect(frame.style.height).toBe('450px');
  });
});
