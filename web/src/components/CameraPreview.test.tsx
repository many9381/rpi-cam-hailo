import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { DetectionSnapshot } from '../api/types';
import type { MjpegPreviewController } from '../hooks/useMjpegPreview';
import { CameraPreview } from './CameraPreview';

let previewController: MjpegPreviewController;
let previewCameraId = '';

vi.mock('../hooks/useMjpegPreview', () => ({
  useMjpegPreview: (cameraId: string) => {
    previewCameraId = cameraId;
    return previewController;
  },
}));

vi.mock('./DetectionOverlay', () => ({
  DetectionOverlay: ({ imageWidth, imageHeight }: {
    imageWidth: number;
    imageHeight: number;
  }) => (
    <div data-testid="detection-overlay"
      data-image-width={imageWidth} data-image-height={imageHeight} />
  ),
}));

const detections: DetectionSnapshot = { events: [] };
const cameras = [
  { id: 'cam-a', state: 'streaming', snapshot_available: true },
  { id: 'cam-b', state: 'starting', snapshot_available: false },
];

const controller = (overrides: Partial<MjpegPreviewController> = {}): MjpegPreviewController => ({
  state: 'connecting',
  streamUrl: '/api/v1/cameras/cam-a/preview.mjpeg?generation=1',
  onLoad: vi.fn(() => true),
  onError: vi.fn(() => true),
  reconnect: vi.fn(),
  ...overrides,
});

afterEach(() => {
  cleanup();
});

describe('CameraPreview', () => {
  it('renders the stable connecting stage, selector, and reconnect control', async () => {
    const user = userEvent.setup();
    previewController = controller();
    const selectCamera = vi.fn();
    const { container } = render(<CameraPreview cameras={cameras}
      selectedCameraId="cam-a" onSelectCamera={selectCamera} snapshot={detections} />);

    expect(screen.getByText('Connecting preview...')).toBeVisible();
    expect(screen.getByRole('status')).toHaveTextContent('Connecting preview...');
    expect(container.querySelector('.camera-stage')).toBeInTheDocument();
    expect(screen.getByRole('img', { name: /cam-a camera preview/i }))
      .toHaveClass('camera-preview-image');
    await user.selectOptions(screen.getByRole('combobox', { name: /camera/i }), 'cam-b');
    expect(selectCamera).toHaveBeenCalledWith('cam-b');
    await user.click(screen.getByRole('button', { name: 'Reconnect preview' }));
    expect(previewController.reconnect).toHaveBeenCalledOnce();
  });

  it('starts MJPEG preview when snapshot compatibility is unavailable', () => {
    previewController = controller({
      streamUrl: '/api/v1/cameras/cam-b/preview.mjpeg?generation=1',
    });
    render(<CameraPreview cameras={cameras}
      selectedCameraId="cam-b" onSelectCamera={() => undefined} snapshot={detections} />);

    expect(previewCameraId).toBe('cam-b');
    expect(screen.getByRole('img', { name: /cam-b camera preview/i })).toHaveAttribute(
      'src', '/api/v1/cameras/cam-b/preview.mjpeg?generation=1',
    );
    expect(screen.getByRole('button', { name: 'Reconnect preview' })).toBeEnabled();
  });

  it('keeps the image hidden until load and updates overlay dimensions per generation', () => {
    previewController = controller();
    const view = render(<CameraPreview cameras={cameras}
      selectedCameraId="cam-a" onSelectCamera={() => undefined} snapshot={detections} />);
    const preview = within(view.container);
    const firstImage = preview.getByRole('img', { name: /camera preview/i });
    expect(firstImage).not.toHaveClass('is-loaded');
    Object.defineProperties(firstImage, {
      naturalWidth: { configurable: true, value: 800 },
      naturalHeight: { configurable: true, value: 800 },
    });
    fireEvent.load(firstImage);
    expect(firstImage).toHaveClass('is-loaded');
    expect(preview.getByTestId('detection-overlay')).toHaveAttribute('data-image-width', '800');
    expect(preview.getByTestId('detection-overlay')).toHaveAttribute('data-image-height', '800');

    previewController = controller({
      state: 'reconnecting',
      streamUrl: '/api/v1/cameras/cam-a/preview.mjpeg?generation=2',
    });
    view.rerender(<CameraPreview cameras={cameras}
      selectedCameraId="cam-a" onSelectCamera={() => undefined} snapshot={detections} />);
    expect(preview.queryByTestId('detection-overlay')).not.toBeInTheDocument();
    const secondImage = preview.getByRole('img', { name: /camera preview/i });
    expect(secondImage).not.toHaveClass('is-loaded');
  });

  it('ignores stale events from a detached image before changing current display state', () => {
    const staleLoad = vi.fn(() => false);
    const staleError = vi.fn(() => false);
    previewController = controller({ onLoad: staleLoad, onError: staleError });
    const view = render(<CameraPreview cameras={cameras}
      selectedCameraId="cam-a" onSelectCamera={() => undefined} snapshot={detections} />);
    const oldImage = screen.getByRole('img', {
      name: /camera preview/i,
    }) as HTMLImageElement;
    Object.defineProperties(oldImage, {
      naturalWidth: { configurable: true, value: 800 },
      naturalHeight: { configurable: true, value: 800 },
    });
    const propsKey = Object.keys(oldImage).find((key) => key.startsWith('__reactProps$'));
    expect(propsKey).toBeDefined();
    const staleHandlers = (oldImage as unknown as Record<string, {
      onLoad(event: { currentTarget: HTMLImageElement }): void;
      onError(): void;
    }>)[propsKey!];

    previewController = controller({
      state: 'reconnecting',
      streamUrl: '/api/v1/cameras/cam-a/preview.mjpeg?generation=2',
      onLoad: vi.fn(() => true),
      onError: vi.fn(() => true),
    });
    view.rerender(<CameraPreview cameras={cameras}
      selectedCameraId="cam-a" onSelectCamera={() => undefined} snapshot={detections} />);
    const currentImage = screen.getByRole('img', {
      name: /camera preview/i,
    }) as HTMLImageElement;
    Object.defineProperties(currentImage, {
      naturalWidth: { configurable: true, value: 1600 },
      naturalHeight: { configurable: true, value: 900 },
    });
    fireEvent.load(currentImage);

    act(() => {
      staleHandlers.onLoad({ currentTarget: oldImage });
      staleHandlers.onError();
    });

    expect(staleLoad).toHaveBeenCalledOnce();
    expect(staleError).toHaveBeenCalledOnce();
    expect(currentImage).toHaveClass('is-loaded');
    expect(screen.getByTestId('detection-overlay')).toHaveAttribute('data-image-width', '1600');
    expect(screen.getByTestId('detection-overlay')).toHaveAttribute('data-image-height', '900');
  });

  it('removes the image while reconnecting and reports only the concise state', () => {
    previewController = controller({ state: 'reconnecting', streamUrl: '' });
    const { container } = render(<CameraPreview cameras={cameras}
      selectedCameraId="cam-a" onSelectCamera={() => undefined} snapshot={detections} />);

    expect(within(container).queryByRole('img', { name: /camera preview/i })).not.toBeInTheDocument();
    expect(screen.getByText('Preview reconnecting...')).toBeVisible();
    expect(screen.queryByText(/snapshot unavailable/i)).not.toBeInTheDocument();
  });

  it('announces a concise no-camera state without a blank stage', () => {
    previewController = controller({ state: 'unavailable', streamUrl: '' });
    render(<CameraPreview cameras={[]}
      selectedCameraId="" onSelectCamera={() => undefined} snapshot={detections} />);

    expect(screen.getByRole('status')).toHaveTextContent('No camera selected.');
    expect(screen.getByRole('button', { name: 'Reconnect preview' })).toBeDisabled();
  });
});
