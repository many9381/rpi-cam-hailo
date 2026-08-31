import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { createRef } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { DetectionSnapshot } from '../api/types';
import type { LivePreviewController } from '../hooks/useLivePreview';
import { LanguageProvider } from '../i18n';
import { CameraPreview } from './CameraPreview';

let previewController: LivePreviewController;
let previewCameraId = '';

vi.mock('../hooks/useLivePreview', () => ({
  useLivePreview: (cameraId: string) => {
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

const controller = (overrides: Partial<LivePreviewController> = {}): LivePreviewController => ({
  state: 'connecting',
  generation: 1,
  videoRef: createRef<HTMLVideoElement>(),
  reconnect: vi.fn(),
  ...overrides,
});

afterEach(() => cleanup());

describe('CameraPreview', () => {
  it('renders the stable video stage, selector, and reconnect control', async () => {
    const user = userEvent.setup();
    previewController = controller();
    const selectCamera = vi.fn();
    render(<LanguageProvider><CameraPreview cameras={cameras} selectedCameraId="cam-a"
      onSelectCamera={selectCamera} snapshot={detections} /></LanguageProvider>);

    expect(screen.getByRole('status')).toHaveTextContent('Connecting preview...');
    expect(screen.getByLabelText('cam-a camera preview')).toBeInstanceOf(HTMLVideoElement);
    await user.selectOptions(screen.getByRole('combobox', { name: /camera/i }), 'cam-b');
    expect(selectCamera).toHaveBeenCalledWith('cam-b');
    await user.click(screen.getByRole('button', { name: 'Reconnect preview' }));
    expect(previewController.reconnect).toHaveBeenCalledOnce();
  });

  it('starts live preview even when snapshot compatibility is unavailable', () => {
    previewController = controller();
    render(<LanguageProvider><CameraPreview cameras={cameras} selectedCameraId="cam-b"
      onSelectCamera={() => undefined} snapshot={detections} /></LanguageProvider>);

    expect(previewCameraId).toBe('cam-b');
    const video = screen.getByLabelText('cam-b camera preview');
    expect(video).toHaveAttribute('autoplay');
    expect(video).toHaveAttribute('playsinline');
    expect(video).toHaveProperty('muted', true);
  });

  it('shows live video and sizes the detection overlay from video metadata', () => {
    previewController = controller({ state: 'live' });
    render(<LanguageProvider><CameraPreview cameras={cameras} selectedCameraId="cam-a"
      onSelectCamera={() => undefined} snapshot={detections} /></LanguageProvider>);
    const video = screen.getByLabelText('cam-a camera preview');
    Object.defineProperties(video, {
      videoWidth: { configurable: true, value: 1920 },
      videoHeight: { configurable: true, value: 1080 },
    });

    fireEvent.loadedMetadata(video);

    expect(video).toHaveClass('is-live');
    expect(screen.getByTestId('detection-overlay'))
      .toHaveAttribute('data-image-width', '1920');
    expect(screen.getByTestId('detection-overlay'))
      .toHaveAttribute('data-image-height', '1080');
    expect(screen.getByRole('status')).toBeEmptyDOMElement();
  });

  it('clears stale overlay dimensions when a new stream generation starts', () => {
    previewController = controller({ state: 'live', generation: 1 });
    const view = render(<LanguageProvider><CameraPreview cameras={cameras} selectedCameraId="cam-a"
      onSelectCamera={() => undefined} snapshot={detections} /></LanguageProvider>);
    const video = screen.getByLabelText('cam-a camera preview');
    Object.defineProperties(video, {
      videoWidth: { configurable: true, value: 1920 },
      videoHeight: { configurable: true, value: 1080 },
    });
    fireEvent.loadedMetadata(video);
    expect(screen.getByTestId('detection-overlay')).toBeInTheDocument();

    previewController = controller({ state: 'reconnecting', generation: 2 });
    view.rerender(<LanguageProvider><CameraPreview cameras={cameras} selectedCameraId="cam-a"
      onSelectCamera={() => undefined} snapshot={detections} /></LanguageProvider>);

    expect(screen.queryByTestId('detection-overlay')).not.toBeInTheDocument();
    expect(screen.getByRole('status')).toHaveTextContent('Preview reconnecting...');
  });

  it('announces a concise no-camera state', () => {
    previewController = controller({ state: 'unavailable', generation: 0 });
    render(<LanguageProvider><CameraPreview cameras={[]} selectedCameraId=""
      onSelectCamera={() => undefined} snapshot={detections} /></LanguageProvider>);

    expect(screen.getByRole('status')).toHaveTextContent('No camera selected.');
    expect(screen.getByRole('button', { name: 'Reconnect preview' })).toBeDisabled();
  });
});
