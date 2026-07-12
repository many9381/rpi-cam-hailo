import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { CameraApiClient, DetectionSnapshot } from '../api/types';
import type { SnapshotController } from '../hooks/useSnapshot';
import { CameraPreview } from './CameraPreview';

let snapshotController: SnapshotController;

vi.mock('../hooks/useSnapshot', () => ({
  useSnapshot: () => snapshotController,
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

const client: CameraApiClient = {
  getJson: vi.fn(), postJson: vi.fn(), getBlob: vi.fn(),
  setUnauthorizedHandler: vi.fn(),
};
const detections: DetectionSnapshot = { events: [] };
const cameras = [
  { id: 'cam-a', state: 'streaming', snapshot_available: true },
  { id: 'cam-b', state: 'starting', snapshot_available: false },
];

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('CameraPreview', () => {
  it('renders a stable loading stage, camera selector, and manual refresh', async () => {
    const user = userEvent.setup();
    const refresh = vi.fn(async () => undefined);
    snapshotController = { state: 'loading', objectUrl: null, refresh };
    const selectCamera = vi.fn();

    const { container } = render(<CameraPreview client={client} cameras={cameras}
      selectedCameraId="cam-a" onSelectCamera={selectCamera} snapshot={detections} />);

    expect(screen.getByText('Loading snapshot...')).toBeVisible();
    expect(container.querySelector('.camera-stage')).toBeInTheDocument();
    await user.selectOptions(screen.getByRole('combobox', { name: /camera/i }), 'cam-b');
    expect(selectCamera).toHaveBeenCalledWith('cam-b');
    await user.click(screen.getByRole('button', { name: /refresh snapshot/i }));
    expect(refresh).toHaveBeenCalledOnce();
  });

  it('aligns the overlay to the contained image rectangle for a square JPEG', () => {
    snapshotController = { state: 'ready', objectUrl: 'blob:square', refresh: vi.fn() };
    render(<CameraPreview client={client} cameras={cameras}
      selectedCameraId="cam-a" onSelectCamera={() => undefined} snapshot={detections} />);
    const image = screen.getByRole('img', { name: /cam-a snapshot/i });
    Object.defineProperties(image, {
      naturalWidth: { configurable: true, value: 800 },
      naturalHeight: { configurable: true, value: 800 },
    });

    fireEvent.load(image);

    expect(screen.getByTestId('detection-overlay')).toHaveAttribute('data-image-width', '800');
    expect(screen.getByTestId('detection-overlay')).toHaveAttribute('data-image-height', '800');
    expect(screen.getByTestId('detection-overlay')).not.toHaveAttribute('style');
  });

  it('keys intrinsic dimensions to each replacement object URL', () => {
    snapshotController = { state: 'ready', objectUrl: 'blob:square', refresh: vi.fn() };
    const view = render(<CameraPreview client={client} cameras={cameras}
      selectedCameraId="cam-a" onSelectCamera={() => undefined} snapshot={detections} />);
    const preview = within(view.container);
    const square = preview.getByRole('img', { name: /cam-a snapshot/i });
    Object.defineProperties(square, {
      naturalWidth: { configurable: true, value: 800 },
      naturalHeight: { configurable: true, value: 800 },
    });
    fireEvent.load(square);
    expect(preview.getByTestId('detection-overlay')).toHaveAttribute('data-image-width', '800');
    expect(preview.getByTestId('detection-overlay')).toHaveAttribute('data-image-height', '800');

    snapshotController = { state: 'ready', objectUrl: 'blob:wide', refresh: vi.fn() };
    view.rerender(<CameraPreview client={client} cameras={cameras}
      selectedCameraId="cam-a" onSelectCamera={() => undefined} snapshot={detections} />);
    expect(preview.queryByTestId('detection-overlay')).not.toBeInTheDocument();

    const wide = preview.getByRole('img', { name: /cam-a snapshot/i });
    expect(wide).not.toBe(square);
    Object.defineProperties(wide, {
      naturalWidth: { configurable: true, value: 1600 },
      naturalHeight: { configurable: true, value: 900 },
    });
    fireEvent.load(wide);
    expect(preview.getByTestId('detection-overlay')).toHaveAttribute('data-image-width', '1600');
    expect(preview.getByTestId('detection-overlay')).toHaveAttribute('data-image-height', '900');
  });

  it('hides a JPEG that fails to decode and keeps manual refresh available', async () => {
    const user = userEvent.setup();
    const refresh = vi.fn(async () => undefined);
    snapshotController = { state: 'ready', objectUrl: 'blob:invalid-jpeg', refresh };
    const view = render(<CameraPreview client={client} cameras={cameras}
      selectedCameraId="cam-a" onSelectCamera={() => undefined} snapshot={detections} />);
    const preview = within(view.container);

    fireEvent.error(preview.getByRole('img', { name: /cam-a snapshot/i }));

    expect(preview.queryByRole('img', { name: /cam-a snapshot/i })).not.toBeInTheDocument();
    expect(preview.queryByTestId('detection-overlay')).not.toBeInTheDocument();
    expect(preview.getByText('Snapshot unavailable')).toBeVisible();
    await user.click(preview.getByRole('button', { name: /refresh snapshot/i }));
    expect(refresh).toHaveBeenCalledOnce();
  });

  it('shows explicit unavailable surfaces for failed and unavailable cameras', () => {
    snapshotController = { state: 'unavailable', objectUrl: null, refresh: vi.fn() };
    const view = render(<CameraPreview client={client} cameras={cameras}
      selectedCameraId="cam-a" onSelectCamera={() => undefined} snapshot={detections} />);
    expect(screen.getByText('Snapshot unavailable')).toBeVisible();

    view.rerender(<CameraPreview client={client} cameras={cameras}
      selectedCameraId="cam-b" onSelectCamera={() => undefined} snapshot={detections} />);
    expect(screen.getByText('Snapshot unavailable for this camera')).toBeVisible();
  });
});
