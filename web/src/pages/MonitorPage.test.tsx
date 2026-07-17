import { cleanup, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { CameraApiClient, DetectionSnapshot } from '../api/types';
import type { MonitoringController } from '../hooks/useMonitoringData';
import { MonitorPage } from './MonitorPage';

const useMonitoringData = vi.fn();
const useDetectionStream = vi.fn();
const useSnapshot = vi.fn();
const cameraPreview = vi.fn();

vi.mock('../hooks/useMonitoringData', () => ({
  useMonitoringData: (...args: unknown[]) => useMonitoringData(...args),
}));
vi.mock('../hooks/useDetectionStream', () => ({
  useDetectionStream: (...args: unknown[]) => useDetectionStream(...args),
}));
vi.mock('../hooks/useSnapshot', () => ({
  useSnapshot: (...args: unknown[]) => useSnapshot(...args),
}));
vi.mock('../hooks/useOperationalData', () => {
  throw new Error('MonitorPage must not import useOperationalData');
});
vi.mock('../features/settings/useRuntimeSettings', () => {
  throw new Error('MonitorPage must not import useRuntimeSettings');
});
vi.mock('../components/CameraPreview', () => ({
  CameraPreview: (props: unknown) => {
    cameraPreview(props);
    const value = props as { selectedCameraId: string; onSelectCamera(id: string): void };
    return (
      <button type="button" onClick={() => value.onSelectCamera('cam-b')}>
        Preview {value.selectedCameraId}
      </button>
    );
  },
}));

const snapshot: DetectionSnapshot = { events: [{
  camera_id: 'cam-a', model_id: 'objects', model_kind: 'object_detection',
  result_state: 'decoded', frame_sequence: 1, frame_timestamp_ns: 1,
  detections: [],
}, {
  camera_id: 'cam-b', model_id: 'objects', model_kind: 'object_detection',
  result_state: 'decoded', frame_sequence: 2, frame_timestamp_ns: 2,
  detections: [],
}] };

const controller = (overrides: Partial<MonitoringController> = {}): MonitoringController => ({
  state: 'ready',
  cameras: [
    { id: 'cam-a', state: 'streaming', width: 1920, height: 1080,
      snapshot_available: true },
    { id: 'cam-b', state: 'streaming', width: 1920, height: 1080,
      snapshot_available: true },
  ],
  selectedCameraId: 'cam-a',
  selectCamera: vi.fn(),
  refresh: vi.fn(async () => undefined),
  ...overrides,
});

const makeClient = (): CameraApiClient => ({
  getJson: vi.fn(),
  deleteJson: vi.fn(),
  putJson: vi.fn(),
  postJson: vi.fn(),
  getBlob: vi.fn(),
  setUnauthorizedHandler: vi.fn(),
});

beforeEach(() => {
  useDetectionStream.mockReturnValue({ status: 'live', snapshot });
  useSnapshot.mockReturnValue({
    state: 'ready', objectUrl: 'blob:cam-a', refresh: vi.fn(async () => undefined),
  });
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe('MonitorPage', () => {
  it('binds one selected camera to preview, detection filtering, and snapshot', async () => {
    const user = userEvent.setup();
    const first = controller();
    useMonitoringData.mockReturnValue(first);
    const page = render(<MonitorPage client={makeClient()} />);

    expect(screen.getByRole('button', { name: 'Preview cam-a' })).toBeVisible();
    expect(useDetectionStream).toHaveBeenCalledWith({ events: [] }, true);
    expect(useSnapshot).toHaveBeenLastCalledWith(expect.anything(), 'cam-a');
    expect(cameraPreview).toHaveBeenLastCalledWith(expect.objectContaining({
      selectedCameraId: 'cam-a', snapshot,
    }));

    await user.click(screen.getByRole('button', { name: 'Preview cam-a' }));
    expect(first.selectCamera).toHaveBeenCalledWith('cam-b');

    useMonitoringData.mockReturnValue(controller({ selectedCameraId: 'cam-b' }));
    page.rerender(<MonitorPage client={makeClient()} />);
    expect(useSnapshot).toHaveBeenLastCalledWith(expect.anything(), 'cam-b');
    expect(cameraPreview).toHaveBeenLastCalledWith(expect.objectContaining({
      selectedCameraId: 'cam-b', snapshot,
    }));
  });

  it('renders the preview, snapshot and refresh actions', async () => {
    const user = userEvent.setup();
    const monitoring = controller();
    const refreshSnapshot = vi.fn(async () => undefined);
    useMonitoringData.mockReturnValue(monitoring);
    useSnapshot.mockReturnValue({
      state: 'ready', objectUrl: 'blob:cam-a', refresh: refreshSnapshot,
    });
    render(<MonitorPage client={makeClient()} />);

    expect(screen.getByRole('heading', { name: 'Live monitoring' })).toBeVisible();
    expect(screen.getByRole('img', { name: 'cam-a camera snapshot' }))
      .toHaveAttribute('src', 'blob:cam-a');
    expect(screen.getByRole('button', { name: 'Refresh snapshot for cam-a' }))
      .toBeVisible();

    await user.click(screen.getByRole('button', { name: 'Refresh monitoring and snapshot' }));
    expect(monitoring.refresh).toHaveBeenCalledOnce();
    expect(refreshSnapshot).toHaveBeenCalledOnce();
  });

  it('bounds loading, stale, error, and unavailable snapshot states', async () => {
    const monitoring = controller({ state: 'loading', cameras: [], selectedCameraId: '' });
    useMonitoringData.mockReturnValue(monitoring);
    const { rerender } = render(<MonitorPage client={makeClient()} />);
    expect(screen.getByText('Loading camera monitoring...')).toBeVisible();

    useMonitoringData.mockReturnValue(controller({ state: 'error', cameras: [], selectedCameraId: '' }));
    rerender(<MonitorPage client={makeClient()} />);
    expect(screen.getByRole('alert')).toHaveTextContent('Camera monitoring is unavailable.');

    const retrySnapshot = vi.fn(async () => undefined);
    useMonitoringData.mockReturnValue(controller({ state: 'stale' }));
    useSnapshot.mockReturnValue({ state: 'unavailable', objectUrl: null, refresh: retrySnapshot });
    rerender(<MonitorPage client={makeClient()} />);
    expect(screen.getByText('Showing last available cameras.')).toBeVisible();
    await userEvent.setup().click(screen.getByRole('button', { name: 'Refresh snapshot for cam-a' }));
    expect(retrySnapshot).toHaveBeenCalledOnce();
  });

  it('does not render administrator surfaces or call administrator endpoints', () => {
    const client = makeClient();
    useMonitoringData.mockReturnValue(controller());
    render(<MonitorPage client={client} />);

    expect(screen.queryByText(/health|stream connection|AI runtime|settings|restart|users|IP/i))
      .not.toBeInTheDocument();
    expect(client.getJson).not.toHaveBeenCalled();
    expect(client.postJson).not.toHaveBeenCalled();
  });
});
