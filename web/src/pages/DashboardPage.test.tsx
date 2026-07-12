import { act, cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { CameraApiClient } from '../api/types';
import type { OperationalController } from '../hooks/useOperationalData';
import { DashboardPage } from './DashboardPage';

let client: CameraApiClient;

class FakeEventSource {
  static instances: FakeEventSource[] = [];
  readonly listeners = new Map<string, EventListener>();
  readonly close = vi.fn();
  onopen: ((event: Event) => void) | null = null;
  onerror: ((event: Event) => void) | null = null;
  constructor(readonly url: string) { FakeEventSource.instances.push(this); }
  addEventListener(type: string, listener: EventListener): void {
    this.listeners.set(type, listener);
  }
  emit(type: string, data: string): void {
    this.listeners.get(type)?.(new MessageEvent(type, { data }));
  }
}

const makeClient = (): CameraApiClient => ({
  getJson: vi.fn(),
  postJson: vi.fn(),
  getBlob: vi.fn((): Promise<Blob> => new Promise<Blob>(() => {})),
  setUnauthorizedHandler: vi.fn(),
});

const controller: OperationalController = {
  state: 'ready',
  selectedCameraId: 'cam-a',
  selectCamera: vi.fn(),
  refresh: vi.fn(async () => undefined),
  replaceDetections: vi.fn(),
  replaceAiStatus: vi.fn(),
  data: {
    health: { status: 'ok' },
    cameras: [{ id: 'cam-a', state: 'streaming', snapshot_available: true }],
    ai: { enabled: false, backend: 'disabled', state: 'disabled',
      model_count: 0, runner_count: 0, reason: 'disabled by config',
      models: [], runners: [] },
    stream: { url: 'rtsp://camera.local:8555/imx708/main', control_tls: false,
      media_srtp: false, secure_media: { control_scheme: 'rtsp',
        media_profile: 'RTP/AVP', keying: 'none',
        requires_tls_control_channel: false } },
    detections: { events: [] },
  },
};

beforeEach(() => {
  client = makeClient();
  FakeEventSource.instances = [];
  vi.stubGlobal('EventSource', FakeEventSource);
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('DashboardPage', () => {
  it.each([
    ['cameras', 'Cameras', ['Camera preview', 'System and cameras'],
      ['Stream connection', 'Hailo AI runtime']],
    ['ai', 'AI inference', ['Camera preview', 'Hailo AI runtime'],
      ['System and cameras', 'Stream connection']],
    ['system', 'System', ['System and cameras', 'Stream connection'],
      ['Camera preview', 'Hailo AI runtime']],
  ] as const)(
    'renders the distinct %s management surface',
    (view, title, visibleSections, hiddenSections) => {
      render(<DashboardPage client={client} controller={controller} view={view} />);

      expect(screen.getByRole('heading', { name: title })).toBeVisible();
      for (const section of visibleSections) {
        expect(screen.getByRole('heading', { name: section })).toBeVisible();
      }
      for (const section of hiddenSections) {
        expect(screen.queryByRole('heading', { name: section })).not.toBeInTheDocument();
      }
    },
  );

  it('composes the authenticated camera preview with operational data', async () => {
    const user = userEvent.setup();
    const refresh = vi.fn(async () => undefined);
    render(<DashboardPage client={client} controller={{ ...controller, refresh }} />);

    expect(screen.getByRole('heading', { name: 'Operational dashboard' })).toBeVisible();
    expect(screen.getByText('Loading snapshot...')).toBeVisible();
    expect(screen.getByRole('combobox', { name: /camera/i })).toHaveValue('cam-a');
    expect(client.getBlob).toHaveBeenCalledWith(
      '/api/v1/cameras/cam-a/snapshot.jpg',
      expect.any(AbortSignal),
    );
    expect(screen.queryByRole('img')).not.toBeInTheDocument();
    expect(screen.queryByRole('video')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: /refresh operational data/i }));
    expect(refresh).toHaveBeenCalledOnce();
  });

  it('renders loading and unavailable states', () => {
    const { rerender } = render(<DashboardPage client={client} controller={{
      ...controller, state: 'loading', data: null,
    }} />);
    expect(screen.getByText('Loading operational data...')).toBeVisible();

    rerender(<DashboardPage client={client} controller={{
      ...controller, state: 'error', data: null,
    }} />);
    expect(screen.getByRole('alert')).toHaveTextContent('Operational data is unavailable.');
  });

  it('feeds named live detections to the list, canvas source, and controller', async () => {
    const { container } = render(
      <DashboardPage client={client} controller={controller} />,
    );
    const live = { events: [{
      camera_id: 'cam-a', model_id: 'pose', model_kind: 'pose',
      result_state: 'decoded', frame_sequence: 20, frame_timestamp_ns: 200,
      detections: [{ label: 'person', confidence: 0.92,
        box: { x: 0.1, y: 0.1, width: 0.3, height: 0.6 },
        keypoints: [{ name: 'nose', x: 0.2, y: 0.2, confidence: 0.9 }] }],
    }] };

    act(() => FakeEventSource.instances[0].emit('detections', JSON.stringify(live)));

    expect(await screen.findByText('Detections 1')).toBeVisible();
    expect(container.querySelector('.detection-row')?.textContent)
      .toBe('poseperson92%');
    expect(controller.replaceDetections).toHaveBeenLastCalledWith(live);
  });

  it('posts an empty restart command and replaces returned AI status', async () => {
    const user = userEvent.setup();
    const restarted = { ...controller.data!.ai, enabled: true, backend: 'hailo',
      state: 'ready', reason: 'AI runtime ready' };
    vi.mocked(client.postJson).mockImplementation(async (_path, _body, parser) =>
      parser({ status: 'restarted', ai: restarted }));
    render(<DashboardPage client={client} controller={controller} />);

    await user.click(screen.getByRole('button', { name: 'Restart AI runtime' }));

    expect(client.postJson).toHaveBeenCalledWith(
      '/api/v1/ai/restart', {}, expect.any(Function),
    );
    expect(controller.replaceAiStatus).toHaveBeenCalledWith(restarted);
    expect(controller.refresh).not.toHaveBeenCalled();
  });

  it('awaits operational refresh when restart omits AI status', async () => {
    const user = userEvent.setup();
    let finishRefresh!: () => void;
    vi.mocked(client.postJson).mockImplementation(async (_path, _body, parser) =>
      parser({ status: 'restarted' }));
    const refresh = vi.fn(() => new Promise<void>((resolve) => {
      finishRefresh = resolve;
    }));
    render(<DashboardPage client={client} controller={{ ...controller, refresh }} />);

    await user.click(screen.getByRole('button', { name: 'Restart AI runtime' }));
    expect(refresh).toHaveBeenCalledOnce();
    expect(screen.getByRole('button', { name: 'Restart AI runtime' })).toBeDisabled();

    act(() => finishRefresh());
    await waitFor(() => expect(
      screen.getByRole('button', { name: 'Restart AI runtime' }),
    ).toBeEnabled());
  });
});
