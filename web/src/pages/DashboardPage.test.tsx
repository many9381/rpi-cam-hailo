import { act, cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { CameraApiClient } from '../api/types';
import type { AuditStatusController } from '../features/audit/useAuditStatus';
import type { ProtectionSnapshot } from '../features/protection/contracts';
import type { SystemProtectionController } from '../features/protection/useSystemProtection';
import type { OperationalController } from '../hooks/useOperationalData';
import {
  makeSettings,
  makeSettingsController,
  makeSettingsSnapshot,
} from '../features/settings/testSupport';
import { LanguageProvider } from '../i18n';
import { DashboardPage } from './DashboardPage';

vi.mock('../features/audit/AuditRecordsPanel', () => ({
  AuditRecordsPanel: ({ auditStatus }: { auditStatus?: AuditStatusController }) => (
    <section data-testid="audit-records-panel"
      data-has-status={auditStatus === undefined ? 'false' : 'true'}>
      <h2>Audit records</h2>
    </section>
  ),
}));

vi.mock('../features/protection/SystemProtectionPanel', () => ({
  SystemProtectionPanel: ({ controller: protection }: {
    controller: SystemProtectionController;
  }) => (
    <section data-testid="system-protection-panel"
      data-protection-state={protection.snapshot?.state ?? 'unavailable'}>
      <h2>System protection</h2>
    </section>
  ),
}));

let client: CameraApiClient;

vi.mock('../hooks/useLivePreview', () => ({
  useLivePreview: () => ({
    state: 'connecting',
    generation: 1,
    videoRef: { current: null },
    reconnect: vi.fn(),
  }),
}));

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
  deleteJson: vi.fn(),
  putJson: vi.fn(),
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

const auditStatus: AuditStatusController = {
  state: 'ready',
  data: {
    current_events: 1,
    max_events: 100,
    usage_percent: 1,
    warning: false,
    rotated_event_count: 0,
    last_rotation_at_seconds: null,
    last_rotated_sequence: null,
  },
  refresh: vi.fn(async () => undefined),
};

const protectionSnapshot: ProtectionSnapshot = {
  state: 'operational',
  check_running: false,
  next_periodic_at_seconds: 1_784_586_400,
  self_test: null,
  integrity: null,
};

const protection: SystemProtectionController = {
  state: 'ready',
  snapshot: protectionSnapshot,
  publicMessage: null,
  activeCommand: null,
  refresh: vi.fn(async () => undefined),
  runSelfTest: vi.fn(async () => undefined),
  runIntegrityCheck: vi.fn(async () => undefined),
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
    ['system', 'System', ['System and cameras', 'Stream connection', 'Audit records'],
      ['Camera preview', 'Hailo AI runtime']],
  ] as const)(
    'renders the distinct %s management surface',
    (view, title, visibleSections, hiddenSections) => {
      render(<DashboardPage client={client} controller={controller} view={view} />,
        { wrapper: LanguageProvider });

      expect(screen.getByRole('heading', { name: title })).toBeVisible();
      for (const section of visibleSections) {
        expect(screen.getByRole('heading', { name: section })).toBeVisible();
      }
      for (const section of hiddenSections) {
        expect(screen.queryByRole('heading', { name: section })).not.toBeInTheDocument();
      }
    },
  );

  it.each([
    ['cameras', 'Camera settings'],
    ['cameras-substream', 'Sub-stream'],
    ['cameras-osd', 'OSD'],
  ] as const)(
    'renders the %s camera settings section',
    (view, sectionHeading) => {
      render(<DashboardPage client={client} controller={controller}
        runtimeSettings={makeSettingsController()} view={view} />,
      { wrapper: LanguageProvider });

      expect(screen.getByRole('heading', { name: sectionHeading, level: 2 }))
        .toBeInTheDocument();
    },
  );

  it('mounts the audit panel with status only for the System view', () => {
    const view = render(<DashboardPage client={client} controller={controller}
      auditStatus={auditStatus} view="dashboard" />, { wrapper: LanguageProvider });
    expect(screen.queryByTestId('audit-records-panel')).not.toBeInTheDocument();

    view.rerender(<DashboardPage client={client} controller={controller}
      auditStatus={auditStatus} view="cameras" />);
    expect(screen.queryByTestId('audit-records-panel')).not.toBeInTheDocument();

    view.rerender(<DashboardPage client={client} controller={controller}
      auditStatus={auditStatus} view="ai" />);
    expect(screen.queryByTestId('audit-records-panel')).not.toBeInTheDocument();

    view.rerender(<DashboardPage client={client} controller={controller}
      auditStatus={auditStatus} view="system" />);
    expect(screen.getByTestId('audit-records-panel')).toHaveAttribute(
      'data-has-status',
      'true',
    );
  });

  it('places system protection above audit records only on the System view', () => {
    const view = render(<DashboardPage client={client} controller={controller}
      protection={protection} auditStatus={auditStatus} view="dashboard" />,
      { wrapper: LanguageProvider });
    expect(screen.queryByTestId('system-protection-panel')).not.toBeInTheDocument();

    view.rerender(<DashboardPage client={client} controller={controller}
      protection={protection} auditStatus={auditStatus} view="system" />);

    const panel = screen.getByTestId('system-protection-panel');
    const audit = screen.getByTestId('audit-records-panel');
    expect(panel).toHaveAttribute('data-protection-state', 'operational');
    expect(panel.compareDocumentPosition(audit) & Node.DOCUMENT_POSITION_FOLLOWING)
      .toBeTruthy();
  });

  it.each([
    ['loading', 'Loading operational data...'],
    ['error', 'Operational data is unavailable.'],
  ] as const)(
    'keeps healthy System audit records available while operational data is %s',
    (state, operationalMessage) => {
      render(<DashboardPage client={client} controller={{
        ...controller,
        state,
        data: null,
      }} auditStatus={auditStatus} view="system" />, { wrapper: LanguageProvider });

      expect(screen.getByText(operationalMessage)).toBeVisible();
      expect(screen.getByTestId('audit-records-panel')).toHaveAttribute(
        'data-has-status',
        'true',
      );
      expect(screen.getByRole('heading', { name: 'Audit records' })).toBeVisible();
    },
  );

  it.each([
    ['cameras-osd', 'DRAFT OSD', 'ACTIVE OSD'],
    ['cameras', 'ACTIVE OSD', 'DRAFT OSD'],
    ['dashboard', 'ACTIVE OSD', 'DRAFT OSD'],
  ] as const)(
    'previews the %s view with the "%s" OSD text',
    (view, shownText, hiddenText) => {
      const active = makeSettings();
      active.osd = {
        enabled: true,
        items: [{ type: 'custom_text', text: 'ACTIVE OSD', position: 'top_left' }],
      };
      const draft = makeSettings();
      draft.osd = {
        enabled: true,
        items: [{ type: 'custom_text', text: 'DRAFT OSD', position: 'bottom_right' }],
      };
      const settingsController = makeSettingsController({
        snapshot: { ...makeSettingsSnapshot(), active },
        draft,
        dirty: true,
      });
      render(<DashboardPage client={client} controller={controller}
        runtimeSettings={settingsController} view={view} />, { wrapper: LanguageProvider });

      expect(screen.getByText(shownText)).toHaveClass('osd-item');
      expect(screen.queryByText(hiddenText)).not.toBeInTheDocument();
    },
  );

  it('composes the authenticated live preview with operational data', async () => {
    const user = userEvent.setup();
    const refresh = vi.fn(async () => undefined);
    render(<DashboardPage client={client} controller={{ ...controller, refresh }} />,
      { wrapper: LanguageProvider });

    expect(screen.getByRole('heading', { name: 'Dashboard' })).toBeVisible();
    expect(screen.getByText('Connecting preview...')).toBeVisible();
    expect(screen.getByRole('combobox', { name: /camera/i })).toHaveValue('cam-a');
    expect(screen.getByLabelText('cam-a camera preview'))
      .toBeInstanceOf(HTMLVideoElement);
    expect(screen.queryByRole('img', { name: /cam-a camera preview/i }))
      .not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: /refresh operational data/i }));
    expect(refresh).toHaveBeenCalledOnce();
  });

  it('refreshes the supplied audit status from the page refresh action', async () => {
    const user = userEvent.setup();
    const refreshAuditStatus = vi.fn(async () => undefined);
    render(<DashboardPage client={client} controller={{
      ...controller,
      refresh: vi.fn(async () => undefined),
    }}
      auditStatus={{ ...auditStatus, refresh: refreshAuditStatus }} />,
      { wrapper: LanguageProvider });

    await user.click(screen.getByRole('button', { name: /refresh operational data/i }));

    expect(refreshAuditStatus).toHaveBeenCalledOnce();
  });

  it('renders loading and unavailable states', () => {
    const { rerender } = render(<DashboardPage client={client} controller={{
      ...controller, state: 'loading', data: null,
    }} />, { wrapper: LanguageProvider });
    expect(screen.getByText('Loading operational data...')).toBeVisible();

    rerender(<DashboardPage client={client} controller={{
      ...controller, state: 'error', data: null,
    }} />);
    expect(screen.getByRole('alert')).toHaveTextContent('Operational data is unavailable.');
  });

  it('feeds named live detections to the list, canvas source, and controller', async () => {
    const { container } = render(
      <DashboardPage client={client} controller={controller} />,
      { wrapper: LanguageProvider },
    );
    const live = { events: [{
      camera_id: 'cam-a', model_id: 'pose', model_kind: 'pose',
      result_state: 'decoded', frame_sequence: 20, frame_timestamp_ns: 200,
      detections: [{ class_id: 0, label: 'person', confidence: 0.92,
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
    render(<DashboardPage client={client} controller={controller} />,
      { wrapper: LanguageProvider });

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
    render(<DashboardPage client={client} controller={{ ...controller, refresh }} />,
      { wrapper: LanguageProvider });

    await user.click(screen.getByRole('button', { name: 'Restart AI runtime' }));
    expect(refresh).toHaveBeenCalledOnce();
    expect(screen.getByRole('button', { name: 'Restart AI runtime' })).toBeDisabled();

    act(() => finishRefresh());
    await waitFor(() => expect(
      screen.getByRole('button', { name: 'Restart AI runtime' }),
    ).toBeEnabled());
  });

  it('restarts a failed camera runtime and refreshes operational data', async () => {
    const user = userEvent.setup();
    vi.mocked(client.postJson).mockImplementation(async (_path, _body, parser) =>
      parser({ runtime: 'running' }));
    const refresh = vi.fn(async () => undefined);
    const failedController: OperationalController = {
      ...controller,
      refresh,
      data: {
        ...controller.data!,
        cameras: [{ id: 'cam-a', state: 'error', snapshot_available: false }],
      },
    };
    render(<DashboardPage client={client} controller={failedController} />,
      { wrapper: LanguageProvider });

    await user.click(screen.getByRole('button', { name: 'Restart camera runtime' }));

    expect(client.postJson).toHaveBeenCalledWith(
      '/api/v1/runtime/restart', {}, expect.any(Function),
    );
    expect(refresh).toHaveBeenCalledOnce();
  });

  it('places camera and AI settings only in their operational views', () => {
    const settingsController = makeSettingsController();
    const { rerender } = render(<DashboardPage client={client}
      controller={controller} runtimeSettings={settingsController} view="cameras" />,
      { wrapper: LanguageProvider });
    expect(screen.getByRole('heading', { name: 'Camera settings' })).toBeVisible();
    expect(screen.queryByRole('heading', { name: 'Model settings' }))
      .not.toBeInTheDocument();
    expect(screen.getByLabelText('Runtime settings actions')).toBeVisible();

    rerender(<DashboardPage client={client} controller={controller}
      runtimeSettings={settingsController} view="ai" />);
    expect(screen.getByRole('heading', { name: 'Model settings' })).toBeVisible();
    expect(screen.queryByRole('heading', { name: 'Camera settings' }))
      .not.toBeInTheDocument();
    expect(screen.getByLabelText('Runtime settings actions')).toBeVisible();
  });

  it('refreshes operational status after an apply command settles', async () => {
    const user = userEvent.setup();
    const refresh = vi.fn(async () => undefined);
    const pending = makeSettingsSnapshot().active;
    pending.camera = { ...pending.camera, profile_id: 'imx708-720p50' };
    const settingsController = makeSettingsController({
      snapshot: makeSettingsSnapshot({ pending }),
      draft: pending,
    });
    render(<DashboardPage client={client} controller={{ ...controller, refresh }}
      runtimeSettings={settingsController} view="cameras" />, { wrapper: LanguageProvider });

    await user.click(screen.getByRole('button', { name: 'Apply pending' }));
    await user.click(screen.getByRole('button', { name: 'Apply now' }));

    await waitFor(() => expect(refresh).toHaveBeenCalledOnce());
  });
});
