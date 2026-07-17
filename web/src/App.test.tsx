import '@testing-library/jest-dom/vitest';

import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { UnauthorizedError } from './api/client';
import type { CameraApiClient, SetupStatus } from './api/types';
import { App } from './App';

const administratorHooks = vi.hoisted(() => ({
  throwOnConstruction: false,
  operationalConstructed: 0,
  runtimeConstructed: 0,
}));

vi.mock('./hooks/useOperationalData', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./hooks/useOperationalData')>();
  return {
    ...actual,
    useOperationalData: (...args: Parameters<typeof actual.useOperationalData>) => {
      administratorHooks.operationalConstructed += 1;
      if (administratorHooks.throwOnConstruction) {
        throw new Error('Viewer session must not construct useOperationalData');
      }
      return actual.useOperationalData(...args);
    },
  };
});

vi.mock('./features/settings/useRuntimeSettings', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./features/settings/useRuntimeSettings')>();
  return {
    ...actual,
    useRuntimeSettings: (...args: Parameters<typeof actual.useRuntimeSettings>) => {
      administratorHooks.runtimeConstructed += 1;
      if (administratorHooks.throwOnConstruction) {
        throw new Error('Viewer session must not construct useRuntimeSettings');
      }
      return actual.useRuntimeSettings(...args);
    },
  };
});

class FakeEventSource {
  static instances: FakeEventSource[] = [];

  readonly close = vi.fn();
  onopen: ((event: Event) => void) | null = null;
  onerror: ((event: Event) => void) | null = null;

  constructor(readonly url: string) {
    FakeEventSource.instances.push(this);
  }

  addEventListener(): void {}
}

const deferred = <T,>() => {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
};

const makeClient = (): CameraApiClient => ({
  getJson: vi.fn(),
  deleteJson: vi.fn(),
  putJson: vi.fn(),
  postJson: vi.fn(),
  getBlob: vi.fn(),
  setUnauthorizedHandler: vi.fn(),
});

afterEach(() => {
  cleanup();
  window.location.hash = '';
  vi.useRealTimers();
  vi.unstubAllGlobals();
  administratorHooks.throwOnConstruction = false;
  administratorHooks.operationalConstructed = 0;
  administratorHooks.runtimeConstructed = 0;
});

describe('App bootstrap gate', () => {
  it('shows a checking state until setup status resolves', () => {
    const client = makeClient();
    vi.mocked(client.getJson).mockReturnValue(new Promise(() => {}));

    render(<App client={client} />);

    expect(screen.getByText('Checking camera setup...')).toBeVisible();
    expect(screen.queryByText('Checking session...')).not.toBeInTheDocument();
  });

  it('renders setup and synchronizes the setup hash only when the server requires it', async () => {
    const client = makeClient();
    vi.mocked(client.getJson).mockResolvedValue({
      required: true,
      phase: 'administrator',
      tls: 'ready',
      peer_ip: '192.0.2.10',
    });

    render(<App client={client} />);

    expect(await screen.findByRole('heading', { name: /create administrator/i })).toBeVisible();
    expect(window.location.hash).toBe('#/setup');
    expect(client.getJson).toHaveBeenCalledWith(
      '/api/v1/setup/status',
      expect.any(Function),
      expect.any(AbortSignal),
    );
  });

  it('recovers authentication only after the operational bootstrap gate', async () => {
    const client = makeClient();
    vi.mocked(client.getJson)
      .mockResolvedValueOnce({ required: false })
      .mockResolvedValueOnce({ username: 'operator.one', role: 'administrator' });

    render(<App client={client} />);

    expect(await screen.findByText('operator.one')).toBeVisible();
    const dashboard = await screen.findByRole('link', { name: 'Dashboard' });
    await waitFor(() => {
      expect(dashboard).toHaveAttribute('aria-current', 'page');
      expect(window.location.hash).toBe('#/dashboard');
    });
    expect(client.getJson).toHaveBeenNthCalledWith(
      2,
      '/api/v1/auth/me',
      expect.any(Function),
      expect.any(AbortSignal),
    );
  });

  it('mounts the operational dashboard for an authenticated session', async () => {
    const client = makeClient();
    vi.mocked(client.getJson).mockImplementation(async (path, parser) => {
      const payloads: Record<string, unknown> = {
        '/api/v1/setup/status': { required: false },
        '/api/v1/auth/me': { username: 'operator.one', role: 'administrator' },
        '/api/v1/health': { status: 'ok' },
        '/api/v1/cameras': { cameras: [], ai: {
          enabled: false, backend: 'disabled', state: 'disabled',
          model_count: 0, runner_count: 0, reason: 'disabled by config',
          models: [], runners: [],
        } },
        '/api/v1/stream': { url: 'rtsp://camera.local:8555/imx708/main',
          control_tls: false, media_srtp: false, secure_media: {
            control_scheme: 'rtsp', media_profile: 'RTP/AVP', keying: 'none',
            requires_tls_control_channel: false,
          } },
        '/api/v1/ai/detections': { events: [] },
      };
      return parser(payloads[path]);
    });

    render(<App client={client} />);

    expect(await screen.findByRole('heading', { name: 'Operational dashboard' }))
      .toBeVisible();
    expect(screen.getByRole('combobox', { name: /camera/i })).toBeDisabled();
  });

  it('keeps one runtime settings controller across operational navigation', async () => {
    const user = userEvent.setup();
    const client = makeClient();
    vi.mocked(client.getJson).mockImplementation(async (path, parser) => {
      const payloads: Record<string, unknown> = {
        '/api/v1/setup/status': { required: false },
        '/api/v1/auth/me': { username: 'operator.one', role: 'administrator' },
        '/api/v1/health': { status: 'ok' },
        '/api/v1/cameras': { cameras: [], ai: {
          enabled: false, backend: 'disabled', state: 'disabled',
          model_count: 0, runner_count: 0, reason: 'disabled by config',
          models: [], runners: [],
        } },
        '/api/v1/stream': { url: 'rtsp://camera.local:8555/imx708/main',
          control_tls: false, media_srtp: false, secure_media: {
            control_scheme: 'rtsp', media_profile: 'RTP/AVP', keying: 'none',
            requires_tls_control_channel: false,
          } },
        '/api/v1/ai/detections': { events: [] },
        '/api/v1/settings/runtime': {
          schema_version: 1,
          revision: 0,
          state: 'clean',
          capabilities: {
            camera_profiles: [{ id: 'imx708-1080p50', width: 1920,
              height: 1080, fps: 50, label: '1080p / 50 fps' }],
            bitrate_kbps: { minimum: 500, maximum: 20_000 },
            gop: { minimum: 1, maximum: 300 },
            models: [],
          },
          active: { camera: { profile_id: 'imx708-1080p50',
            bitrate_kbps: 6_000, gop: 25 }, models: [] },
          pending: null,
          last_apply: { status: 'never', code: '', restored: false },
        },
      };
      return parser(payloads[path]);
    });

    render(<App client={client} />);
    await screen.findByRole('heading', { name: 'Operational dashboard' });
    await waitFor(() => expect(vi.mocked(client.getJson).mock.calls.filter(
      ([path]) => path === '/api/v1/settings/runtime',
    )).toHaveLength(1));

    await user.click(screen.getByRole('link', { name: 'Cameras' }));
    await screen.findByRole('heading', { name: 'Cameras' });
    await user.click(screen.getByRole('link', { name: 'AI' }));
    await screen.findByRole('heading', { name: 'AI inference' });

    expect(vi.mocked(client.getJson).mock.calls.filter(
      ([path]) => path === '/api/v1/settings/runtime',
    )).toHaveLength(1);
  });

  it('forces anonymous users to login even after direct protected hash manipulation', async () => {
    const client = makeClient();
    vi.mocked(client.getJson)
      .mockResolvedValueOnce({ required: false })
      .mockRejectedValueOnce(new UnauthorizedError());
    window.location.hash = '#/system';

    render(<App client={client} />);

    expect(await screen.findByRole('heading', { name: /camera login/i })).toBeVisible();
    await waitFor(() => expect(window.location.hash).toBe('#/login'));
    expect(screen.queryByRole('navigation', { name: /primary/i })).not.toBeInTheDocument();
  });

  it('signs in through the exact API paths before mounting the protected shell', async () => {
    const user = userEvent.setup();
    const client = makeClient();
    vi.mocked(client.getJson)
      .mockResolvedValueOnce({ required: false })
      .mockRejectedValueOnce(new UnauthorizedError())
      .mockResolvedValueOnce({ username: 'server-owner', role: 'administrator' });
    vi.mocked(client.postJson).mockResolvedValue({
      role: 'administrator',
      idle_expires_at_seconds: 100,
    });
    render(<App client={client} />);
    await user.type(await screen.findByLabelText(/^username$/i), 'operator.one');
    await user.type(screen.getByLabelText(/^password$/i), 'NorthStar!9');

    await user.click(screen.getByRole('button', { name: /sign in/i }));

    expect(client.postJson).toHaveBeenCalledWith(
      '/api/v1/auth/login',
      { username: 'operator.one', password: 'NorthStar!9' },
      expect.any(Function),
    );
    expect(await screen.findByText('server-owner')).toBeVisible();
    expect(window.location.hash).toBe('#/dashboard');
  });

  it('shows generic unavailable feedback and retries setup status', async () => {
    const user = userEvent.setup();
    const client = makeClient();
    vi.mocked(client.getJson)
      .mockRejectedValueOnce(new Error('private transport detail'))
      .mockResolvedValueOnce({ required: false })
      .mockRejectedValueOnce(new UnauthorizedError());

    render(<App client={client} />);

    expect(await screen.findByRole('alert')).toHaveTextContent('Camera management is unavailable.');
    expect(screen.queryByText(/private transport detail/i)).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: /retry/i }));

    expect(await screen.findByRole('heading', { name: /camera login/i })).toBeVisible();
    expect(client.getJson).toHaveBeenCalledTimes(3);
  });

  it('rechecks server status after setup and transitions without claiming authentication', async () => {
    const user = userEvent.setup();
    const client = makeClient();
    vi.mocked(client.getJson)
      .mockResolvedValueOnce({ required: true, phase: 'administrator',
        tls: 'ready', peer_ip: '192.0.2.10' })
      .mockResolvedValueOnce({ required: false })
      .mockRejectedValueOnce(new UnauthorizedError());
    vi.mocked(client.postJson).mockResolvedValue({ required: false, runtime: 'running' });

    render(<App client={client} />);
    await user.type(await screen.findByLabelText(/^username$/i), 'operator.one');
    await user.type(screen.getByLabelText(/^password$/i), 'NorthStar!9');
    await user.type(screen.getByLabelText(/confirm password/i), 'NorthStar!9');
    await user.click(screen.getByRole('button', { name: /initialize camera/i }));

    expect(await screen.findByRole('heading', { name: /camera login/i })).toBeVisible();
    expect(client.getJson).toHaveBeenCalledTimes(3);
    expect(window.location.hash).toBe('#/login');
  });

  it('retries a pending runtime transition without requesting credentials', async () => {
    const user = userEvent.setup();
    const client = makeClient();
    vi.mocked(client.getJson)
      .mockResolvedValueOnce({ required: true, phase: 'runtime_pending',
        tls: 'ready', peer_ip: '192.0.2.10' })
      .mockResolvedValueOnce({ required: false })
      .mockRejectedValueOnce(new UnauthorizedError());
    vi.mocked(client.postJson).mockResolvedValue({
      required: false,
      runtime: 'running',
    });

    render(<App client={client} />);

    await screen.findByRole('heading', { name: 'Start camera runtime' });
    const panel = screen.getByRole('region', { name: 'Start camera runtime' });
    expect(panel).toHaveClass('auth-panel');
    expect(panel.closest('main')).toHaveClass('auth-surface');
    expect(panel.querySelector('.brand-mark')).toHaveTextContent('CF');
    expect(panel.querySelectorAll('.field')).toHaveLength(1);
    expect(screen.queryByLabelText(/^password$/i)).not.toBeInTheDocument();
    const peerInput = screen.getByLabelText(/management peer address/i);
    const startButton = screen.getByRole('button', { name: 'Start runtime' });
    expect(peerInput).toHaveValue('192.0.2.10');
    expect(panel.querySelector('form')).toBeNull();
    expect(panel.querySelector('.auth-form')).toBeInTheDocument();
    expect(startButton)
      .toHaveClass('primary-button');
    expect(startButton).toHaveAttribute('type', 'button');
    await user.click(peerInput);
    await user.keyboard('{Enter}');
    expect(client.postJson).not.toHaveBeenCalled();
    await user.click(startButton);

    expect(client.postJson).toHaveBeenCalledWith(
      '/api/v1/setup/runtime',
      {},
      expect.any(Function),
    );
    expect(await screen.findByRole('heading', { name: 'Camera login' }))
      .toBeVisible();
  });

  it('styles generic runtime recovery feedback without exposing the request failure', async () => {
    const user = userEvent.setup();
    const client = makeClient();
    vi.mocked(client.getJson)
      .mockResolvedValueOnce({ required: true, phase: 'runtime_pending',
        tls: 'ready', peer_ip: '192.0.2.10' })
      .mockResolvedValueOnce({ required: true, phase: 'runtime_pending',
        tls: 'ready', peer_ip: '192.0.2.10' });
    vi.mocked(client.postJson).mockRejectedValue(new Error('runtime detail'));

    render(<App client={client} />);
    await user.click(await screen.findByRole('button', { name: 'Start runtime' }));

    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Camera runtime could not be started. Try again.',
    );
    expect(screen.getByRole('alert')).toHaveClass('form-error');
    expect(screen.queryByText(/runtime detail/i)).not.toBeInTheDocument();
  });

  it('disables the runtime recovery start action while startup is pending', async () => {
    const user = userEvent.setup();
    const client = makeClient();
    vi.mocked(client.getJson).mockResolvedValue({ required: true, phase: 'runtime_pending',
      tls: 'ready', peer_ip: '192.0.2.10' });
    vi.mocked(client.postJson).mockImplementation(() => new Promise<never>(() => {}));

    render(<App client={client} />);
    const button = await screen.findByRole('button', { name: 'Start runtime' });
    await user.click(button);

    expect(button).toBeDisabled();
    expect(button).toHaveTextContent('Starting runtime...');
  });

  it('switches from administrator setup to runtime recovery after a transition failure', async () => {
    const user = userEvent.setup();
    const client = makeClient();
    vi.mocked(client.getJson)
      .mockResolvedValueOnce({ required: true, phase: 'administrator',
        tls: 'ready', peer_ip: '192.0.2.10' })
      .mockResolvedValueOnce({ required: true, phase: 'runtime_pending',
        tls: 'ready', peer_ip: '192.0.2.10' });
    vi.mocked(client.postJson).mockRejectedValue(new Error('runtime detail'));

    render(<App client={client} />);
    await user.type(await screen.findByLabelText(/^username$/i), 'operator.one');
    await user.type(screen.getByLabelText(/^password$/i), 'NorthStar!9');
    await user.type(screen.getByLabelText(/confirm password/i), 'NorthStar!9');
    await user.click(screen.getByRole('button', { name: 'Initialize camera' }));

    expect(await screen.findByRole('heading', { name: 'Start camera runtime' }))
      .toBeVisible();
    expect(screen.queryByText(/runtime detail/i)).not.toBeInTheDocument();
    expect(client.getJson).toHaveBeenCalledTimes(2);
  });

  it('preserves generic setup feedback when authoritative phase does not advance', async () => {
    const user = userEvent.setup();
    const client = makeClient();
    const administrator = { required: true as const, phase: 'administrator' as const,
      tls: 'ready' as const, peer_ip: '192.0.2.10' };
    vi.mocked(client.getJson)
      .mockResolvedValueOnce(administrator)
      .mockResolvedValueOnce(administrator);
    vi.mocked(client.postJson).mockRejectedValue(new Error('policy detail'));

    render(<App client={client} />);
    await user.type(await screen.findByLabelText(/^username$/i), 'operator.one');
    await user.type(screen.getByLabelText(/^password$/i), 'NorthStar!9');
    await user.type(screen.getByLabelText(/confirm password/i), 'NorthStar!9');
    await user.click(screen.getByRole('button', { name: 'Initialize camera' }));

    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Camera initialization failed. Check the credentials and try again.',
    );
    expect(screen.getByRole('heading', { name: 'Create administrator' })).toBeVisible();
    expect(screen.queryByText(/policy detail/i)).not.toBeInTheDocument();
  });

  it('updates the peer address while preserving same-phase setup feedback', async () => {
    const user = userEvent.setup();
    const client = makeClient();
    vi.mocked(client.getJson)
      .mockResolvedValueOnce({ required: true, phase: 'administrator',
        tls: 'ready', peer_ip: '192.0.2.10' })
      .mockResolvedValueOnce({ required: true, phase: 'administrator',
        tls: 'ready', peer_ip: '192.0.2.11' });
    vi.mocked(client.postJson).mockRejectedValue(new Error('policy detail'));

    render(<App client={client} />);
    await user.type(await screen.findByLabelText(/^username$/i), 'operator.one');
    await user.type(screen.getByLabelText(/^password$/i), 'NorthStar!9');
    await user.type(screen.getByLabelText(/confirm password/i), 'NorthStar!9');
    await user.click(screen.getByRole('button', { name: 'Initialize camera' }));

    expect(await screen.findByRole('alert')).toBeVisible();
    expect(screen.getByLabelText(/management peer address/i))
      .toHaveValue('192.0.2.11');
  });

  it('re-enables setup after bounded reconciliation when status never settles', async () => {
    const client = makeClient();
    vi.mocked(client.getJson)
      .mockResolvedValueOnce({ required: true, phase: 'administrator',
        tls: 'ready', peer_ip: '192.0.2.10' })
      .mockReturnValueOnce(new Promise(() => {}));
    vi.mocked(client.postJson).mockRejectedValue(new Error('offline'));

    render(<App client={client} />);
    fireEvent.change(await screen.findByLabelText(/^username$/i), {
      target: { value: 'operator.one' },
    });
    fireEvent.change(screen.getByLabelText(/^password$/i), {
      target: { value: 'NorthStar!9' },
    });
    fireEvent.change(screen.getByLabelText(/confirm password/i), {
      target: { value: 'NorthStar!9' },
    });

    vi.useFakeTimers();
    fireEvent.click(screen.getByRole('button', { name: 'Initialize camera' }));
    await act(async () => {
      await Promise.resolve();
      vi.advanceTimersByTime(5_000);
      await Promise.resolve();
    });

    expect(screen.getByRole('alert')).toHaveTextContent(
      'Camera initialization failed. Check the credentials and try again.',
    );
    expect(screen.getByRole('button', { name: 'Initialize camera' })).toBeEnabled();
  });

  it('leaves runtime recovery when the command response is lost after startup', async () => {
    const user = userEvent.setup();
    const client = makeClient();
    vi.mocked(client.getJson)
      .mockResolvedValueOnce({ required: true, phase: 'runtime_pending',
        tls: 'ready', peer_ip: '192.0.2.10' })
      .mockResolvedValueOnce({ required: false })
      .mockRejectedValueOnce(new UnauthorizedError());
    vi.mocked(client.postJson).mockRejectedValue(new Error('response lost'));

    render(<App client={client} />);
    await user.click(await screen.findByRole('button', { name: 'Start runtime' }));

    expect(await screen.findByRole('heading', { name: 'Camera login' }))
      .toBeVisible();
    expect(screen.queryByText(/response lost/i)).not.toBeInTheDocument();
  });

  it('ignores stale setup status responses after a retry', async () => {
    const user = userEvent.setup();
    const client = makeClient();
    const first = deferred<SetupStatus>();
    vi.mocked(client.getJson)
      .mockReturnValueOnce(first.promise)
      .mockRejectedValueOnce(new Error('offline'))
      .mockResolvedValueOnce({ required: false })
      .mockRejectedValueOnce(new UnauthorizedError());

    const view = render(<App client={client} />);
    view.unmount();
    render(<App client={client} />);
    await user.click(await screen.findByRole('button', { name: /retry/i }));
    expect(await screen.findByRole('heading', { name: /camera login/i })).toBeVisible();

    await act(async () => first.resolve({
      required: true,
      phase: 'administrator',
      tls: 'ready',
      peer_ip: '198.51.100.20',
    }));
    await waitFor(() => {
      expect(screen.queryByRole('heading', { name: /create administrator/i }))
        .not.toBeInTheDocument();
    });
  });

  it.each(['global 401', 'logout'] as const)(
    'closes the detection source on %s and creates exactly one after re-authentication',
    async (invalidation) => {
      const user = userEvent.setup();
      const client = makeClient();
      let authenticated = true;
      let unauthorizedHandler: (() => void) | null = null;
      FakeEventSource.instances = [];
      vi.stubGlobal('EventSource', FakeEventSource);
      vi.mocked(client.setUnauthorizedHandler).mockImplementation((handler) => {
        unauthorizedHandler = handler;
      });
      vi.mocked(client.getBlob).mockResolvedValue(new Blob(['snapshot'], {
        type: 'image/jpeg',
      }));
      vi.mocked(client.getJson).mockImplementation(async (path) => {
        const payloads: Record<string, unknown> = {
          '/api/v1/setup/status': { required: false },
          '/api/v1/health': { status: 'ok' },
          '/api/v1/cameras': {
            cameras: [{ id: 'imx708', state: 'streaming', snapshot_available: true }],
            ai: {
              enabled: true, backend: 'hailort', state: 'running',
              model_count: 0, runner_count: 0, reason: 'ready', models: [], runners: [],
            },
          },
          '/api/v1/stream': {
            url: 'rtsps://camera.local:8555/imx708/main',
            control_tls: true,
            media_srtp: true,
            secure_media: {
              control_scheme: 'rtsps', media_profile: 'RTP/SAVP', keying: 'sdes',
              requires_tls_control_channel: true,
            },
          },
          '/api/v1/ai/detections': { events: [] },
        };
        if (path === '/api/v1/auth/me') {
          if (!authenticated) {
            throw new UnauthorizedError();
          }
          return { username: 'operator.one', role: 'administrator' } as never;
        }
        return payloads[path] as never;
      });
      vi.mocked(client.postJson).mockImplementation(async (path, _body, _parser, signal) => {
        if (path === '/api/v1/auth/logout') {
          return new Promise((_, reject) => signal?.addEventListener('abort', () => {
            reject(new DOMException('Aborted', 'AbortError'));
          }, { once: true }));
        }
        authenticated = true;
        return { role: 'administrator', idle_expires_at_seconds: 100 } as never;
      });

      render(<App client={client} />);

      expect(await screen.findByRole('heading', { name: 'Operational dashboard' }))
        .toBeVisible();
      await waitFor(() => expect(FakeEventSource.instances).toHaveLength(1));
      const firstSource = FakeEventSource.instances[0];

      if (invalidation === 'global 401') {
        authenticated = false;
        const handler: unknown = unauthorizedHandler;
        if (typeof handler !== 'function') {
          throw new Error('Unauthorized handler was not registered');
        }
        handler();
      } else {
        await user.click(screen.getByRole('button', { name: 'Open user menu' }));
        await user.click(screen.getByRole('button', { name: 'Sign out' }));
      }

      expect(await screen.findByRole('heading', { name: 'Camera login' })).toBeVisible();
      expect(firstSource.close).toHaveBeenCalledOnce();
      expect(FakeEventSource.instances).toHaveLength(1);

      await user.type(screen.getByLabelText(/^username$/i), 'operator.one');
      await user.type(screen.getByLabelText(/^password$/i), 'NorthStar!9');
      await user.click(screen.getByRole('button', { name: 'Sign in' }));

      expect(await screen.findByRole('heading', { name: 'Operational dashboard' }))
        .toBeVisible();
      await waitFor(() => expect(FakeEventSource.instances).toHaveLength(2));
      expect(FakeEventSource.instances[1].url)
        .toBe('/api/v1/ai/detections/stream');
    },
  );
});

function renderRecoveredSession(
  role: 'administrator' | 'viewer',
  pathname: string,
  overrides: Record<string, unknown> = {},
) {
  const client = makeClient();
  window.location.hash = `#${pathname}`;
  vi.mocked(client.getBlob).mockResolvedValue(new Blob(['snapshot'], { type: 'image/jpeg' }));
  vi.mocked(client.getJson).mockImplementation(async (path, parser) => {
    const payloads: Record<string, unknown> = {
      '/api/v1/setup/status': { required: false },
      '/api/v1/auth/me': { username: `${role}.one`, role },
      '/api/v1/health': { status: 'ok' },
      '/api/v1/cameras': {
        cameras: [],
        ai: {
          enabled: false, backend: 'disabled', state: 'disabled', model_count: 0,
          runner_count: 0, reason: 'disabled', models: [], runners: [],
        },
      },
      '/api/v1/stream': {
        url: 'rtsp://camera.local:8555/main', control_tls: false, media_srtp: false,
        secure_media: {
          control_scheme: 'rtsp', media_profile: 'RTP/AVP', keying: 'none',
          requires_tls_control_channel: false,
        },
      },
      '/api/v1/settings/runtime': {
        schema_version: 1,
        revision: 0,
        state: 'clean',
        capabilities: {
          camera_profiles: [], bitrate_kbps: { minimum: 500, maximum: 20_000 },
          gop: { minimum: 1, maximum: 300 }, models: [],
        },
        active: { camera: { profile_id: '', bitrate_kbps: 500, gop: 1 }, models: [] },
        pending: null,
        last_apply: { status: 'never', code: '', restored: false },
      },
      '/api/v1/monitoring/cameras': {
        cameras: [{ id: 'imx708', state: 'streaming', snapshot_available: true,
          width: 1920, height: 1080 }],
      },
    };
    return parser({ ...payloads, ...overrides }[path]) as never;
  });
  render(<App client={client} />);
  return client;
}

describe('App role-specific route trees', () => {
  it('uses the supplied parser when recovering a principal', async () => {
    renderRecoveredSession('viewer', '/monitor', {
      '/api/v1/auth/me': { username: 'viewer.one', role: 'operator' },
    });

    expect(await screen.findByRole('heading', { name: /camera login/i })).toBeVisible();
  });

  it('preserves administrator child injection without constructing default controllers', async () => {
    const client = makeClient();
    window.location.hash = '#/dashboard';
    vi.mocked(client.getJson)
      .mockResolvedValueOnce({ required: false })
      .mockResolvedValueOnce({ username: 'administrator.one', role: 'administrator' });

    render(<App client={client} operationalChild={<p>Injected operational child</p>} />);

    expect(await screen.findByText('Injected operational child')).toBeVisible();
    expect(administratorHooks.operationalConstructed).toBe(0);
    expect(administratorHooks.runtimeConstructed).toBe(0);
  });

  it.each(['/dashboard', '/cameras', '/ai', '/system', '/users', '/monitor'])(
    'redirects an anonymous operational deep link from %s to login',
    async (pathname) => {
      const client = makeClient();
      window.location.hash = `#${pathname}`;
      vi.mocked(client.getJson)
        .mockResolvedValueOnce({ required: false })
        .mockRejectedValueOnce(new UnauthorizedError());

      render(<App client={client} />);

      await screen.findByRole('heading', { name: /camera login/i });
      await waitFor(() => expect(window.location.hash).toBe('#/login'));
    },
  );

  it.each([
    ['/login', '/dashboard'],
    ['/monitor', '/dashboard'],
    ['/dashboard', '/dashboard'],
    ['/cameras', '/cameras'],
    ['/ai', '/ai'],
    ['/system', '/system'],
    ['/users', '/users'],
  ] as const)('routes administrator %s to %s', async (pathname, expectedPath) => {
    renderRecoveredSession('administrator', pathname);

    await waitFor(() => expect(window.location.hash).toBe(`#${expectedPath}`));
  });

  it.each([
    ['/login', '/monitor'],
    ['/dashboard', '/monitor'],
    ['/cameras', '/monitor'],
    ['/ai', '/monitor'],
    ['/system', '/monitor'],
    ['/users', '/monitor'],
    ['/unknown', '/monitor'],
    ['/monitor', '/monitor'],
  ] as const)('routes viewer %s to %s without administrator hooks', async (pathname, expectedPath) => {
    administratorHooks.throwOnConstruction = true;
    FakeEventSource.instances = [];
    vi.stubGlobal('EventSource', FakeEventSource);
    const client = renderRecoveredSession('viewer', pathname);

    await screen.findByRole('heading', { name: 'Live monitoring' });
    await waitFor(() => expect(window.location.hash).toBe(`#${expectedPath}`));
    expect(administratorHooks.operationalConstructed).toBe(0);
    expect(administratorHooks.runtimeConstructed).toBe(0);
    const getJsonPaths = vi.mocked(client.getJson).mock.calls.map(([path]) => path);
    expect(getJsonPaths).toEqual(expect.arrayContaining([
      '/api/v1/setup/status',
      '/api/v1/auth/me',
      '/api/v1/monitoring/cameras',
    ]));
    expect(getJsonPaths.every((path) => [
      '/api/v1/setup/status',
      '/api/v1/auth/me',
      '/api/v1/monitoring/cameras',
    ].includes(path))).toBe(true);
    for (const path of [
      '/api/v1/health',
      '/api/v1/cameras',
      '/api/v1/stream',
      '/api/v1/settings/runtime',
      '/api/v1/security/users',
      '/api/v1/security/management-ips',
    ]) {
      expect(getJsonPaths).not.toContain(path);
    }
    expect(vi.mocked(client.getBlob).mock.calls.map(([path]) => path)).toEqual([
      '/api/v1/cameras/imx708/snapshot.jpg',
    ]);
    expect(vi.mocked(client.postJson).mock.calls).toEqual([]);
    expect(vi.mocked(client.putJson).mock.calls).toEqual([]);
    expect(vi.mocked(client.deleteJson).mock.calls).toEqual([]);
    expect(FakeEventSource.instances.map(({ url }) => url)).toEqual([
      '/api/v1/ai/detections/stream',
    ]);
  });
});
