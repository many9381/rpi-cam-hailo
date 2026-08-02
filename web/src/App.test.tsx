import '@testing-library/jest-dom/vitest';

import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { StrictMode } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ApiClient, UnauthorizedError } from './api/client';
import type { CameraApiClient, SetupStatus } from './api/types';
import { App } from './App';

const administratorHooks = vi.hoisted(() => ({
  throwOnConstruction: false,
  operationalConstructed: 0,
  runtimeConstructed: 0,
  userManagementConstructed: 0,
  auditStatusConstructed: 0,
  auditRecordsConstructed: 0,
  protectionConstructed: 0,
}));

const originalScrollIntoView = Element.prototype.scrollIntoView;

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

vi.mock('./features/users/useUserManagement', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./features/users/useUserManagement')>();
  return {
    ...actual,
    useUserManagement: (...args: Parameters<typeof actual.useUserManagement>) => {
      administratorHooks.userManagementConstructed += 1;
      if (administratorHooks.throwOnConstruction) {
        throw new Error('Viewer session must not construct useUserManagement');
      }
      return actual.useUserManagement(...args);
    },
  };
});

vi.mock('./features/audit/useAuditStatus', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./features/audit/useAuditStatus')>();
  const { useRef } = await import('react');
  return {
    ...actual,
    useAuditStatus: (...args: Parameters<typeof actual.useAuditStatus>) => {
      const counted = useRef(false);
      if (!counted.current) {
        counted.current = true;
        administratorHooks.auditStatusConstructed += 1;
      }
      if (administratorHooks.throwOnConstruction) {
        throw new Error('Viewer session must not construct useAuditStatus');
      }
      return actual.useAuditStatus(...args);
    },
  };
});

vi.mock('./features/audit/useAuditRecords', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./features/audit/useAuditRecords')>();
  const { useRef } = await import('react');
  return {
    ...actual,
    useAuditRecords: (...args: Parameters<typeof actual.useAuditRecords>) => {
      const counted = useRef(false);
      if (!counted.current) {
        counted.current = true;
        administratorHooks.auditRecordsConstructed += 1;
      }
      if (administratorHooks.throwOnConstruction) {
        throw new Error('Viewer session must not construct useAuditRecords');
      }
      return actual.useAuditRecords(...args);
    },
  };
});

vi.mock('./features/protection/useSystemProtection', async (importOriginal) => {
  const actual = await importOriginal<
    typeof import('./features/protection/useSystemProtection')
  >();
  const { useRef } = await import('react');
  return {
    ...actual,
    useSystemProtection: (
      ...args: Parameters<typeof actual.useSystemProtection>
    ) => {
      const counted = useRef(false);
      if (!counted.current) {
        counted.current = true;
        administratorHooks.protectionConstructed += 1;
      }
      if (administratorHooks.throwOnConstruction) {
        throw new Error('Viewer session must not construct useSystemProtection');
      }
      return actual.useSystemProtection(...args);
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

// A first-boot device that is still serving the initial account's credential.
const uninitializedStatus = {
  required: true,
  phase: 'administrator',
  tls: 'ready',
  peer_ip: '192.0.2.10',
  initial_username: 'setup.x7k2q',
  initial_password: 'T4m#pR9vLw',
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
  if (originalScrollIntoView === undefined) {
    delete (Element.prototype as { scrollIntoView?: Element['scrollIntoView'] })
      .scrollIntoView;
  } else {
    Element.prototype.scrollIntoView = originalScrollIntoView;
  }
  vi.useRealTimers();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  administratorHooks.throwOnConstruction = false;
  administratorHooks.operationalConstructed = 0;
  administratorHooks.runtimeConstructed = 0;
  administratorHooks.userManagementConstructed = 0;
  administratorHooks.auditStatusConstructed = 0;
  administratorHooks.auditRecordsConstructed = 0;
  administratorHooks.protectionConstructed = 0;
});

describe('App bootstrap gate', () => {
  it('shows a checking state until setup status resolves', () => {
    const client = makeClient();
    vi.mocked(client.getJson).mockReturnValue(new Promise(() => {}));

    render(<App client={client} />);

    expect(screen.getByText('Checking camera setup...')).toBeVisible();
    expect(screen.queryByText('Checking session...')).not.toBeInTheDocument();
  });

  it('renders the login page for an uninitialized device instead of a setup form', async () => {
    const client = makeClient();
    vi.mocked(client.getJson).mockImplementation(async (path) => {
      // Nobody has signed in yet, so the resume probe is answered the way
      // every first boot answers it. That is the ordinary path, not a fault:
      // the operator must see the credential panel and no error.
      if (path === '/api/v1/auth/me') {
        throw new UnauthorizedError();
      }
      return uninitializedStatus as never;
    });

    render(<App client={client} />);

    expect(await screen.findByRole('heading', { name: /camera login/i })).toBeVisible();
    expect(screen.queryByRole('heading', { name: /create administrator/i })).not.toBeInTheDocument();
    expect(window.location.hash).not.toBe('#/setup');
    expect(await screen.findByText('setup.x7k2q')).toBeInTheDocument();
    expect(screen.getByText('T4m#pR9vLw')).toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(client.getJson).toHaveBeenCalledWith(
      '/api/v1/setup/status',
      expect.any(Function),
      expect.any(AbortSignal),
    );
  });

  it('resumes the setup wizard on reload while the initial session is still live', async () => {
    const client = makeClient();
    vi.mocked(client.getJson).mockImplementation(async (path, parser) => {
      // The operator signed in before reloading the tab, so the session the
      // wizard needs still exists. Signing in again is not an option: the
      // duplicate-session rule in AuthService refuses a second concurrent
      // session for the same account and reports it as a bad credential.
      if (path === '/api/v1/auth/me') {
        return parser({ username: 'setup.x7k2q', role: 'viewer' }) as never;
      }
      return parser(uninitializedStatus) as never;
    });

    render(<App client={client} />);

    expect(await screen.findByRole('heading', { name: /create administrator/i }))
      .toBeVisible();
    expect(screen.queryByRole('heading', { name: /camera login/i }))
      .not.toBeInTheDocument();
    expect(client.getJson).toHaveBeenCalledWith(
      '/api/v1/auth/me',
      expect.any(Function),
      expect.any(AbortSignal),
    );
  });

  it('renders the setup wizard after signing in with the initial account, then returns to login once initialization succeeds', async () => {
    const user = userEvent.setup();
    const client = makeClient();
    // Modelled on the device: no session until login, and both the initial
    // account and the session it owned are gone once initialize commits.
    let authenticated = false;
    let setupRequired = true;
    vi.mocked(client.getJson).mockImplementation(async (path) => {
      if (path === '/api/v1/auth/me') {
        if (!authenticated) {
          throw new UnauthorizedError();
        }
        return { username: 'setup.x7k2q', role: 'viewer' } as never;
      }
      return (setupRequired ? uninitializedStatus : { required: false }) as never;
    });
    vi.mocked(client.postJson).mockImplementation(async (path, body, parser) => {
      if (path === '/api/v1/auth/login') {
        authenticated = true;
        return parser({ role: 'viewer', idle_expires_at_seconds: 300 });
      }
      if (path === '/api/v1/setup/initialize') {
        setupRequired = false;
        authenticated = false;
        return parser({ required: false, runtime: 'running' });
      }
      throw new Error(`unexpected postJson call: ${path}`);
    });

    render(<App client={client} />);

    await user.type(await screen.findByLabelText(/^username$/i), 'setup.x7k2q');
    await user.type(screen.getByLabelText(/^password$/i), 'T4m#pR9vLw');
    await user.click(screen.getByRole('button', { name: /sign in/i }));

    expect(client.postJson).toHaveBeenCalledWith(
      '/api/v1/auth/login',
      { username: 'setup.x7k2q', password: 'T4m#pR9vLw' },
      expect.any(Function),
    );
    await screen.findByRole('heading', { name: /create administrator/i });
    expect(screen.queryByRole('heading', { name: /camera login/i })).not.toBeInTheDocument();

    await user.type(screen.getByLabelText(/^username$/i), 'operator.one');
    await user.type(screen.getByLabelText(/^password$/i), 'NorthStar!9');
    await user.type(screen.getByLabelText(/confirm password/i), 'NorthStar!9');
    await user.click(screen.getByRole('button', { name: /next/i }));
    await screen.findByRole('heading', { name: /management access/i });
    await user.click(screen.getByRole('button', { name: /^next$/i }));
    await screen.findByRole('heading', { name: /review/i });

    await user.click(screen.getByRole('button', { name: /complete setup/i }));

    expect(client.postJson).toHaveBeenCalledWith(
      '/api/v1/setup/initialize',
      {
        username: 'operator.one',
        password: 'NorthStar!9',
        peer_ip: '192.0.2.10',
        management_ips: [],
      },
      expect.any(Function),
    );
    expect(await screen.findByRole('heading', { name: /camera login/i })).toBeVisible();
    expect(screen.queryByRole('heading', { name: /create administrator/i }))
      .not.toBeInTheDocument();
  });

  it('uses the refreshed peer address on a retry after a failed submission changes it', async () => {
    const user = userEvent.setup();
    const client = makeClient();
    let authenticated = false;
    let setupRequired = true;
    // The reconciliation that follows the failed submission reports the same
    // phase (not advanced) with a different peer — e.g. the operator is
    // behind a proxy whose outbound address changed.
    let peerIp = '192.0.2.10';
    vi.mocked(client.getJson).mockImplementation(async (path) => {
      if (path === '/api/v1/auth/me') {
        if (!authenticated) {
          throw new UnauthorizedError();
        }
        return { username: 'setup.x7k2q', role: 'viewer' } as never;
      }
      return (setupRequired
        ? { ...uninitializedStatus, peer_ip: peerIp }
        : { required: false }) as never;
    });
    let failInitialize = true;
    vi.mocked(client.postJson).mockImplementation(async (path, body, parser) => {
      if (path === '/api/v1/auth/login') {
        authenticated = true;
        return parser({ role: 'viewer', idle_expires_at_seconds: 300 });
      }
      if (path === '/api/v1/setup/initialize') {
        if (failInitialize) {
          peerIp = '192.0.2.11';
          throw new Error('policy detail');
        }
        setupRequired = false;
        authenticated = false;
        return parser({ required: false, runtime: 'running' });
      }
      throw new Error(`unexpected postJson call: ${path}`);
    });

    render(<App client={client} />);
    await user.type(await screen.findByLabelText(/^username$/i), 'setup.x7k2q');
    await user.type(screen.getByLabelText(/^password$/i), 'T4m#pR9vLw');
    await user.click(screen.getByRole('button', { name: /sign in/i }));
    await screen.findByRole('heading', { name: /create administrator/i });

    await user.type(screen.getByLabelText(/^username$/i), 'operator.one');
    await user.type(screen.getByLabelText(/^password$/i), 'NorthStar!9');
    await user.type(screen.getByLabelText(/confirm password/i), 'NorthStar!9');
    await user.click(screen.getByRole('button', { name: /next/i }));
    await screen.findByRole('heading', { name: /management access/i });
    expect(screen.getByRole('list', { name: /registered management hosts/i }))
      .toHaveTextContent('192.0.2.10 (current session)');
    await user.click(screen.getByRole('button', { name: /^next$/i }));
    await screen.findByRole('heading', { name: /review/i });

    await user.click(screen.getByRole('button', { name: /complete setup/i }));

    // Reconciliation reported the same phase with a new peer_ip: the
    // wizard stays up, the operator is sent back to re-enter the cleared
    // password, and the IP step must show the UPDATED address, not the
    // stale one captured when the wizard first rendered.
    await screen.findByRole('heading', { name: /create administrator/i });
    expect(screen.getByRole('alert')).toBeVisible();
    await user.type(screen.getByLabelText(/^password$/i), 'NorthStar!9');
    await user.type(screen.getByLabelText(/confirm password/i), 'NorthStar!9');
    await user.click(screen.getByRole('button', { name: /next/i }));
    await screen.findByRole('heading', { name: /management access/i });
    expect(screen.getByRole('list', { name: /registered management hosts/i }))
      .toHaveTextContent('192.0.2.11 (current session)');
    await user.click(screen.getByRole('button', { name: /^next$/i }));
    await screen.findByRole('heading', { name: /review/i });

    failInitialize = false;
    await user.click(screen.getByRole('button', { name: /complete setup/i }));

    expect(await screen.findByRole('heading', { name: /camera login/i })).toBeVisible();
    const initializeCalls = vi.mocked(client.postJson).mock.calls
      .filter(([path]) => path === '/api/v1/setup/initialize');
    // The first (failed) attempt legitimately used the address the wizard
    // was told about at the time — that is not the bug being guarded here.
    // What matters is that the retry, after peer_ip changed underneath it,
    // used the fresh value rather than a value captured in a stale closure.
    expect(initializeCalls).toHaveLength(2);
    expect(initializeCalls[0][1]).toMatchObject({ peer_ip: '192.0.2.10' });
    expect(initializeCalls[1][1]).toMatchObject({ peer_ip: '192.0.2.11' });
  });

  it('does not render a credential panel when the server withholds the initial credential', async () => {
    const client = makeClient();
    vi.mocked(client.getJson).mockImplementation(async (path) => {
      if (path === '/api/v1/auth/me') {
        throw new UnauthorizedError();
      }
      return {
        required: true,
        phase: 'administrator',
        tls: 'ready',
        peer_ip: '192.0.2.10',
      } as never;
    });

    render(<App client={client} />);

    expect(await screen.findByRole('heading', { name: /camera login/i })).toBeVisible();
    expect(screen.queryByText(/초기 설정|initial setup/i)).not.toBeInTheDocument();
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

  it('re-enables runtime recovery after bounded reconciliation when status never settles', async () => {
    const client = makeClient();
    vi.mocked(client.getJson)
      .mockResolvedValueOnce({ required: true, phase: 'runtime_pending',
        tls: 'ready', peer_ip: '192.0.2.10' })
      .mockReturnValueOnce(new Promise(() => {}));
    vi.mocked(client.postJson).mockRejectedValue(new Error('offline'));

    render(<App client={client} />);
    const startButton = await screen.findByRole('button', { name: 'Start runtime' });

    vi.useFakeTimers();
    fireEvent.click(startButton);
    await act(async () => {
      await Promise.resolve();
      vi.advanceTimersByTime(5_000);
      await Promise.resolve();
    });

    expect(screen.getByRole('alert')).toHaveTextContent(
      'Camera runtime could not be started. Try again.',
    );
    expect(screen.getByRole('button', { name: 'Start runtime' })).toBeEnabled();
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
      initial_username: null,
      initial_password: null,
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
  options: {
    strictMode?: boolean;
    pendingPaths?: ReadonlySet<string>;
    auditStatusResponses?: ReadonlyArray<unknown | Promise<unknown>>;
  } = {},
) {
  const client = makeClient();
  const auditStatusResponses = [...(options.auditStatusResponses ?? [])];
  window.location.hash = `#${pathname}`;
  vi.mocked(client.getBlob).mockResolvedValue(new Blob(['snapshot'], { type: 'image/jpeg' }));
  vi.mocked(client.getJson).mockImplementation(async (path, parser) => {
    if (options.pendingPaths?.has(path)) {
      return new Promise<never>(() => {});
    }
    if (path === '/api/v1/audit/status' && auditStatusResponses.length > 0) {
      return parser(await auditStatusResponses.shift()) as never;
    }
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
      '/api/v1/ai/detections': { events: [] },
      '/api/v1/audit/status': {
        current_events: 10,
        max_events: 100,
        usage_percent: 10,
        warning: false,
        rotated_event_count: 0,
        last_rotation_at_seconds: null,
        last_rotated_sequence: null,
      },
      '/api/v1/audit/events?sort_by=timestamp&sort_direction=desc&limit=50': {
        events: [],
        next_cursor: null,
      },
      '/api/v1/system/protection': {
        state: 'operational',
        check_running: false,
        next_periodic_at_seconds: 1_784_586_400,
        self_test: null,
        integrity: null,
      },
      '/api/v1/monitoring/cameras': {
        cameras: [{ id: 'imx708', state: 'streaming', snapshot_available: true,
          width: 1920, height: 1080 }],
      },
    };
    return parser({ ...payloads, ...overrides }[path]) as never;
  });
  const application = <App client={client} />;
  render(options.strictMode
    ? <StrictMode>{application}</StrictMode>
    : application);
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
    expect(administratorHooks.userManagementConstructed).toBe(0);
    expect(administratorHooks.auditStatusConstructed).toBe(0);
    expect(administratorHooks.auditRecordsConstructed).toBe(0);
    expect(administratorHooks.protectionConstructed).toBe(0);
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

  it.each(['/dashboard', '/cameras', '/ai', '/users'])(
    'constructs one audit status controller and no records controller on %s',
    async (pathname) => {
      const client = renderRecoveredSession('administrator', pathname, pathname === '/users'
        ? {
          '/api/v1/security/users': { users: [] },
          '/api/v1/security/management-ips': {
            management_ips: [],
            current_peer_ip: '192.0.2.44',
          },
        }
        : {});

      await waitFor(() => expect(vi.mocked(client.getJson).mock.calls.filter(
        ([path]) => path === '/api/v1/audit/status',
      )).toHaveLength(1));
      expect(administratorHooks.auditStatusConstructed).toBe(1);
      expect(administratorHooks.auditRecordsConstructed).toBe(0);
      expect(vi.mocked(client.getJson).mock.calls.some(
        ([path]) => path.startsWith('/api/v1/audit/events'),
      )).toBe(false);
    },
  );

  it('constructs one status and one records controller only on System', async () => {
    const client = renderRecoveredSession('administrator', '/system');

    expect(await screen.findByRole('heading', { name: 'Audit records' })).toBeVisible();
    await waitFor(() => expect(vi.mocked(client.getJson).mock.calls.filter(
      ([path]) => path.startsWith('/api/v1/audit/events?'),
    )).toHaveLength(1));
    expect(administratorHooks.auditStatusConstructed).toBe(1);
    expect(administratorHooks.auditRecordsConstructed).toBe(1);
    expect(administratorHooks.protectionConstructed).toBe(1);
    expect(screen.getByRole('heading', { name: 'System protection' })).toBeVisible();
    expect(vi.mocked(client.getJson).mock.calls.filter(
      ([path]) => path === '/api/v1/audit/status',
    )).toHaveLength(1);
  });

  it('scrolls and focuses audit records after the capacity warning routes to System', async () => {
    const user = userEvent.setup();
    const scrollIntoView = vi.fn();
    Element.prototype.scrollIntoView = scrollIntoView;
    renderRecoveredSession('administrator', '/dashboard', {
      '/api/v1/audit/status': {
        current_events: 90,
        max_events: 100,
        usage_percent: 90,
        warning: true,
        rotated_event_count: 4,
        last_rotation_at_seconds: null,
        last_rotated_sequence: null,
      },
    });

    await user.click(await screen.findByRole('link', { name: 'Review audit records' }));

    const auditSection = await screen.findByRole('region', { name: 'Audit records' });
    await waitFor(() => {
      expect(window.location.hash).toBe('#/system#audit-records');
      expect(scrollIntoView).toHaveBeenCalledOnce();
      expect(document.activeElement).toBe(auditSection);
    });

    const refresh = screen.getByRole('button', { name: 'Refresh audit records' });
    await user.click(refresh);
    await waitFor(() => expect(refresh).toHaveFocus());
    expect(scrollIntoView).toHaveBeenCalledOnce();
  });

  it('leaves one live audit status request and poll interval after the StrictMode probe', async () => {
    const setInterval = vi.spyOn(window, 'setInterval');
    const clearInterval = vi.spyOn(window, 'clearInterval');
    const client = renderRecoveredSession('administrator', '/dashboard', {}, {
      strictMode: true,
      pendingPaths: new Set(['/api/v1/audit/status']),
    });

    expect(await screen.findByRole('heading', { name: 'Operational dashboard' }))
      .toBeVisible();
    await waitFor(() => expect(vi.mocked(client.getJson).mock.calls.filter(
      ([path]) => path === '/api/v1/audit/status',
    )).toHaveLength(2));

    const statusSignals = vi.mocked(client.getJson).mock.calls
      .filter(([path]) => path === '/api/v1/audit/status')
      .map(([, , signal]) => signal);
    expect(statusSignals.map((signal) => signal?.aborted)).toEqual([true, false]);

    const auditTimerIds = setInterval.mock.calls.flatMap(([, delay], index) =>
      delay === 30_000 ? [setInterval.mock.results[index]?.value] : []);
    const clearedTimerIds = clearInterval.mock.calls.map(([timerId]) => timerId);
    expect(auditTimerIds).toHaveLength(4);
    expect(auditTimerIds.filter((timerId) => !clearedTimerIds.includes(timerId)))
      .toHaveLength(2);
  });

  it('leaves one live System event request after the StrictMode probe', async () => {
    const eventPath = '/api/v1/audit/events?sort_by=timestamp&sort_direction=desc&limit=50';
    const client = renderRecoveredSession('administrator', '/system', {}, {
      strictMode: true,
      pendingPaths: new Set([eventPath]),
    });

    expect(await screen.findByRole('heading', { name: 'Audit records' })).toBeVisible();
    await waitFor(() => expect(vi.mocked(client.getJson).mock.calls.filter(
      ([path]) => path === eventPath,
    )).toHaveLength(2));

    const eventSignals = vi.mocked(client.getJson).mock.calls
      .filter(([path]) => path === eventPath)
      .map(([, , signal]) => signal);
    expect(eventSignals.map((signal) => signal?.aborted)).toEqual([true, false]);
  });

  it('starts zero audit effects for a viewer StrictMode entry', async () => {
    administratorHooks.throwOnConstruction = true;
    const setInterval = vi.spyOn(window, 'setInterval');
    const client = renderRecoveredSession('viewer', '/monitor', {}, {
      strictMode: true,
    });

    expect(await screen.findByRole('heading', { name: 'Live monitoring' })).toBeVisible();
    expect(vi.mocked(client.getJson).mock.calls.filter(
      ([path]) => path === '/api/v1/audit/status' || path.startsWith('/api/v1/audit/events'),
    )).toHaveLength(0);
    expect(setInterval.mock.calls.filter(([, delay]) => delay === 30_000))
      .toHaveLength(0);
  });

  it('keeps the operational status controller while leaving System', async () => {
    const user = userEvent.setup();
    const client = renderRecoveredSession('administrator', '/system');
    await screen.findByRole('heading', { name: 'Audit records' });
    await waitFor(() => expect(administratorHooks.auditRecordsConstructed).toBe(1));

    await user.click(screen.getByRole('link', { name: 'Dashboard' }));
    await screen.findByRole('heading', { name: 'Operational dashboard' });

    expect(administratorHooks.auditStatusConstructed).toBe(1);
    expect(administratorHooks.auditRecordsConstructed).toBe(1);
    expect(administratorHooks.protectionConstructed).toBe(1);
    expect(vi.mocked(client.getJson).mock.calls.filter(
      ([path]) => path === '/api/v1/audit/status',
    )).toHaveLength(1);
    expect(vi.mocked(client.getJson).mock.calls.filter(
      ([path]) => path.startsWith('/api/v1/audit/events?'),
    )).toHaveLength(1);
  });

  it('preserves an audit warning across administrator route transitions', async () => {
    const user = userEvent.setup();
    const pendingStatus = deferred<unknown>();
    const client = renderRecoveredSession('administrator', '/dashboard', {
      '/api/v1/security/users': { users: [] },
      '/api/v1/security/management-ips': {
        management_ips: [],
        current_peer_ip: '192.0.2.44',
      },
    }, {
      auditStatusResponses: [{
        current_events: 90,
        max_events: 100,
        usage_percent: 90,
        warning: true,
        rotated_event_count: 4,
        last_rotation_at_seconds: null,
        last_rotated_sequence: null,
      }, pendingStatus.promise, {
        current_events: 40,
        max_events: 100,
        usage_percent: 40,
        warning: false,
        rotated_event_count: 4,
        last_rotation_at_seconds: null,
        last_rotated_sequence: null,
      }],
    });

    const warningText = /Audit storage is at 90%/;
    expect(await screen.findByText(warningText)).toBeVisible();
    await user.click(screen.getByRole('button', { name: 'Refresh device state' }));
    await waitFor(() => expect(vi.mocked(client.getJson).mock.calls.filter(
      ([path]) => path === '/api/v1/audit/status',
    )).toHaveLength(2));

    await user.click(screen.getByRole('link', { name: 'System' }));
    await screen.findByRole('heading', { name: 'Audit records' });
    expect(screen.getByText(warningText)).toBeVisible();

    await user.click(screen.getByRole('link', { name: 'Users' }));
    await screen.findByRole('heading', { name: 'Users & access' });
    expect(screen.getByText(warningText)).toBeVisible();

    await user.click(screen.getByRole('link', { name: 'Dashboard' }));
    await screen.findByRole('heading', { name: 'Operational dashboard' });
    expect(screen.getByText(warningText)).toBeVisible();
    expect(administratorHooks.auditStatusConstructed).toBe(1);
    expect(vi.mocked(client.getJson).mock.calls.filter(
      ([path]) => path === '/api/v1/audit/status',
    )).toHaveLength(2);

    pendingStatus.reject(new Error('status refresh failed'));
    expect(await screen.findByText(/Capacity status may be out of date\./))
      .toBeVisible();
    expect(screen.getByText(warningText)).toBeVisible();

    await user.click(screen.getByRole('button', { name: 'Refresh device state' }));
    await waitFor(() => expect(screen.queryByText(warningText))
      .not.toBeInTheDocument());
    expect(vi.mocked(client.getJson).mock.calls.filter(
      ([path]) => path === '/api/v1/audit/status',
    )).toHaveLength(3);
  });

  it('refreshes audit status with the administrator operational shell', async () => {
    const user = userEvent.setup();
    const client = renderRecoveredSession('administrator', '/dashboard');
    await screen.findByRole('heading', { name: 'Operational dashboard' });
    await waitFor(() => expect(vi.mocked(client.getJson).mock.calls.filter(
      ([path]) => path === '/api/v1/audit/status',
    )).toHaveLength(1));

    await user.click(screen.getByRole('button', { name: 'Refresh device state' }));

    await waitFor(() => expect(vi.mocked(client.getJson).mock.calls.filter(
      ([path]) => path === '/api/v1/audit/status',
    )).toHaveLength(2));
  });

  it('prompts to reauthenticate when management authority lapses, then resumes the view', async () => {
    const user = userEvent.setup();
    const client = renderRecoveredSession('administrator', '/dashboard');
    await screen.findByRole('heading', { name: 'Operational dashboard' });
    await waitFor(() => expect(vi.mocked(client.getJson).mock.calls.filter(
      ([path]) => path === '/api/v1/health',
    )).toHaveLength(1));

    vi.mocked(client.getJson).mockRejectedValueOnce(
      new UnauthorizedError('E_MANAGEMENT_REAUTHENTICATION_REQUIRED'),
    );
    await user.click(screen.getByRole('button', { name: 'Refresh device state' }));

    const passwordInput = await screen.findByLabelText(/password/i);
    vi.mocked(client.postJson).mockImplementationOnce(async (path, body, parser) => {
      expect(path).toBe('/api/v1/auth/reauthenticate');
      expect(body).toEqual({ password: 'NorthStar!9' });
      return parser({ management_expires_at_seconds: 4_000 });
    });

    await user.type(passwordInput, 'NorthStar!9');
    await user.click(screen.getByRole('button', { name: /confirm/i }));

    await waitFor(() => expect(screen.queryByLabelText(/password/i)).not.toBeInTheDocument());
    await waitFor(() => expect(vi.mocked(client.getJson).mock.calls.filter(
      ([path]) => path === '/api/v1/health',
    )).toHaveLength(3));
    expect(screen.queryByRole('heading', { name: 'Camera login' })).not.toBeInTheDocument();
    expect(await screen.findByRole('heading', { name: 'Operational dashboard' }))
      .toBeVisible();
  });

  it('does not prompt to reauthenticate for an ordinary authentication failure', async () => {
    const user = userEvent.setup();
    const client = renderRecoveredSession('administrator', '/dashboard');
    await screen.findByRole('heading', { name: 'Operational dashboard' });

    vi.mocked(client.getJson).mockRejectedValueOnce(
      new UnauthorizedError('E_AUTHENTICATION_REQUIRED'),
    );
    await user.click(screen.getByRole('button', { name: 'Refresh device state' }));

    await waitFor(() => expect(vi.mocked(client.getJson).mock.calls.filter(
      ([path]) => path === '/api/v1/health',
    )).toHaveLength(2));
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Operational dashboard' })).toBeVisible();
  });

  it('leaves the operator authenticated with the modal open after a rejected reauthentication password', async () => {
    // This test exercises the real ApiClient (not the mocked CameraApiClient used by
    // renderRecoveredSession) against a controllable fetch, because the regression it
    // pins lives inside ApiClient.requireSuccess: a wrong password on
    // /api/v1/auth/reauthenticate must not invoke the unauthorized handler and must not
    // drop the operator to the login screen.
    const user = userEvent.setup();
    const jsonFetchResponse = (value: unknown, status = 200) => new Response(
      JSON.stringify(value),
      { status, headers: { 'Content-Type': 'application/json' } },
    );
    let healthCalls = 0;
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      const method = (init?.method ?? 'GET').toUpperCase();

      if (url === '/api/v1/setup/status') {
        return jsonFetchResponse({ required: false });
      }
      if (url === '/api/v1/auth/me') {
        return jsonFetchResponse({ username: 'administrator.one', role: 'administrator' });
      }
      if (url === '/api/v1/auth/reauthenticate' && method === 'POST') {
        return jsonFetchResponse(
          { code: 'E_AUTHENTICATION_FAILED', message: 'authentication failed' },
          401,
        );
      }
      if (url === '/api/v1/health') {
        healthCalls += 1;
        if (healthCalls === 2) {
          return jsonFetchResponse({
            code: 'E_MANAGEMENT_REAUTHENTICATION_REQUIRED',
            message: 'management reauthentication required',
          }, 401);
        }
        return jsonFetchResponse({ status: 'ok' });
      }
      if (url === '/api/v1/cameras') {
        return jsonFetchResponse({
          cameras: [],
          ai: {
            enabled: false, backend: 'disabled', state: 'disabled', model_count: 0,
            runner_count: 0, reason: 'disabled', models: [], runners: [],
          },
        });
      }
      if (url === '/api/v1/stream') {
        return jsonFetchResponse({
          url: 'rtsp://camera.local:8555/main', control_tls: false, media_srtp: false,
          secure_media: {
            control_scheme: 'rtsp', media_profile: 'RTP/AVP', keying: 'none',
            requires_tls_control_channel: false,
          },
        });
      }
      if (url === '/api/v1/settings/runtime') {
        return jsonFetchResponse({
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
        });
      }
      if (url === '/api/v1/ai/detections') {
        return jsonFetchResponse({ events: [] });
      }
      if (url === '/api/v1/audit/status') {
        return jsonFetchResponse({
          current_events: 10,
          max_events: 100,
          usage_percent: 10,
          warning: false,
          rotated_event_count: 0,
          last_rotation_at_seconds: null,
          last_rotated_sequence: null,
        });
      }
      if (url.startsWith('/api/v1/audit/events')) {
        return jsonFetchResponse({ events: [], next_cursor: null });
      }
      if (url === '/api/v1/system/protection') {
        return jsonFetchResponse({
          state: 'operational',
          check_running: false,
          next_periodic_at_seconds: 1_784_586_400,
          self_test: null,
          integrity: null,
        });
      }
      throw new Error(`Unexpected fetch in test: ${method} ${url}`);
    });

    const client = new ApiClient(fetchMock as unknown as typeof fetch);
    window.location.hash = '#/dashboard';
    render(<App client={client} />);

    expect(await screen.findByRole('heading', { name: 'Operational dashboard' })).toBeVisible();
    await user.click(screen.getByRole('button', { name: 'Refresh device state' }));

    const passwordInput = await screen.findByLabelText(/password/i);
    await user.type(passwordInput, 'WrongPass9!');
    await user.click(screen.getByRole('button', { name: /confirm/i }));

    const alert = await screen.findByRole('alert');
    await waitFor(() => expect(alert).not.toHaveTextContent(''));
    expect(screen.getByLabelText(/password/i)).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Operational dashboard' })).toBeVisible();
    expect(screen.queryByRole('heading', { name: 'Camera login' })).not.toBeInTheDocument();
  });

  it('loads administrator users with only the two management resources', async () => {
    const client = renderRecoveredSession('administrator', '/users', {
      '/api/v1/security/users': { users: [] },
      '/api/v1/security/management-ips': {
        management_ips: [{
          id: 1,
          address: '192.0.2.44',
          role: 'administrator',
          created_at_seconds: 100,
        }],
        current_peer_ip: '192.0.2.44',
      },
    });

    expect(await screen.findByRole('heading', { name: 'Users & access' }))
      .toBeVisible();
    await waitFor(() => {
      const securityPaths = vi.mocked(client.getJson).mock.calls
        .map(([path]) => path)
        .filter((path) => path.startsWith('/api/v1/security/'));
      expect(securityPaths).toEqual([
        '/api/v1/security/users',
        '/api/v1/security/management-ips',
      ]);
    });

    expect(administratorHooks.userManagementConstructed).toBeGreaterThan(0);
    expect(administratorHooks.operationalConstructed).toBe(0);
    expect(administratorHooks.runtimeConstructed).toBe(0);
    const getJsonPaths = vi.mocked(client.getJson).mock.calls.map(([path]) => path);
    for (const path of [
      '/api/v1/health',
      '/api/v1/cameras',
      '/api/v1/stream',
      '/api/v1/settings/runtime',
      '/api/v1/ai/detections',
    ]) {
      expect(getJsonPaths).not.toContain(path);
    }
  });

  it('refreshes both management resources and catches refresh failures on users', async () => {
    const user = userEvent.setup();
    const client = renderRecoveredSession('administrator', '/users', {
      '/api/v1/security/users': { users: [] },
      '/api/v1/security/management-ips': {
        management_ips: [],
        current_peer_ip: '192.0.2.44',
      },
    });

    await screen.findByRole('heading', { name: 'Users & access' });
    await waitFor(() => {
      expect(vi.mocked(client.getJson).mock.calls.filter(
        ([path]) => path === '/api/v1/security/users',
      )).toHaveLength(1);
      expect(vi.mocked(client.getJson).mock.calls.filter(
        ([path]) => path === '/api/v1/security/management-ips',
      )).toHaveLength(1);
      expect(vi.mocked(client.getJson).mock.calls.filter(
        ([path]) => path === '/api/v1/audit/status',
      )).toHaveLength(1);
    });
    vi.mocked(client.getJson).mockRejectedValue(new Error('offline'));

    await user.click(screen.getByRole('button', { name: 'Refresh device state' }));

    await waitFor(() => {
      expect(vi.mocked(client.getJson).mock.calls.filter(
        ([path]) => path === '/api/v1/security/users',
      )).toHaveLength(2);
      expect(vi.mocked(client.getJson).mock.calls.filter(
        ([path]) => path === '/api/v1/security/management-ips',
      )).toHaveLength(2);
      expect(vi.mocked(client.getJson).mock.calls.filter(
        ([path]) => path === '/api/v1/audit/status',
      )).toHaveLength(2);
    });
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
    expect(administratorHooks.userManagementConstructed).toBe(0);
    expect(administratorHooks.auditStatusConstructed).toBe(0);
    expect(administratorHooks.auditRecordsConstructed).toBe(0);
    expect(administratorHooks.protectionConstructed).toBe(0);
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
      '/api/v1/audit/status',
      '/api/v1/audit/events?sort_by=timestamp&sort_direction=desc&limit=50',
      '/api/v1/system/protection',
    ]) {
      expect(getJsonPaths).not.toContain(path);
    }
    expect(vi.mocked(client.getBlob).mock.calls.map(([path]) => path)).toEqual([
      '/api/v1/cameras/imx708/snapshot.jpg',
    ]);
    expect(vi.mocked(client.postJson).mock.calls).toEqual([]);
    expect(vi.mocked(client.putJson).mock.calls).toEqual([]);
    expect(vi.mocked(client.deleteJson).mock.calls).toEqual([]);
    expect(screen.queryByRole('heading', { name: 'System protection' }))
      .not.toBeInTheDocument();
    expect(FakeEventSource.instances.map(({ url }) => url)).toEqual([
      '/api/v1/ai/detections/stream',
    ]);
  });
});
