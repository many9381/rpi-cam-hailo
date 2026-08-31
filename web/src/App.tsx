import {
  type ReactNode,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import { HashRouter, useLocation, useNavigate } from 'react-router-dom';

import { UnauthorizedError } from './api/client';
import {
  parseLoginResult,
  parsePrincipal,
  parseReauthenticateResult,
  parseSetupStatus,
} from './api/contracts';
import type { CameraApiClient, Parser, SetupStatus } from './api/types';
import { AuthProvider, useAuth } from './auth/AuthContext';
import { AppShell } from './components/AppShell';
import { ViewerShell } from './components/ViewerShell';
import { LoginPage } from './pages/LoginPage';
import { RuntimeRecoveryPage } from './pages/RuntimeRecoveryPage';
import { SetupWizard } from './pages/setup/SetupWizard';
import { DashboardPage, type OperationalView } from './pages/DashboardPage';
import { MonitorPage } from './pages/MonitorPage';
import { UsersPage } from './pages/UsersPage';
import { useOperationalData } from './hooks/useOperationalData';
import {
  useAuditStatus,
  type AuditStatusController,
} from './features/audit/useAuditStatus';
import { ReauthenticateModal } from './features/auth/ReauthenticateModal';
import { useRuntimeSettings } from './features/settings/useRuntimeSettings';
import { useUserManagement } from './features/users/useUserManagement';
import { useSystemProtection } from './features/protection/useSystemProtection';
import type { SystemProtectionController } from './features/protection/useSystemProtection';

const MANAGEMENT_REAUTHENTICATION_REQUIRED = 'E_MANAGEMENT_REAUTHENTICATION_REQUIRED';

function isManagementReauthenticationRequired(error: unknown): boolean {
  return error instanceof UnauthorizedError &&
    error.code === MANAGEMENT_REAUTHENTICATION_REQUIRED;
}

/**
 * Wraps a CameraApiClient so that any request made through it which fails
 * because the operator's management authority has lapsed notifies the
 * supplied callback before the UnauthorizedError continues to propagate to
 * the original caller. Every other outcome (success or any other failure)
 * passes through unchanged.
 */
function createManagementAwareClient(
  client: CameraApiClient,
  notifyReauthenticationRequired: () => void,
): CameraApiClient {
  async function guard<T>(promise: Promise<T>): Promise<T> {
    try {
      return await promise;
    } catch (error) {
      if (isManagementReauthenticationRequired(error)) {
        notifyReauthenticationRequired();
      }
      throw error;
    }
  }

  return {
    getJson<T>(path: string, parser: Parser<T>, signal?: AbortSignal) {
      return guard(client.getJson(path, parser, signal));
    },
    deleteJson<T>(path: string, parser: Parser<T>, signal?: AbortSignal) {
      return guard(client.deleteJson(path, parser, signal));
    },
    putJson<B, T>(path: string, body: B, parser: Parser<T>, signal?: AbortSignal) {
      return guard(client.putJson(path, body, parser, signal));
    },
    postJson<B, T>(path: string, body: B, parser: Parser<T>, signal?: AbortSignal) {
      return guard(client.postJson(path, body, parser, signal));
    },
    getBlob(path: string, signal?: AbortSignal) {
      return guard(client.getBlob(path, signal));
    },
    setUnauthorizedHandler(handler: (() => void) | null) {
      client.setUnauthorizedHandler(handler);
    },
  };
}

/**
 * True when the caller already holds a session the device accepts.
 *
 * A reload during setup throws away the component state that remembered the
 * operator had signed in, but not the session cookie. Signing in again is not
 * a recovery: AuthService refuses a second concurrent session for one account
 * and reports the refusal as E_AUTHENTICATION_FAILED, so a correct credential
 * looks wrong until the first session idles out. Asking who we are instead
 * costs one request and resumes exactly where the reload interrupted.
 *
 * Every failure — E_AUTHENTICATION_REQUIRED on a device nobody has signed in
 * to yet, an abort, an unreachable camera — means the same thing here and is
 * answered the same way, by leaving the operator on the login page. None of
 * them is an error to report: not holding a session is the normal first boot.
 */
async function holdsLiveSession(
  client: CameraApiClient,
  signal: AbortSignal,
): Promise<boolean> {
  try {
    await client.getJson('/api/v1/auth/me', parsePrincipal, signal);
    return true;
  } catch {
    return false;
  }
}

type BootstrapState =
  | { kind: 'checking' }
  | { kind: 'required'; status: Extract<SetupStatus, { required: true }> }
  | { kind: 'operational' }
  | { kind: 'unavailable' };

interface BootstrapGateProps {
  client: CameraApiClient;
  operationalChild?: ReactNode;
}

export function BootstrapGate({
  client,
  operationalChild = (
    <main className="loading-surface">Checking session...</main>
  ),
}: BootstrapGateProps) {
  const location = useLocation();
  const navigate = useNavigate();
  const [attempt, setAttempt] = useState(0);
  const [state, setState] = useState<BootstrapState>({ kind: 'checking' });
  // Set once the initial account signs in successfully, so the wizard that
  // claims the administrator account renders in the session that login
  // established. /api/v1/setup/initialize requires that session now — see
  // SetupWizard.tsx.
  const [wizardActive, setWizardActive] = useState(false);

  const reconcilePhase = async (
    expected: Extract<SetupStatus, { required: true }>['phase'],
  ): Promise<boolean> => {
    const controller = new AbortController();
    let timeoutId: number | undefined;
    const timeout = new Promise<null>((resolve) => {
      timeoutId = window.setTimeout(() => {
        resolve(null);
        controller.abort();
      }, 5_000);
    });

    try {
      const status = await Promise.race([
        client.getJson(
          '/api/v1/setup/status',
          parseSetupStatus,
          controller.signal,
        ),
        timeout,
      ]);
      if (status === null) {
        return false;
      }
      if (status.required && status.phase === expected) {
        setState({ kind: 'required', status });
        return false;
      }
      setState(status.required
        ? { kind: 'required', status }
        : { kind: 'operational' });
      return true;
    } catch {
      return false;
    } finally {
      window.clearTimeout(timeoutId);
    }
  };

  useEffect(() => {
    let cancelled = false;
    const controller = new AbortController();
    setState({ kind: 'checking' });

    client.getJson('/api/v1/setup/status', parseSetupStatus, controller.signal)
      .then(async (status) => {
        if (cancelled) {
          return;
        }
        if (!status.required) {
          setState({ kind: 'operational' });
          return;
        }
        // Resume a wizard a reload interrupted. Only the administrator phase
        // has a wizard to resume, and only there can a session predate this
        // mount: runtime_pending is reached after the initial account and its
        // session are already gone.
        if (status.phase === 'administrator' &&
            await holdsLiveSession(client, controller.signal)) {
          if (cancelled) {
            return;
          }
          setWizardActive(true);
        }
        if (cancelled) {
          return;
        }
        setState({ kind: 'required', status });
      })
      .catch(() => {
        if (!cancelled) {
          setState({ kind: 'unavailable' });
        }
      });

    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [attempt, client]);

  const requiresRuntimeRecovery = state.kind === 'required' &&
    state.status.phase === 'runtime_pending';

  useEffect(() => {
    if (requiresRuntimeRecovery && location.pathname !== '/setup') {
      navigate('/setup', { replace: true });
    }
  }, [location.pathname, navigate, requiresRuntimeRecovery]);

  const bootstrapLogin = useCallback(async (username: string, password: string) => {
    await client.postJson(
      '/api/v1/auth/login',
      { username, password },
      parseLoginResult,
    );
    setWizardActive(true);
  }, [client]);

  if (state.kind === 'checking') {
    return <main className="loading-surface">Checking camera setup...</main>;
  }
  if (state.kind === 'unavailable') {
    return (
      <main className="loading-surface">
        <div>
          <p role="alert">Camera management is unavailable.</p>
          <button type="button" onClick={() => setAttempt((value) => value + 1)}>
            Retry
          </button>
        </div>
      </main>
    );
  }
  if (state.kind === 'required') {
    if (state.status.phase === 'runtime_pending') {
      return (
        <RuntimeRecoveryPage
          client={client}
          peerIp={state.status.peer_ip}
          onStarted={() => setAttempt((value) => value + 1)}
          onStartFailed={() => reconcilePhase('runtime_pending')}
        />
      );
    }
    if (wizardActive) {
      return (
        <SetupWizard
          client={client}
          peerIp={state.status.peer_ip}
          onInitialized={() => {
            setWizardActive(false);
            setAttempt((value) => value + 1);
          }}
          onInitializationFailed={() => reconcilePhase('administrator')}
        />
      );
    }
    const initialCredential = typeof state.status.initial_username === 'string' &&
        typeof state.status.initial_password === 'string'
      ? {
          username: state.status.initial_username,
          password: state.status.initial_password,
        }
      : null;
    return (
      <LoginPage login={bootstrapLogin} initialCredential={initialCredential} />
    );
  }
  return operationalChild;
}

const administratorPaths = new Set(['/dashboard', '/cameras', '/ai', '/system', '/users']);
const operationalViews: Record<string, OperationalView> = {
  '/dashboard': 'dashboard',
  '/cameras': 'cameras',
  '/ai': 'ai',
  '/system': 'system',
};

type RegisterViewRefresh = (refresh: (() => void) | null) => void;

function AdministratorOperationalShell({
  auditStatus,
  client,
  protection,
  registerViewRefresh,
}: {
  auditStatus: AuditStatusController;
  client: CameraApiClient;
  protection: SystemProtectionController;
  registerViewRefresh: RegisterViewRefresh;
}) {
  const auth = useAuth();
  const location = useLocation();
  const controller = useOperationalData(client);
  const runtimeSettings = useRuntimeSettings(client);
  const view = operationalViews[location.pathname] ?? 'dashboard';
  const onRefresh = useCallback(() => {
    void controller.refresh().catch(() => undefined);
    void runtimeSettings.refresh().catch(() => undefined);
    void auditStatus.refresh().catch(() => undefined);
    void protection.refresh().catch(() => undefined);
  }, [auditStatus, controller, protection, runtimeSettings]);

  useEffect(() => {
    registerViewRefresh(onRefresh);
    return () => registerViewRefresh(null);
  }, [onRefresh, registerViewRefresh]);

  return (
    <AppShell principal={auth.principal!} logout={auth.logout} changePassword={auth.changePassword}
      runtimeSettings={runtimeSettings}
      auditStatus={auditStatus}
      protection={protection}
      onRefresh={onRefresh}>
      <DashboardPage client={client} controller={controller}
        runtimeSettings={runtimeSettings} auditStatus={auditStatus}
        protection={protection}
        auditFragment={location.hash} view={view} />
    </AppShell>
  );
}

function AdministratorUsersShell({ auditStatus, client, protection, registerViewRefresh }: {
  auditStatus: AuditStatusController;
  client: CameraApiClient;
  protection: SystemProtectionController;
  registerViewRefresh: RegisterViewRefresh;
}) {
  const auth = useAuth();
  const controller = useUserManagement(client);
  const onRefresh = useCallback(() => {
    void controller.refreshAll().catch(() => undefined);
    void auditStatus.refresh().catch(() => undefined);
    void protection.refresh().catch(() => undefined);
  }, [auditStatus, controller, protection]);

  useEffect(() => {
    registerViewRefresh(onRefresh);
    return () => registerViewRefresh(null);
  }, [onRefresh, registerViewRefresh]);

  return (
    <AppShell
      principal={auth.principal!}
      logout={auth.logout}
      changePassword={auth.changePassword}
      auditStatus={auditStatus}
      protection={protection}
      onRefresh={onRefresh}
    >
      <UsersPage controller={controller} />
    </AppShell>
  );
}

function AdministratorDefaultApplication({ client, registerViewRefresh }: {
  client: CameraApiClient;
  registerViewRefresh: RegisterViewRefresh;
}) {
  const location = useLocation();
  const auditStatus = useAuditStatus(client);
  const protection = useSystemProtection(client);
  return location.pathname === '/users'
    ? <AdministratorUsersShell client={client} auditStatus={auditStatus}
        protection={protection} registerViewRefresh={registerViewRefresh} />
    : <AdministratorOperationalShell client={client} auditStatus={auditStatus}
        protection={protection} registerViewRefresh={registerViewRefresh} />;
}

function AdministratorApplication({ child, client }: {
  child?: ReactNode;
  client: CameraApiClient;
}) {
  const auth = useAuth();
  const location = useLocation();
  const navigate = useNavigate();
  const [reauthenticationRequired, setReauthenticationRequired] = useState(false);
  const currentViewRefresh = useRef<(() => void) | null>(null);

  const managedClient = useMemo(
    () => createManagementAwareClient(
      client,
      () => setReauthenticationRequired(true),
    ),
    [client],
  );

  const registerViewRefresh = useCallback<RegisterViewRefresh>((refresh) => {
    currentViewRefresh.current = refresh;
  }, []);

  useEffect(() => {
    if (!administratorPaths.has(location.pathname)) {
      navigate('/dashboard', { replace: true });
    }
  }, [location.pathname, navigate]);

  const reauthenticate = useCallback(async (password: string) => {
    await client.postJson(
      '/api/v1/auth/reauthenticate',
      { password },
      parseReauthenticateResult,
    );
  }, [client]);

  return (
    <>
      {child === undefined
        ? <AdministratorDefaultApplication client={managedClient}
            registerViewRefresh={registerViewRefresh} />
        : (
          <AppShell principal={auth.principal!} logout={auth.logout}
            changePassword={auth.changePassword}>
            {child}
          </AppShell>
        )}
      {reauthenticationRequired && (
        <ReauthenticateModal
          reauthenticate={reauthenticate}
          onSuccess={() => {
            setReauthenticationRequired(false);
            currentViewRefresh.current?.();
          }}
          onCancel={() => setReauthenticationRequired(false)}
        />
      )}
    </>
  );
}

function ViewerApplication({ client }: { client: CameraApiClient }) {
  const auth = useAuth();
  const location = useLocation();
  const navigate = useNavigate();

  useEffect(() => {
    if (location.pathname !== '/monitor') {
      navigate('/monitor', { replace: true });
    }
  }, [location.pathname, navigate]);

  return (
    <ViewerShell principal={auth.principal!} logout={auth.logout}
      changePassword={auth.changePassword}>
      <MonitorPage client={client} />
    </ViewerShell>
  );
}

function AuthenticatedApplication({ child, client }: {
  child?: ReactNode;
  client: CameraApiClient;
}) {
  const auth = useAuth();
  const location = useLocation();
  const navigate = useNavigate();

  useEffect(() => {
    if (auth.state === 'anonymous' && location.pathname !== '/login') {
      navigate('/login', { replace: true });
    }
  }, [auth.state, location.pathname, navigate]);

  if (auth.state === 'checking') {
    return <main className="loading-surface">Checking session...</main>;
  }
  if (auth.state === 'anonymous') {
    return <LoginPage login={auth.login} />;
  }
  return auth.principal!.role === 'viewer'
    ? <ViewerApplication client={client} />
    : <AdministratorApplication child={child} client={client} />;
}

interface AppProps {
  client: CameraApiClient;
  operationalChild?: ReactNode;
}

export function App({ client, operationalChild }: AppProps) {
  return (
    <HashRouter>
      <BootstrapGate
        client={client}
        operationalChild={(
          <AuthProvider client={client}>
            <AuthenticatedApplication child={operationalChild} client={client} />
          </AuthProvider>
        )}
      />
    </HashRouter>
  );
}
