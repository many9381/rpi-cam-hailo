import { type ReactNode, useEffect, useState } from 'react';
import { HashRouter, useLocation, useNavigate } from 'react-router-dom';

import { parseSetupStatus } from './api/contracts';
import type { CameraApiClient, SetupStatus } from './api/types';
import { AuthProvider, useAuth } from './auth/AuthContext';
import { AppShell } from './components/AppShell';
import { ViewerShell } from './components/ViewerShell';
import { LoginPage } from './pages/LoginPage';
import { SetupPage } from './pages/SetupPage';
import { RuntimeRecoveryPage } from './pages/RuntimeRecoveryPage';
import { DashboardPage, type OperationalView } from './pages/DashboardPage';
import { MonitorPage } from './pages/MonitorPage';
import { UsersPage } from './pages/UsersPage';
import { useOperationalData } from './hooks/useOperationalData';
import {
  useAuditStatus,
  type AuditStatusController,
} from './features/audit/useAuditStatus';
import { useRuntimeSettings } from './features/settings/useRuntimeSettings';
import { useUserManagement } from './features/users/useUserManagement';

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
      .then((status) => {
        if (cancelled) {
          return;
        }
        if (status.required) {
          setState({ kind: 'required', status });
        } else {
          setState({ kind: 'operational' });
        }
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

  useEffect(() => {
    const destination = state.kind === 'required' ? '/setup' : null;
    if (destination !== null && location.pathname !== destination) {
      navigate(destination, { replace: true });
    }
  }, [location.pathname, navigate, state.kind]);

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
    return (
      <SetupPage
        client={client}
        peerIp={state.status.peer_ip}
        onInitialized={() => setAttempt((value) => value + 1)}
        onInitializationFailed={() => reconcilePhase('administrator')}
      />
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

function AdministratorOperationalShell({
  auditStatus,
  client,
}: {
  auditStatus: AuditStatusController;
  client: CameraApiClient;
}) {
  const auth = useAuth();
  const location = useLocation();
  const controller = useOperationalData(client);
  const runtimeSettings = useRuntimeSettings(client);
  const view = operationalViews[location.pathname] ?? 'dashboard';
  return (
    <AppShell principal={auth.principal!} logout={auth.logout} changePassword={auth.changePassword}
      runtimeSettings={runtimeSettings}
      auditStatus={auditStatus}
      onRefresh={() => {
        void controller.refresh().catch(() => undefined);
        void runtimeSettings.refresh().catch(() => undefined);
        void auditStatus.refresh().catch(() => undefined);
      }}>
      <DashboardPage client={client} controller={controller}
        runtimeSettings={runtimeSettings} auditStatus={auditStatus}
        auditFragment={location.hash} view={view} />
    </AppShell>
  );
}

function AdministratorUsersShell({ auditStatus, client }: {
  auditStatus: AuditStatusController;
  client: CameraApiClient;
}) {
  const auth = useAuth();
  const controller = useUserManagement(client);
  return (
    <AppShell
      principal={auth.principal!}
      logout={auth.logout}
      changePassword={auth.changePassword}
      auditStatus={auditStatus}
      onRefresh={() => {
        void controller.refreshAll().catch(() => undefined);
        void auditStatus.refresh().catch(() => undefined);
      }}
    >
      <UsersPage controller={controller} />
    </AppShell>
  );
}

function AdministratorDefaultApplication({ client }: { client: CameraApiClient }) {
  const location = useLocation();
  const auditStatus = useAuditStatus(client);
  return location.pathname === '/users'
    ? <AdministratorUsersShell client={client} auditStatus={auditStatus} />
    : <AdministratorOperationalShell client={client} auditStatus={auditStatus} />;
}

function AdministratorApplication({ child, client }: {
  child?: ReactNode;
  client: CameraApiClient;
}) {
  const auth = useAuth();
  const location = useLocation();
  const navigate = useNavigate();

  useEffect(() => {
    if (!administratorPaths.has(location.pathname)) {
      navigate('/dashboard', { replace: true });
    }
  }, [location.pathname, navigate]);

  if (child === undefined) {
    return <AdministratorDefaultApplication client={client} />;
  }
  return (
    <AppShell principal={auth.principal!} logout={auth.logout}
      changePassword={auth.changePassword}>
      {child}
    </AppShell>
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
