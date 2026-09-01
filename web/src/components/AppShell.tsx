import {
  Camera,
  LayoutDashboard,
  Menu,
  RefreshCw,
  ScanSearch,
  Settings,
  UsersRound,
  X,
} from 'lucide-react';
import {
  type KeyboardEvent as ReactKeyboardEvent,
  type ReactNode,
  useEffect,
  useRef,
  useState,
} from 'react';
import { useLocation } from 'react-router-dom';

import type { Principal } from '../api/types';
import type { AuthContextValue } from '../auth/AuthContext';
import { AuditCapacityNotice } from '../features/audit/AuditCapacityNotice';
import type { AuditStatusController } from '../features/audit/useAuditStatus';
import { ProtectionNotice } from '../features/protection/ProtectionNotice';
import type { SystemProtectionController } from '../features/protection/useSystemProtection';
import type { RuntimeSettingsController } from '../features/settings/useRuntimeSettings';
import { useTranslation } from '../i18n/LanguageContext';
import { AccountMenu } from './AccountMenu';
import { IconButton } from './IconButton';
import { LanguageSwitcher } from './LanguageSwitcher';

interface AppShellProps {
  principal: Principal;
  logout(): Promise<void>;
  changePassword: AuthContextValue['changePassword'];
  children: ReactNode;
  onRefresh?: () => void;
  runtimeSettings?: RuntimeSettingsController;
  auditStatus?: AuditStatusController;
  protection?: SystemProtectionController;
}

const navigation = [
  { labelKey: 'nav.dashboard', path: '/dashboard', icon: LayoutDashboard },
  { labelKey: 'nav.cameras', path: '/cameras', icon: Camera },
  { labelKey: 'nav.ai', path: '/ai', icon: ScanSearch },
  { labelKey: 'nav.system', path: '/system', icon: Settings },
  { labelKey: 'nav.users', path: '/users', icon: UsersRound },
] as const;

function RuntimeSettingsNotice({
  controller,
}: {
  controller?: RuntimeSettingsController;
}) {
  const { t } = useTranslation();
  const snapshot = controller?.snapshot;
  if (snapshot === null || snapshot === undefined) {
    return null;
  }

  let role: 'alert' | 'status' = 'status';
  let message: string | null = null;
  if (snapshot.last_apply.status === 'failed') {
    role = 'alert';
    message = snapshot.last_apply.restored
      ? t('status.applyFailedRestored')
      : t('status.applyFailedRecoveryRequired');
  } else if (snapshot.state === 'recovery_required') {
    message = t('status.recoveryRequired');
  } else if (snapshot.state === 'applying' || controller?.status === 'applying') {
    message = t('status.applying');
  } else if (snapshot.pending !== null) {
    message = t('status.pending');
  }

  if (message === null) {
    return null;
  }

  const pendingCameraChanged = snapshot.pending !== null &&
    (snapshot.pending.camera.profile_id !== snapshot.active.camera.profile_id ||
     snapshot.pending.camera.bitrate_kbps !== snapshot.active.camera.bitrate_kbps ||
     snapshot.pending.camera.gop !== snapshot.active.camera.gop);
  const pendingModelChanged = snapshot.pending !== null &&
    snapshot.pending.models.some((model, index) => {
      const active = snapshot.active.models[index];
      return active === undefined || model.id !== active.id ||
        model.enabled !== active.enabled ||
        model.confidence_threshold !== active.confidence_threshold;
    });
  const settingsPath = pendingCameraChanged || !pendingModelChanged
    ? '/cameras'
    : '/ai';
  const linkLabel = settingsPath === '/cameras'
    ? t('status.reviewCameraSettings')
    : t('status.reviewAiSettings');

  return (
    <div className={`settings-shell-notice settings-shell-${role}`} role={role}>
      <span>{message}</span>
      <a href={`#${settingsPath}`}>{linkLabel}</a>
    </div>
  );
}

function NavigationLinks({ pathname, onSelect }: {
  pathname: string;
  onSelect?: () => void;
}) {
  const { t } = useTranslation();
  return (
    <ul className="nav-list">
      {navigation.map(({ labelKey, path, icon: Icon }) => (
        <li key={path}>
          <a
            className={pathname === path ? 'nav-link active' : 'nav-link'}
            href={`#${path}`}
            aria-current={pathname === path ? 'page' : undefined}
            onClick={onSelect}
          >
            <Icon size={19} aria-hidden="true" />
            <span>{t(labelKey)}</span>
          </a>
        </li>
      ))}
    </ul>
  );
}

export function AppShell({
  principal,
  logout,
  changePassword,
  children,
  onRefresh = () => undefined,
  runtimeSettings,
  auditStatus,
  protection,
}: AppShellProps) {
  const { t } = useTranslation();
  const { pathname } = useLocation();
  const protectionState = protection?.snapshot?.state;
  const deviceState = protectionState === 'restricted'
    ? t('status.deviceRestricted')
    : protectionState === 'checking' ? t('status.deviceChecking') : t('status.deviceOperational');
  const deviceStateClass = protectionState === 'restricted'
    ? 'device-state device-state-restricted'
    : protectionState === 'checking'
      ? 'device-state device-state-checking'
      : 'device-state';
  const [drawerOpen, setDrawerOpen] = useState(false);
  const menuButtonRef = useRef<HTMLButtonElement>(null);
  const closeButtonRef = useRef<HTMLButtonElement>(null);
  const drawerWasOpen = useRef(false);

  useEffect(() => {
    if (drawerOpen) {
      drawerWasOpen.current = true;
      closeButtonRef.current?.focus();
      document.body.classList.add('drawer-active');
      return () => document.body.classList.remove('drawer-active');
    }
    if (drawerWasOpen.current) {
      drawerWasOpen.current = false;
      menuButtonRef.current?.focus();
    }
  }, [drawerOpen]);

  useEffect(() => {
    if (!drawerOpen) {
      return;
    }
    const handleEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setDrawerOpen(false);
      }
    };
    document.addEventListener('keydown', handleEscape);
    return () => document.removeEventListener('keydown', handleEscape);
  }, [drawerOpen]);

  const trapDrawerFocus = (event: ReactKeyboardEvent<HTMLElement>) => {
    if (event.key !== 'Tab') {
      return;
    }
    const focusable = Array.from(
      event.currentTarget.querySelectorAll<HTMLElement>('button, a[href]'),
    );
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last?.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first?.focus();
    }
  };

  return (
    <div className="app-layout">
      <aside className="sidebar">
        <div className="sidebar-brand"><span>{t('common.brandShort')}</span> {t('common.brand')}</div>
        <nav aria-label={t('nav.primaryLabel')}>
          <NavigationLinks pathname={pathname} />
        </nav>
      </aside>

      <header className="topbar">
        <div className="topbar-leading">
          <IconButton
            ref={menuButtonRef}
            className="mobile-menu-button"
            label={t('nav.openNavigation')}
            aria-expanded={drawerOpen}
            onClick={() => setDrawerOpen(true)}
          >
            <Menu size={20} aria-hidden="true" />
          </IconButton>
          <span className={deviceStateClass}>
            <span aria-hidden="true" />{deviceState}
          </span>
        </div>
        <div className="topbar-actions">
          <IconButton label={t('status.refreshDeviceState')} onClick={onRefresh}>
            <RefreshCw size={18} aria-hidden="true" />
          </IconButton>
          <LanguageSwitcher />
          <AccountMenu principal={principal} logout={logout} changePassword={changePassword} />
        </div>
      </header>

      <main className="shell-content">
        <ProtectionNotice controller={protection} />
        <AuditCapacityNotice controller={auditStatus} />
        <RuntimeSettingsNotice controller={runtimeSettings} />
        {children}
      </main>

      {drawerOpen && (
        <div className="drawer-layer">
          <button
            type="button"
            className="drawer-backdrop"
            aria-label={t('nav.dismissNavigation')}
            tabIndex={-1}
            onClick={() => setDrawerOpen(false)}
          />
          <aside
            className="mobile-drawer"
            role="dialog"
            aria-modal="true"
            aria-label={t('nav.navigationLabel')}
            onKeyDown={trapDrawerFocus}
          >
            <div className="drawer-header">
              <span>{t('common.brand')}</span>
              <IconButton
                ref={closeButtonRef}
                label={t('nav.closeNavigation')}
                onClick={() => setDrawerOpen(false)}
              >
                <X size={20} aria-hidden="true" />
              </IconButton>
            </div>
            <nav aria-label={t('nav.drawerLabel')}>
              <NavigationLinks
                pathname={pathname}
                onSelect={() => setDrawerOpen(false)}
              />
            </nav>
          </aside>
        </div>
      )}
    </div>
  );
}
