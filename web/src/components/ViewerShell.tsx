import { Camera, Menu, X } from 'lucide-react';
import {
  type KeyboardEvent as ReactKeyboardEvent,
  type ReactNode,
  useEffect,
  useRef,
  useState,
} from 'react';
import { useLocation } from 'react-router-dom';

import { useTranslation } from '../i18n/LanguageContext';
import { AccountMenu, type AccountMenuProps } from './AccountMenu';
import { IconButton } from './IconButton';

export interface ViewerShellProps extends AccountMenuProps {
  children: ReactNode;
}

const viewerNavigation = [
  { labelKey: 'nav.live', path: '/monitor', icon: Camera },
] as const;

function NavigationLinks({ pathname, onSelect }: {
  pathname: string;
  onSelect?: () => void;
}) {
  const { t } = useTranslation();
  return (
    <ul className="nav-list">
      {viewerNavigation.map(({ labelKey, path, icon: Icon }) => (
        <li key={path}>
          <a className={pathname === path ? 'nav-link active' : 'nav-link'} href={`#${path}`}
            aria-current={pathname === path ? 'page' : undefined} onClick={onSelect}>
            <Icon size={19} aria-hidden="true" />
            <span>{t(labelKey)}</span>
          </a>
        </li>
      ))}
    </ul>
  );
}

export function ViewerShell({ principal, logout, changePassword, children }: ViewerShellProps) {
  const { t } = useTranslation();
  const { pathname } = useLocation();
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
        <nav aria-label={t('nav.primaryLabel')}><NavigationLinks pathname={pathname} /></nav>
      </aside>

      <header className="topbar">
        <div className="topbar-leading">
          <IconButton ref={menuButtonRef} className="mobile-menu-button" label={t('nav.openNavigation')}
            aria-expanded={drawerOpen} onClick={() => setDrawerOpen(true)}>
            <Menu size={20} aria-hidden="true" />
          </IconButton>
        </div>
        <div className="topbar-actions">
          <AccountMenu principal={principal} logout={logout} changePassword={changePassword} />
        </div>
      </header>

      <main className="shell-content">{children}</main>

      {drawerOpen && (
        <div className="drawer-layer">
          <button type="button" className="drawer-backdrop" aria-label={t('nav.dismissNavigation')}
            tabIndex={-1} onClick={() => setDrawerOpen(false)} />
          <aside className="mobile-drawer" role="dialog" aria-modal="true" aria-label={t('nav.navigationLabel')}
            onKeyDown={trapDrawerFocus}>
            <div className="drawer-header">
              <span>{t('common.brand')}</span>
              <IconButton ref={closeButtonRef} label={t('nav.closeNavigation')}
                onClick={() => setDrawerOpen(false)}>
                <X size={20} aria-hidden="true" />
              </IconButton>
            </div>
            <nav aria-label={t('nav.drawerLabel')}>
              <NavigationLinks pathname={pathname} onSelect={() => setDrawerOpen(false)} />
            </nav>
          </aside>
        </div>
      )}
    </div>
  );
}
