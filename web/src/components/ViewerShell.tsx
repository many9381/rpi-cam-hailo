import { Camera, Menu, X } from 'lucide-react';
import {
  type KeyboardEvent as ReactKeyboardEvent,
  type ReactNode,
  useEffect,
  useRef,
  useState,
} from 'react';
import { useLocation } from 'react-router-dom';

import { AccountMenu, type AccountMenuProps } from './AccountMenu';
import { IconButton } from './IconButton';

export interface ViewerShellProps extends AccountMenuProps {
  children: ReactNode;
}

const viewerNavigation = [
  { label: 'Live', path: '/monitor', icon: Camera },
] as const;

function NavigationLinks({ pathname, onSelect }: {
  pathname: string;
  onSelect?: () => void;
}) {
  return (
    <ul className="nav-list">
      {viewerNavigation.map(({ label, path, icon: Icon }) => (
        <li key={path}>
          <a className={pathname === path ? 'nav-link active' : 'nav-link'} href={`#${path}`}
            aria-current={pathname === path ? 'page' : undefined} onClick={onSelect}>
            <Icon size={19} aria-hidden="true" />
            <span>{label}</span>
          </a>
        </li>
      ))}
    </ul>
  );
}

export function ViewerShell({ principal, logout, changePassword, children }: ViewerShellProps) {
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
        <div className="sidebar-brand"><span>CF</span> Camera Firmware</div>
        <nav aria-label="Primary navigation"><NavigationLinks pathname={pathname} /></nav>
      </aside>

      <header className="topbar">
        <div className="topbar-leading">
          <IconButton ref={menuButtonRef} className="mobile-menu-button" label="Open navigation"
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
          <button type="button" className="drawer-backdrop" aria-label="Dismiss navigation"
            tabIndex={-1} onClick={() => setDrawerOpen(false)} />
          <aside className="mobile-drawer" role="dialog" aria-modal="true" aria-label="Navigation"
            onKeyDown={trapDrawerFocus}>
            <div className="drawer-header">
              <span>Camera Firmware</span>
              <IconButton ref={closeButtonRef} label="Close navigation"
                onClick={() => setDrawerOpen(false)}>
                <X size={20} aria-hidden="true" />
              </IconButton>
            </div>
            <nav aria-label="Drawer navigation">
              <NavigationLinks pathname={pathname} onSelect={() => setDrawerOpen(false)} />
            </nav>
          </aside>
        </div>
      )}
    </div>
  );
}
