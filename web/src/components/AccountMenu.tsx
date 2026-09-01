import { LogOut, UserRound } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';

import type { Principal } from '../api/types';
import type { AuthContextValue } from '../auth/AuthContext';
import { ChangePasswordDialog } from '../features/users/ChangePasswordDialog';
import { useTranslation } from '../i18n/LanguageContext';
import { IconButton } from './IconButton';

export interface AccountMenuProps {
  principal: Principal;
  logout(): Promise<void>;
  changePassword: AuthContextValue['changePassword'];
}

export function AccountMenu({ principal, logout, changePassword }: AccountMenuProps) {
  const { t } = useTranslation();
  const [menuOpen, setMenuOpen] = useState(false);
  const [changePasswordOpen, setChangePasswordOpen] = useState(false);
  const userMenuButtonRef = useRef<HTMLButtonElement>(null);
  const changePasswordButtonRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!menuOpen || changePasswordOpen) {
      return;
    }
    const handleEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setMenuOpen(false);
        userMenuButtonRef.current?.focus();
      }
    };
    document.addEventListener('keydown', handleEscape);
    return () => document.removeEventListener('keydown', handleEscape);
  }, [changePasswordOpen, menuOpen]);

  return (
    <>
      <span className="header-username">{principal.username}</span>
      <div className="user-menu-wrap">
        <IconButton
          ref={userMenuButtonRef}
          label={t('account.openMenu')}
          aria-expanded={menuOpen}
          aria-controls="user-disclosure"
          onClick={() => setMenuOpen((open) => !open)}
        >
          <UserRound size={19} aria-hidden="true" />
        </IconButton>
        {menuOpen && (
          <div className="user-menu" id="user-disclosure">
            <span className="user-role">{principal.role}</span>
            <button ref={changePasswordButtonRef} className="user-menu-change-password"
              type="button" onClick={() => setChangePasswordOpen(true)}>
              {t('account.changePassword')}
            </button>
            <button className="user-menu-sign-out"
              type="button"
              onClick={() => {
                setMenuOpen(false);
                void logout();
              }}
            >
              <LogOut size={17} aria-hidden="true" />
              {t('account.signOut')}
            </button>
          </div>
        )}
      </div>
      <ChangePasswordDialog
        open={changePasswordOpen}
        returnFocusRef={changePasswordButtonRef}
        changePassword={changePassword}
        onClose={() => setChangePasswordOpen(false)}
      />
    </>
  );
}
