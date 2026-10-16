import { type KeyboardEvent, type ReactNode, useState } from 'react';

import { AccessIpsTab } from '../features/users/AccessIpsTab';
import { AccountsTab } from '../features/users/AccountsTab';
import type { UserManagementController } from '../features/users/useUserManagement';
import { useTranslation } from '../i18n/LanguageContext';

interface UsersPageProps {
  controller: UserManagementController;
  managementIpPolicy?: ReactNode;
}

type ActiveTab = 'accounts' | 'access_ips';

const tabs: ReadonlyArray<{
  key: ActiveTab;
  labelKey: string;
  tabId: string;
  panelId: string;
}> = [
  {
    key: 'accounts',
    labelKey: 'users.tabAccounts',
    tabId: 'users-accounts-tab',
    panelId: 'users-accounts-panel',
  },
  {
    key: 'access_ips',
    labelKey: 'users.tabAccessIps',
    tabId: 'users-access-ips-tab',
    panelId: 'users-access-ips-panel',
  },
];

export function UsersPage({ controller, managementIpPolicy }: UsersPageProps) {
  const { t } = useTranslation();
  const [activeTab, setActiveTab] = useState<ActiveTab>('accounts');
  const [createDialog, setCreateDialog] =
    useState<'viewer' | 'management_ip' | null>(null);

  const selectTab = (nextTab: ActiveTab, moveFocus: boolean) => {
    setActiveTab(nextTab);
    setCreateDialog(null);
    if (moveFocus) {
      const target = tabs.find((tab) => tab.key === nextTab);
      document.getElementById(target?.tabId ?? '')?.focus();
    }
  };

  const handleTabKeyDown = (
    event: KeyboardEvent<HTMLButtonElement>,
    currentTab: ActiveTab,
  ) => {
    const currentIndex = tabs.findIndex((tab) => tab.key === currentTab);
    let nextIndex: number | null = null;
    switch (event.key) {
      case 'ArrowLeft':
        nextIndex = (currentIndex - 1 + tabs.length) % tabs.length;
        break;
      case 'ArrowRight':
        nextIndex = (currentIndex + 1) % tabs.length;
        break;
      case 'Home':
        nextIndex = 0;
        break;
      case 'End':
        nextIndex = tabs.length - 1;
        break;
      default:
        return;
    }
    event.preventDefault();
    selectTab(tabs[nextIndex].key, true);
  };

  const activeDefinition = tabs.find((tab) => tab.key === activeTab)!;
  const mutationPending = controller.mutation !== null;

  return (
    <div className="users-page">
      <header className="users-heading">
        <h1>{t('users.pageTitle')}</h1>
        {activeTab === 'accounts' ? (
          <button
            className="users-create-button"
            type="button"
            disabled={mutationPending}
            onClick={() => setCreateDialog('viewer')}
          >
            {t('users.addViewer')}
          </button>
        ) : (
          <button
            className="users-create-button"
            type="button"
            disabled={mutationPending}
            onClick={() => setCreateDialog('management_ip')}
          >
            {t('users.addAccessIp')}
          </button>
        )}
      </header>

      <div className="users-tabs" role="tablist" aria-label={t('users.tabListLabel')}>
        {tabs.map((tab) => (
          <button
            key={tab.key}
            id={tab.tabId}
            type="button"
            role="tab"
            aria-controls={tab.panelId}
            aria-selected={activeTab === tab.key}
            tabIndex={activeTab === tab.key ? 0 : -1}
            onClick={() => selectTab(tab.key, false)}
            onKeyDown={(event) => handleTabKeyDown(event, tab.key)}
          >
            {t(tab.labelKey)}
          </button>
        ))}
      </div>

      <section
        id={activeDefinition.panelId}
        role="tabpanel"
        aria-labelledby={activeDefinition.tabId}
      >
        {activeTab === 'accounts' ? (
          <AccountsTab
            controller={controller}
            createOpen={createDialog === 'viewer'}
            onCreateClose={() => setCreateDialog(null)}
          />
        ) : (
          <>
            {managementIpPolicy}
            <AccessIpsTab
              controller={controller}
              createOpen={createDialog === 'management_ip'}
              onCreateClose={() => setCreateDialog(null)}
            />
          </>
        )}
      </section>
    </div>
  );
}
