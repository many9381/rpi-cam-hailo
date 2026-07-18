import { type KeyboardEvent, useState } from 'react';

import { AccessIpsTab } from '../features/users/AccessIpsTab';
import { AccountsTab } from '../features/users/AccountsTab';
import type { UserManagementController } from '../features/users/useUserManagement';

interface UsersPageProps {
  controller: UserManagementController;
}

type ActiveTab = 'accounts' | 'access_ips';

const tabs: ReadonlyArray<{
  key: ActiveTab;
  label: string;
  tabId: string;
  panelId: string;
}> = [
  {
    key: 'accounts',
    label: 'Accounts',
    tabId: 'users-accounts-tab',
    panelId: 'users-accounts-panel',
  },
  {
    key: 'access_ips',
    label: 'Access IPs',
    tabId: 'users-access-ips-tab',
    panelId: 'users-access-ips-panel',
  },
];

export function UsersPage({ controller }: UsersPageProps) {
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
        <h1>Users &amp; access</h1>
        {activeTab === 'accounts' ? (
          <button
            className="users-create-button"
            type="button"
            disabled={mutationPending}
            onClick={() => setCreateDialog('viewer')}
          >
            Add viewer
          </button>
        ) : (
          <button
            className="users-create-button"
            type="button"
            disabled={mutationPending}
            onClick={() => setCreateDialog('management_ip')}
          >
            Add access IP
          </button>
        )}
      </header>

      <div className="users-tabs" role="tablist" aria-label="Users and access">
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
            {tab.label}
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
          <AccessIpsTab
            controller={controller}
            createOpen={createDialog === 'management_ip'}
            onCreateClose={() => setCreateDialog(null)}
          />
        )}
      </section>
    </div>
  );
}
