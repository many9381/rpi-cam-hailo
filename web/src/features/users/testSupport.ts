import { vi } from 'vitest';

import type { UserManagementController } from './useUserManagement';

export const makeUserManagementController = (
  overrides: Partial<UserManagementController> = {},
): UserManagementController => ({
  users: { status: 'ready', data: [], error: null },
  managementIps: {
    status: 'ready',
    data: { management_ips: [], current_peer_ip: '' },
    error: null,
  },
  mutation: null,
  refreshUsers: vi.fn(async () => undefined),
  refreshManagementIps: vi.fn(async () => undefined),
  refreshAll: vi.fn(async () => undefined),
  createViewer: vi.fn(async () => ({ refreshed: true })),
  setViewerEnabled: vi.fn(async () => ({ refreshed: true })),
  resetViewerPassword: vi.fn(async () => ({ refreshed: true })),
  deleteViewer: vi.fn(async () => ({ refreshed: true })),
  createManagementIp: vi.fn(async () => ({ refreshed: true })),
  updateManagementIp: vi.fn(async () => ({ refreshed: true })),
  deleteManagementIp: vi.fn(async () => ({ refreshed: true })),
  ...overrides,
});
