import '@testing-library/jest-dom/vitest';

import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { LanguageProvider } from '../../i18n';
import type { ProtectionSnapshot } from './contracts';
import { ProtectionNotice } from './ProtectionNotice';
import type { SystemProtectionController } from './useSystemProtection';

const snapshot = (state: ProtectionSnapshot['state']): ProtectionSnapshot => ({
  state,
  check_running: state === 'checking',
  next_periodic_at_seconds: 1_784_586_400,
  self_test: null,
  integrity: null,
});

const controller = (
  state: ProtectionSnapshot['state'],
): SystemProtectionController => ({
  state: 'ready',
  snapshot: snapshot(state),
  publicMessage: null,
  activeCommand: null,
  refresh: vi.fn(async () => undefined),
  runSelfTest: vi.fn(async () => undefined),
  runIntegrityCheck: vi.fn(async () => undefined),
});

afterEach(cleanup);

describe('ProtectionNotice', () => {
  it('links the full-width restricted notice to the System page', () => {
    render(<ProtectionNotice controller={controller('restricted')} />, {
      wrapper: LanguageProvider,
    });

    const notice = screen.getByRole('alert');
    expect(notice).toHaveClass('protection-shell-notice');
    expect(notice).toHaveTextContent('System protection is restricted.');
    expect(screen.getByRole('link', { name: 'Review system protection' }))
      .toHaveAttribute('href', '#/system');
  });

  it.each(['operational', 'checking'] as const)(
    'does not show a restricted notice while %s',
    (state) => {
      render(<ProtectionNotice controller={controller(state)} />, {
        wrapper: LanguageProvider,
      });
      expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    },
  );

  it('does not invent a restriction when status is unavailable', () => {
    render(<ProtectionNotice controller={{
      ...controller('operational'),
      state: 'unavailable',
      snapshot: null,
    }} />, { wrapper: LanguageProvider });
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });
});
