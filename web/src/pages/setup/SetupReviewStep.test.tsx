import '@testing-library/jest-dom/vitest';

import { cleanup, render as rtlRender, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { ReactElement } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { LanguageProvider } from '../../i18n';
import { SetupReviewStep } from './SetupReviewStep';

// SetupReviewStep now calls useTranslation(), so every render needs a
// LanguageProvider ancestor - centralized here the same way App.test.tsx
// does it, instead of wrapping each call site individually.
function render(ui: ReactElement) {
  return rtlRender(<LanguageProvider>{ui}</LanguageProvider>);
}

afterEach(cleanup);

describe('SetupReviewStep', () => {
  it('shows the collected values with the password masked', () => {
    render(
      <SetupReviewStep
        username="operator.one"
        password="NorthStar!9"
        peerIp="192.0.2.44"
        hosts={['198.51.100.20']}
        submitting={false}
        onBack={vi.fn()}
        onSubmit={vi.fn()}
      />,
    );

    expect(screen.getByText('operator.one')).toBeVisible();
    expect(screen.getByText('192.0.2.44', { exact: false })).toBeVisible();
    expect(screen.getByText('198.51.100.20')).toBeVisible();
    expect(screen.queryByText('NorthStar!9')).not.toBeInTheDocument();
  });

  it('calls onBack and onSubmit from their respective controls', async () => {
    const user = userEvent.setup();
    const onBack = vi.fn();
    const onSubmit = vi.fn();
    render(
      <SetupReviewStep
        username="operator.one"
        password="NorthStar!9"
        peerIp="192.0.2.44"
        hosts={[]}
        submitting={false}
        onBack={onBack}
        onSubmit={onSubmit}
      />,
    );

    await user.click(screen.getByRole('button', { name: /^back$/i }));
    expect(onBack).toHaveBeenCalledTimes(1);

    await user.click(screen.getByRole('button', { name: /complete setup/i }));
    expect(onSubmit).toHaveBeenCalledTimes(1);
  });

  it('disables the controls while submitting', () => {
    render(
      <SetupReviewStep
        username="operator.one"
        password="NorthStar!9"
        peerIp="192.0.2.44"
        hosts={[]}
        submitting
        onBack={vi.fn()}
        onSubmit={vi.fn()}
      />,
    );

    expect(screen.getByRole('button', { name: /^back$/i })).toBeDisabled();
    expect(screen.getByRole('button', { name: /completing setup/i })).toBeDisabled();
  });
});
