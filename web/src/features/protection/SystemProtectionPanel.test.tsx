import '@testing-library/jest-dom/vitest';

// @ts-expect-error Vitest provides Node built-ins outside the browser bundle.
import { readFileSync } from 'node:fs';
import { cleanup, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { ProtectionSnapshot } from './contracts';
import { SystemProtectionPanel } from './SystemProtectionPanel';
import type { SystemProtectionController } from './useSystemProtection';

const styles = readFileSync('src/styles.css', 'utf8');

const suite = (
  name: 'self_test' | 'integrity',
  passed = true,
): NonNullable<ProtectionSnapshot['self_test']> => ({
  suite: name,
  trigger: 'startup',
  passed,
  started_at_seconds: 1_784_500_000,
  finished_at_seconds: 1_784_500_002,
  items: [{
    id: name === 'self_test' ? 'crypto.sha256' : 'camera-firmware',
    category: name === 'self_test' ? null : 'firmware',
    passed,
    code: passed ? 'OK' : 'E_INTEGRITY_MISMATCH',
  }],
});

const snapshot = (
  overrides: Partial<ProtectionSnapshot> = {},
): ProtectionSnapshot => ({
  state: 'operational',
  check_running: false,
  next_periodic_at_seconds: 1_784_586_400,
  self_test: suite('self_test'),
  integrity: suite('integrity'),
  ...overrides,
});

const controller = (
  overrides: Partial<SystemProtectionController> = {},
): SystemProtectionController => ({
  state: 'ready',
  snapshot: snapshot(),
  publicMessage: null,
  activeCommand: null,
  refresh: vi.fn(async () => undefined),
  runSelfTest: vi.fn(async () => undefined),
  runIntegrityCheck: vi.fn(async () => undefined),
  ...overrides,
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe('SystemProtectionPanel', () => {
  it('renders an unframed operational summary with accessible icon commands', () => {
    const view = render(<SystemProtectionPanel controller={controller()} />);

    const section = screen.getByRole('region', { name: 'System protection' });
    expect(within(section).getByText('Operational')).toBeVisible();
    expect(within(section).getByText('Security self-test')).toBeVisible();
    expect(within(section).getByText('Integrity check')).toBeVisible();
    expect(section).toHaveClass('operational-section');
    expect(section).not.toHaveClass('data-card');
    expect(section.querySelector('.data-card')).toBeNull();

    for (const name of [
      'Refresh system protection',
      'Run security self-test',
      'Run integrity check',
    ]) {
      expect(within(section).getByRole('button', { name }))
        .toHaveAttribute('title', name);
    }
  });

  it('runs both administrator commands from the keyboard', async () => {
    const user = userEvent.setup();
    const value = controller();
    render(<SystemProtectionPanel controller={value} />);

    const selfTest = screen.getByRole('button', { name: 'Run security self-test' });
    selfTest.focus();
    await user.keyboard('{Enter}');
    const integrity = screen.getByRole('button', { name: 'Run integrity check' });
    integrity.focus();
    await user.keyboard(' ');

    expect(value.runSelfTest).toHaveBeenCalledOnce();
    expect(value.runIntegrityCheck).toHaveBeenCalledOnce();
  });

  it('shows checking progress and disables every command while a suite runs', () => {
    render(<SystemProtectionPanel controller={controller({
      snapshot: snapshot({ state: 'checking', check_running: true }),
      activeCommand: 'integrity',
    })} />);

    expect(screen.getByText('Checking')).toBeVisible();
    for (const name of ['Refresh system protection', 'Run security self-test']) {
      expect(screen.getByRole('button', { name })).toBeDisabled();
    }
    const running = screen.getByRole('button', { name: 'Integrity check running' });
    expect(running).toBeDisabled();
    expect(running).toHaveAttribute('aria-busy', 'true');
    expect(running).toHaveTextContent('Integrity check running');
  });

  it('disables commands while a request is active over a retained snapshot', () => {
    render(<SystemProtectionPanel controller={controller({ state: 'loading' })} />);

    for (const name of [
      'Refresh system protection',
      'Run security self-test',
      'Run integrity check',
    ]) {
      expect(screen.getByRole('button', { name })).toBeDisabled();
    }
  });

  it('keeps a restricted snapshot visible with failed item codes', () => {
    render(<SystemProtectionPanel controller={controller({
      state: 'stale',
      snapshot: snapshot({
        state: 'restricted',
        integrity: suite('integrity', false),
      }),
      publicMessage: 'Showing the last verified protection result.',
    })} />);

    expect(screen.getByText('Restricted')).toBeVisible();
    expect(screen.getByText('E_INTEGRITY_MISMATCH')).toBeVisible();
    expect(screen.getByText('Showing the last verified protection result.'))
      .toHaveAttribute('role', 'status');
  });

  it('renders unavailable feedback and exposes a retry command', async () => {
    const user = userEvent.setup();
    const value = controller({
      state: 'unavailable',
      snapshot: null,
      publicMessage: 'System protection is temporarily unavailable.',
    });
    render(<SystemProtectionPanel controller={value} />);

    expect(screen.getByRole('alert')).toHaveTextContent(
      'System protection is temporarily unavailable.',
    );
    await user.click(screen.getByRole('button', { name: 'Retry system protection' }));
    expect(value.refresh).toHaveBeenCalledOnce();
    expect(screen.queryByRole('button', { name: 'Run security self-test' }))
      .not.toBeInTheDocument();
  });

  it('wraps a maximum-length public code without changing control dimensions', () => {
    const longCode = `E_${'X'.repeat(62)}`;
    const integrity = suite('integrity', false);
    integrity.items[0] = { ...integrity.items[0], code: longCode };
    render(<SystemProtectionPanel controller={controller({
      snapshot: snapshot({ state: 'restricted', integrity }),
    })} />);

    expect(screen.getByText(longCode)).toHaveClass('protection-item-code');
    expect(styles).toMatch(/\.protection-item-code\s*\{[^}]*overflow-wrap:\s*anywhere/s);
    expect(styles).toMatch(/\.protection-command-button\s*\{[^}]*min-height:\s*36px/s);
  });
});
