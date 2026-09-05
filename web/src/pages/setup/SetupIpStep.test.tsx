import '@testing-library/jest-dom/vitest';

import { cleanup, render as rtlRender, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { ReactElement } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { LanguageProvider } from '../../i18n';
import { SetupIpStep } from './SetupIpStep';

// SetupIpStep now calls useTranslation(), so every render needs a
// LanguageProvider ancestor - centralized here the same way App.test.tsx
// does it, instead of wrapping each call site individually.
function render(ui: ReactElement) {
  return rtlRender(<LanguageProvider>{ui}</LanguageProvider>);
}

afterEach(cleanup);

describe('SetupIpStep', () => {
  it('lists the current peer as already registered', () => {
    render(
      <SetupIpStep peerIp="192.0.2.44" hosts={[]} onAddHost={vi.fn()}
        onBack={vi.fn()} onNext={vi.fn()} />,
    );

    const registered = screen.getByRole('list', { name: /registered management hosts/i });
    expect(registered).toHaveTextContent('192.0.2.44 (current session)');
  });

  it.each([
    ['192.168.10.2~253', 'range'],
    ['192.168.10.*', 'wildcard'],
    ['192.168.10.0/24', 'CIDR'],
    ['0.0.0.0', 'unspecified address'],
    ['any', 'the literal any'],
    ['ANY', 'the literal any, case-insensitive'],
    ['::', 'IPv6 unspecified address, compressed'],
    ['0000:0000:0000:0000:0000:0000:0000:0000', 'IPv6 unspecified address, fully expanded'],
    ['0:0:0:0:0:0:0:0', 'IPv6 unspecified address, uncompressed shorthand'],
  ])('rejects %s (%s) with a visible reason', async (value) => {
    const user = userEvent.setup();
    const onAddHost = vi.fn();
    render(
      <SetupIpStep peerIp="192.0.2.44" hosts={[]} onAddHost={onAddHost}
        onBack={vi.fn()} onNext={vi.fn()} />,
    );

    await user.type(screen.getByLabelText(/add a management address/i), value);
    await user.click(screen.getByRole('button', { name: /add host/i }));

    expect(screen.getByText(/only single hosts may be registered/i)).toBeVisible();
    expect(onAddHost).not.toHaveBeenCalled();
  });

  it('accepts a second single host and lists both alongside the current peer', async () => {
    const user = userEvent.setup();
    const onAddHost = vi.fn();
    const { rerender } = render(
      <SetupIpStep peerIp="192.0.2.44" hosts={[]} onAddHost={onAddHost}
        onBack={vi.fn()} onNext={vi.fn()} />,
    );

    await user.type(screen.getByLabelText(/add a management address/i), '198.51.100.20');
    await user.click(screen.getByRole('button', { name: /add host/i }));
    expect(onAddHost).toHaveBeenCalledWith('198.51.100.20');

    rerender(
      <LanguageProvider>
        <SetupIpStep peerIp="192.0.2.44" hosts={['198.51.100.20']} onAddHost={onAddHost}
          onBack={vi.fn()} onNext={vi.fn()} />
      </LanguageProvider>,
    );
    await user.type(screen.getByLabelText(/add a management address/i), '203.0.113.7');
    await user.click(screen.getByRole('button', { name: /add host/i }));
    expect(onAddHost).toHaveBeenCalledWith('203.0.113.7');

    rerender(
      <LanguageProvider>
        <SetupIpStep peerIp="192.0.2.44" hosts={['198.51.100.20', '203.0.113.7']}
          onAddHost={onAddHost} onBack={vi.fn()} onNext={vi.fn()} />
      </LanguageProvider>,
    );
    expect(screen.getByText('198.51.100.20')).toBeVisible();
    expect(screen.getByText('203.0.113.7')).toBeVisible();
  });

  it('accepts a single IPv6 host', async () => {
    const user = userEvent.setup();
    const onAddHost = vi.fn();
    render(
      <SetupIpStep peerIp="192.0.2.44" hosts={[]} onAddHost={onAddHost}
        onBack={vi.fn()} onNext={vi.fn()} />,
    );

    await user.type(screen.getByLabelText(/add a management address/i), '2001:db8::10');
    await user.click(screen.getByRole('button', { name: /add host/i }));

    expect(onAddHost).toHaveBeenCalledWith('2001:db8::10');
  });

  it('rejects an address that is not a valid IPv4 or IPv6 literal', async () => {
    const user = userEvent.setup();
    const onAddHost = vi.fn();
    render(
      <SetupIpStep peerIp="192.0.2.44" hosts={[]} onAddHost={onAddHost}
        onBack={vi.fn()} onNext={vi.fn()} />,
    );

    await user.type(screen.getByLabelText(/add a management address/i), 'not-an-address');
    await user.click(screen.getByRole('button', { name: /add host/i }));

    expect(screen.getByText(/valid ipv4 or ipv6/i)).toBeVisible();
    expect(onAddHost).not.toHaveBeenCalled();
  });

  it('stops the operator at 31 additional hosts (32 total including the current peer)', async () => {
    const user = userEvent.setup();
    const onAddHost = vi.fn();
    const hosts = Array.from({ length: 31 }, (_, index) => `198.51.100.${index}`);
    render(
      <SetupIpStep peerIp="192.0.2.44" hosts={hosts} onAddHost={onAddHost}
        onBack={vi.fn()} onNext={vi.fn()} />,
    );

    expect(screen.getByLabelText(/add a management address/i)).toBeDisabled();
    expect(screen.getByRole('button', { name: /add host/i })).toBeDisabled();
    expect(screen.getByText(/up to 31 additional hosts may be registered/i)).toBeVisible();
  });

  it('calls onBack and onNext from their respective controls', async () => {
    const user = userEvent.setup();
    const onBack = vi.fn();
    const onNext = vi.fn();
    render(
      <SetupIpStep peerIp="192.0.2.44" hosts={[]} onAddHost={vi.fn()}
        onBack={onBack} onNext={onNext} />,
    );

    await user.click(screen.getByRole('button', { name: /^back$/i }));
    expect(onBack).toHaveBeenCalledTimes(1);

    await user.click(screen.getByRole('button', { name: /^next$/i }));
    expect(onNext).toHaveBeenCalledTimes(1);
  });
});
