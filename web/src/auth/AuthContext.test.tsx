import { cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { UnauthorizedError } from '../api/client';
import type { CameraApiClient, Principal } from '../api/types';
import { AuthProvider, useAuth } from './AuthContext';

const makeClient = (): CameraApiClient => ({
  getJson: vi.fn(),
  postJson: vi.fn(),
  getBlob: vi.fn(),
  setUnauthorizedHandler: vi.fn(),
});

function Probe() {
  const auth = useAuth();
  return (
    <div>
      <output>{auth.state}</output>
      <span>{auth.principal?.username}</span>
      <button type="button" onClick={() => void auth.login('form-user', 'SecretPass9!')}>
        Login
      </button>
      <button type="button" onClick={() => void auth.logout()}>
        Logout
      </button>
    </div>
  );
}

afterEach(cleanup);

describe('AuthProvider', () => {
  it('recovers an authenticated principal from /auth/me', async () => {
    const client = makeClient();
    vi.mocked(client.getJson).mockResolvedValue({
      username: 'operator.one',
      role: 'administrator',
    });

    render(<AuthProvider client={client}><Probe /></AuthProvider>);

    expect(screen.getByText('checking')).toBeVisible();
    expect(await screen.findByText('operator.one')).toBeVisible();
    expect(screen.getByText('authenticated')).toBeVisible();
    expect(client.getJson).toHaveBeenCalledWith(
      '/api/v1/auth/me',
      expect.any(Function),
      expect.any(AbortSignal),
    );
  });

  it('treats an expected recovery 401 as anonymous without leaking details', async () => {
    const client = makeClient();
    vi.mocked(client.getJson).mockRejectedValue(
      new UnauthorizedError('private-session-detail'),
    );

    render(<AuthProvider client={client}><Probe /></AuthProvider>);

    expect(await screen.findByText('anonymous')).toBeVisible();
    expect(screen.queryByText(/private-session-detail/i)).not.toBeInTheDocument();
  });

  it('logs in and then obtains the server-authoritative principal', async () => {
    const user = userEvent.setup();
    const client = makeClient();
    vi.mocked(client.getJson)
      .mockRejectedValueOnce(new UnauthorizedError())
      .mockResolvedValueOnce({ username: 'server-owner', role: 'administrator' });
    vi.mocked(client.postJson).mockResolvedValue({
      role: 'administrator',
      idle_expires_at_seconds: 100,
    });
    render(<AuthProvider client={client}><Probe /></AuthProvider>);
    await screen.findByText('anonymous');

    await user.click(screen.getByRole('button', { name: 'Login' }));

    expect(client.postJson).toHaveBeenCalledWith(
      '/api/v1/auth/login',
      { username: 'form-user', password: 'SecretPass9!' },
      expect.any(Function),
    );
    expect(await screen.findByText('server-owner')).toBeVisible();
    expect(screen.queryByText('form-user')).not.toBeInTheDocument();
    expect(client.getJson).toHaveBeenLastCalledWith(
      '/api/v1/auth/me',
      expect.any(Function),
    );
  });

  it('clears the principal when the global unauthorized handler runs', async () => {
    const client = makeClient();
    vi.mocked(client.getJson).mockResolvedValue({
      username: 'operator.one',
      role: 'administrator',
    });
    render(<AuthProvider client={client}><Probe /></AuthProvider>);
    await screen.findByText('operator.one');

    const handler = vi.mocked(client.setUnauthorizedHandler).mock.calls[0][0];
    handler?.();

    expect(await screen.findByText('anonymous')).toBeVisible();
    expect(screen.queryByText('operator.one')).not.toBeInTheDocument();
  });

  it.each([
    ['successful response', () => Promise.resolve({ logged_out: true })],
    ['network failure', () => Promise.reject(new Error('offline'))],
  ])('always clears local state after logout: %s', async (_case, makeResult) => {
    const user = userEvent.setup();
    const client = makeClient();
    vi.mocked(client.getJson).mockResolvedValue({
      username: 'operator.one',
      role: 'administrator',
    });
    vi.mocked(client.postJson).mockImplementation(() => makeResult());
    render(<AuthProvider client={client}><Probe /></AuthProvider>);
    await screen.findByText('operator.one');

    await user.click(screen.getByRole('button', { name: 'Logout' }));

    expect(await screen.findByText('anonymous')).toBeVisible();
    expect(client.postJson).toHaveBeenCalledWith(
      '/api/v1/auth/logout',
      {},
      expect.any(Function),
      expect.any(AbortSignal),
    );
  });

  it('aborts and settles an outstanding logout before starting a new login', async () => {
    const user = userEvent.setup();
    const client = makeClient();
    let logoutSignal: AbortSignal | undefined;
    const order: string[] = [];
    vi.mocked(client.getJson)
      .mockResolvedValueOnce({ username: 'operator.one', role: 'administrator' })
      .mockResolvedValueOnce({ username: 'server-owner', role: 'administrator' });
    vi.mocked(client.postJson).mockImplementation(
      async (path, _body, _parser, signal) => {
        if (path === '/api/v1/auth/logout') {
          logoutSignal = signal;
          return new Promise((_, reject) => signal?.addEventListener('abort', () => {
            order.push('logout-aborted');
            reject(new DOMException('Aborted', 'AbortError'));
          }, { once: true }));
        }
        order.push('login-started');
        return { role: 'administrator', idle_expires_at_seconds: 100 } as never;
      },
    );
    render(<AuthProvider client={client}><Probe /></AuthProvider>);
    await screen.findByText('operator.one');

    await user.click(screen.getByRole('button', { name: 'Logout' }));
    expect(await screen.findByText('anonymous')).toBeVisible();
    await user.click(screen.getByRole('button', { name: 'Login' }));

    expect(logoutSignal?.aborted).toBe(true);
    expect(order).toEqual(['logout-aborted', 'login-started']);
    expect(await screen.findByText('server-owner')).toBeVisible();
  });

  it('does not access web storage and unregisters its unauthorized handler', async () => {
    const client = makeClient();
    vi.mocked(client.getJson).mockRejectedValue(new UnauthorizedError());
    const local = vi.spyOn(Storage.prototype, 'getItem');
    const session = vi.spyOn(Storage.prototype, 'setItem');

    const view = render(<AuthProvider client={client}><Probe /></AuthProvider>);
    await screen.findByText('anonymous');
    view.unmount();

    expect(local).not.toHaveBeenCalled();
    expect(session).not.toHaveBeenCalled();
    expect(client.setUnauthorizedHandler).toHaveBeenLastCalledWith(null);
    local.mockRestore();
    session.mockRestore();
  });

  it('ignores a stale recovery response after global invalidation', async () => {
    const client = makeClient();
    let resolve!: (principal: Principal) => void;
    vi.mocked(client.getJson).mockReturnValue(new Promise((done) => { resolve = done; }));
    render(<AuthProvider client={client}><Probe /></AuthProvider>);

    const handler = vi.mocked(client.setUnauthorizedHandler).mock.calls[0][0];
    handler?.();
    resolve({ username: 'stale-user', role: 'administrator' });

    await waitFor(() => expect(screen.getByText('anonymous')).toBeVisible());
    expect(screen.queryByText('stale-user')).not.toBeInTheDocument();
  });
});
