import '@testing-library/jest-dom/vitest';

import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ApiClient } from '../../api/client';
import { BootstrapGate } from '../../App';
import { LanguageProvider } from '../../i18n';
import { SetupWizard } from './SetupWizard';

const initialStatus = {
  required: true, phase: 'administrator', tls: 'ready', peer_ip: '192.0.2.10',
  initial_username: 'setup.old', initial_password: 'OldInitial!9',
};
const freshStatus = {
  ...initialStatus, initial_username: 'setup.new', initial_password: 'NewInitial!9',
};
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), {
  status, headers: { 'Content-Type': 'application/json' },
});

afterEach(() => {
  cleanup();
  localStorage.removeItem('cf.lang');
  vi.useRealTimers();
});

async function review(user: ReturnType<typeof userEvent.setup>) {
  await user.type(await screen.findByLabelText(/^username$/i), 'operator.one');
  await user.type(screen.getByLabelText(/^password$/i), 'NorthStar!9');
  await user.type(screen.getByLabelText(/confirm password/i), 'NorthStar!9');
  await user.click(screen.getByRole('button', { name: /^next$/i }));
  await user.click(screen.getByRole('button', { name: /^next$/i }));
}

function expiredSessionCamera(
  refresh: 'ready' | 'offline' | 'timeout' | 'completed' = 'ready',
  rejection = 'E_AUTHENTICATION_REQUIRED',
) {
  let session = true;
  let expired = false;
  let statusReads = 0;
  let initializeRequests = 0;
  let refreshMode = refresh;
  const client = new ApiClient(async (input) => {
    const path = String(input);
    if (path === '/api/v1/setup/status') {
      ++statusReads;
      if (!expired) return json(initialStatus);
      if (refreshMode === 'offline') throw new TypeError('Private transport details');
      if (refreshMode === 'timeout') return new Promise<Response>(() => {});
      if (refreshMode === 'completed') return json({ required: false });
      return json(freshStatus);
    }
    if (path === '/api/v1/auth/me') {
      return session
        ? json({ username: 'setup.old', role: 'viewer' })
        : json({ code: 'E_AUTHENTICATION_REQUIRED' }, 401);
    }
    if (path === '/api/v1/auth/login') {
      session = true;
      return json({ role: 'viewer', idle_expires_at_seconds: 1720000700 });
    }
    if (path === '/api/v1/setup/initialize') {
      ++initializeRequests;
      expired = true;
      session = false;
      return json({ code: rejection }, 401);
    }
    throw new Error(`Unexpected test request: ${path}`);
  });
  render(<LanguageProvider><MemoryRouter>
    <BootstrapGate client={client} operationalChild={<p>Operational camera</p>} />
  </MemoryRouter></LanguageProvider>);
  return {
    restoreNetwork: () => { refreshMode = 'ready'; },
    statusReads: () => statusReads,
    initializeRequests: () => initializeRequests,
  };
}

describe('Initial setup session recovery', () => {
  it.each(['E_AUTHENTICATION_REQUIRED', 'E_AUTHENTICATION_FAILED'])(
    'returns a rejected setup session (%s) to login with refreshed initial credentials', async (code) => {
    const user = userEvent.setup();
    const camera = expiredSessionCamera('ready', code);
    await review(user);
    await user.click(screen.getByRole('button', { name: /complete setup/i }));

    expect(await screen.findByRole('heading', { name: 'Camera login' })).toBeVisible();
    expect(screen.getByRole('status')).toHaveTextContent('Your initial setup session has ended');
    expect(screen.getByText('setup.new')).toBeVisible();
    expect(screen.getByText('NewInitial!9')).toBeVisible();
    expect(screen.queryByText('OldInitial!9')).not.toBeInTheDocument();
    expect(screen.getByLabelText(/^password$/i)).toHaveValue('');
    expect(camera.statusReads()).toBe(2);
    expect(camera.initializeRequests()).toBe(1);

    await user.type(screen.getByLabelText(/^username$/i), 'setup.new');
    await user.type(screen.getByLabelText(/^password$/i), 'NewInitial!9');
    await user.click(screen.getByRole('button', { name: /^sign in$/i }));
    expect(await screen.findByRole('heading', { name: 'Create administrator' })).toBeVisible();
    expect(screen.getByLabelText(/^password$/i)).toHaveValue('');
    expect(screen.queryByRole('status')).not.toBeInTheDocument();
    expect(camera.initializeRequests()).toBe(1);
  });

  it('offers a retry if fresh initial credentials cannot be fetched', async () => {
    const user = userEvent.setup();
    const camera = expiredSessionCamera('offline');
    await review(user);
    await user.click(screen.getByRole('button', { name: /complete setup/i }));
    const retry = await screen.findByRole('button', { name: /^retry$/i });
    expect(screen.queryByLabelText(/^password$/i)).not.toBeInTheDocument();
    expect(screen.queryByText('OldInitial!9')).not.toBeInTheDocument();
    camera.restoreNetwork();
    await user.click(retry);
    expect(await screen.findByRole('heading', { name: 'Camera login' })).toBeVisible();
    expect(screen.getByText('NewInitial!9')).toBeVisible();
    expect(screen.getByRole('status')).toHaveTextContent('Your initial setup session has ended');
    expect(camera.initializeRequests()).toBe(1);
  });

  it('bounds the credential refresh wait after session rejection', async () => {
    const user = userEvent.setup();
    expiredSessionCamera('timeout');
    await review(user);
    vi.useFakeTimers();
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: /complete setup/i })); });
    await act(async () => { await vi.advanceTimersByTimeAsync(5_000); });
    expect(screen.getByRole('button', { name: /^retry$/i })).toBeVisible();
    expect(screen.queryByRole('heading', { name: 'Create administrator' })).not.toBeInTheDocument();
  });

  it('honors completed setup even when the old setup session is rejected', async () => {
    const user = userEvent.setup();
    expiredSessionCamera('completed');
    await review(user);
    await user.click(screen.getByRole('button', { name: /complete setup/i }));
    expect(await screen.findByText('Operational camera')).toBeVisible();
    expect(screen.queryByRole('heading', { name: 'Camera login' })).not.toBeInTheDocument();
  });
});

describe('Public setup failures', () => {
  it.each([
    [400, 'E_USERNAME_RESERVED', 'This username is reserved.'],
    [400, 'E_PASSWORD_LENGTH', 'Enter a password with the required length.'],
    [403, 'E_REQUEST_ORIGIN', 'The request origin or camera address was rejected.'],
    [503, 'E_INTERNAL', 'The camera service could not complete setup.'],
    [429, 'E_RATE_LIMITED', 'Too many requests.'],
    [400, 'E_BOOTSTRAP_PEER', 'Your connection address changed.'],
    [400, '__proto__', 'The setup request was rejected.'],
    [0, '', 'Unable to confirm camera initialization.'],
  ])('shows safe guidance for HTTP %i / %s', async (status, code, message) => {
    const user = userEvent.setup();
    const client = new ApiClient(async () => {
      if (status === 0) throw new TypeError('secret internal connection detail');
      return json({ code, message: 'secret internal connection detail' }, status);
    });
    render(<LanguageProvider><SetupWizard client={client} peerIp="192.0.2.10" onInitialized={() => {}} /></LanguageProvider>);
    await review(user);
    await user.click(screen.getByRole('button', { name: /complete setup/i }));
    expect(await screen.findByRole('alert')).toHaveTextContent(message);
    expect(screen.queryByText(/secret internal connection detail/)).not.toBeInTheDocument();
    expect(screen.getByLabelText(/^username$/i)).toHaveValue('operator.one');
    expect(screen.getByLabelText(/^password$/i)).toHaveValue('');
    expect(screen.getByLabelText(/confirm password/i)).toHaveValue('');
  });

  it('explains a service failure in Korean without blaming the password', async () => {
    localStorage.setItem('cf.lang', 'ko');
    const user = userEvent.setup();
    const client = new ApiClient(async () => json({ code: 'E_SECURITY_UNAVAILABLE' }, 503));
    render(<LanguageProvider><SetupWizard client={client} peerIp="192.0.2.10" onInitialized={() => {}} /></LanguageProvider>);
    await user.type(screen.getByLabelText('사용자 이름'), 'operator.one');
    await user.type(screen.getByLabelText('비밀번호'), 'NorthStar!9');
    await user.type(screen.getByLabelText('비밀번호 확인'), 'NorthStar!9');
    await user.click(screen.getByRole('button', { name: '다음' }));
    await user.click(screen.getByRole('button', { name: '다음' }));
    await user.click(screen.getByRole('button', { name: '설정 완료' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('카메라 서비스가 초기 설정을 완료하지 못했습니다.');
    expect(screen.getByRole('alert')).not.toHaveTextContent('자격 증명');
  });
});
