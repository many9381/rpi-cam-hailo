import { cleanup, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { LanguageProvider } from '../i18n';
import { StatusPanel } from './StatusPanel';

afterEach(cleanup);

describe('StatusPanel', () => {
  it('renders health and selectable camera inventory', () => {
    render(<LanguageProvider><StatusPanel
      health={{ status: 'ok' }}
      cameras={[
        { id: 'cam-a', state: 'streaming', snapshot_available: true },
        { id: 'cam-b', state: 'starting', snapshot_available: false },
      ]}
      selectedCameraId="cam-a"
      onSelectCamera={() => undefined}
      onRestartRuntime={async () => undefined}
    /></LanguageProvider>);

    expect(screen.getByText('ok')).toBeVisible();
    expect(screen.getByRole('radio', { name: /cam-a/i })).toBeChecked();
    expect(screen.getByText('Snapshot unavailable')).toBeVisible();
    expect(screen.queryByRole('button', { name: 'Restart camera runtime' }))
      .not.toBeInTheDocument();
  });

  it('shows encoder health metrics when the camera reports them', () => {
    render(<LanguageProvider><StatusPanel
      health={{ status: 'ok' }}
      cameras={[{
        id: 'cam-a', state: 'streaming', snapshot_available: true,
        capture_fps: 49.8, encoded_fps: 24.9, last_encode_ms: 7.2,
      }]}
      selectedCameraId="cam-a"
      onSelectCamera={() => undefined}
      onRestartRuntime={async () => undefined}
    /></LanguageProvider>);

    // encoded_fps well below capture_fps signals encoder backlog.
    expect(screen.getByText(/capture 49\.8/i)).toBeVisible();
    expect(screen.getByText(/encode 24\.9/i)).toBeVisible();
    expect(screen.getByText(/7\.2\s*ms/i)).toBeVisible();
  });

  it('omits the metrics line when the camera reports none', () => {
    render(<LanguageProvider><StatusPanel
      health={{ status: 'ok' }}
      cameras={[{ id: 'cam-a', state: 'streaming', snapshot_available: true }]}
      selectedCameraId="cam-a"
      onSelectCamera={() => undefined}
      onRestartRuntime={async () => undefined}
    /></LanguageProvider>);
    expect(screen.queryByText(/capture/i)).not.toBeInTheDocument();
  });

  it('offers one bounded runtime retry for an error camera', async () => {
    const user = userEvent.setup();
    const restart = vi.fn(() => new Promise<void>(() => {}));
    render(<LanguageProvider><StatusPanel
      health={{ status: 'ok' }}
      cameras={[{ id: 'cam-a', state: 'error', snapshot_available: false }]}
      selectedCameraId="cam-a"
      onSelectCamera={() => undefined}
      onRestartRuntime={restart}
    /></LanguageProvider>);

    const button = screen.getByRole('button', { name: 'Restart camera runtime' });
    await user.click(button);
    await user.click(button);

    expect(restart).toHaveBeenCalledOnce();
    expect(button).toBeDisabled();
  });

  it('shows generic runtime retry feedback without backend details', async () => {
    const user = userEvent.setup();
    render(<LanguageProvider><StatusPanel
      health={{ status: 'ok' }}
      cameras={[{ id: 'cam-a', state: 'error', snapshot_available: false }]}
      selectedCameraId="cam-a"
      onSelectCamera={() => undefined}
      onRestartRuntime={async () => { throw new Error('private detail'); }}
    /></LanguageProvider>);

    await user.click(screen.getByRole('button', { name: 'Restart camera runtime' }));

    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Camera runtime restart failed. Try again.',
    );
    expect(screen.queryByText(/private detail/i)).not.toBeInTheDocument();
  });
});
