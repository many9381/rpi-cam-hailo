import { cleanup, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { StatusPanel } from './StatusPanel';

afterEach(cleanup);

describe('StatusPanel', () => {
  it('renders health and selectable camera inventory', () => {
    render(<StatusPanel
      health={{ status: 'ok' }}
      cameras={[
        { id: 'cam-a', state: 'streaming', snapshot_available: true },
        { id: 'cam-b', state: 'starting', snapshot_available: false },
      ]}
      selectedCameraId="cam-a"
      onSelectCamera={() => undefined}
      onRestartRuntime={async () => undefined}
    />);

    expect(screen.getByText('ok')).toBeVisible();
    expect(screen.getByRole('radio', { name: /cam-a/i })).toBeChecked();
    expect(screen.getByText('Snapshot unavailable')).toBeVisible();
    expect(screen.queryByRole('button', { name: 'Restart camera runtime' }))
      .not.toBeInTheDocument();
  });

  it('offers one bounded runtime retry for an error camera', async () => {
    const user = userEvent.setup();
    const restart = vi.fn(() => new Promise<void>(() => {}));
    render(<StatusPanel
      health={{ status: 'ok' }}
      cameras={[{ id: 'cam-a', state: 'error', snapshot_available: false }]}
      selectedCameraId="cam-a"
      onSelectCamera={() => undefined}
      onRestartRuntime={restart}
    />);

    const button = screen.getByRole('button', { name: 'Restart camera runtime' });
    await user.click(button);
    await user.click(button);

    expect(restart).toHaveBeenCalledOnce();
    expect(button).toBeDisabled();
  });

  it('shows generic runtime retry feedback without backend details', async () => {
    const user = userEvent.setup();
    render(<StatusPanel
      health={{ status: 'ok' }}
      cameras={[{ id: 'cam-a', state: 'error', snapshot_available: false }]}
      selectedCameraId="cam-a"
      onSelectCamera={() => undefined}
      onRestartRuntime={async () => { throw new Error('private detail'); }}
    />);

    await user.click(screen.getByRole('button', { name: 'Restart camera runtime' }));

    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Camera runtime restart failed. Try again.',
    );
    expect(screen.queryByText(/private detail/i)).not.toBeInTheDocument();
  });
});
