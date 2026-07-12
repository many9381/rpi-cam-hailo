import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { StatusPanel } from './StatusPanel';

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
    />);

    expect(screen.getByText('ok')).toBeVisible();
    expect(screen.getByRole('radio', { name: /cam-a/i })).toBeChecked();
    expect(screen.getByText('Snapshot unavailable')).toBeVisible();
  });
});
