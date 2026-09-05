import '@testing-library/jest-dom/vitest';

import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { LanguageProvider } from '../../i18n';
import type { AuditStatusController } from './useAuditStatus';
import { AuditCapacityNotice } from './AuditCapacityNotice';

const makeController = (
  overrides: Partial<AuditStatusController> = {},
): AuditStatusController => ({
  state: 'ready',
  data: {
    current_events: 90,
    max_events: 100,
    usage_percent: 90,
    warning: true,
    rotated_event_count: 4,
    last_rotation_at_seconds: 1_784_333_000,
    last_rotated_sequence: 4,
  },
  refresh: vi.fn(async () => undefined),
  ...overrides,
});

afterEach(cleanup);

describe('AuditCapacityNotice', () => {
  it('does not make a capacity claim without an authoritative warning', () => {
    const { rerender } = render(
      <AuditCapacityNotice controller={undefined} />,
      { wrapper: LanguageProvider },
    );
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();

    rerender(<AuditCapacityNotice controller={makeController({
      state: 'loading',
      data: null,
    })} />);
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();

    rerender(<AuditCapacityNotice controller={makeController({
      state: 'unavailable',
      data: null,
    })} />);
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();

    rerender(<AuditCapacityNotice controller={makeController({
      data: { ...makeController().data!, warning: false },
    })} />);
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('shows one persistent warning with exact capacity and System link', () => {
    render(<AuditCapacityNotice controller={makeController()} />, {
      wrapper: LanguageProvider,
    });

    const warning = screen.getByRole('alert');
    expect(warning).toHaveTextContent('90 of 100 audit records');
    expect(warning).toHaveTextContent('90%');
    expect(screen.getByRole('link', { name: 'Review audit records' }))
      .toHaveAttribute('href', '#/system#audit-records');
    expect(screen.getAllByRole('alert')).toHaveLength(1);
  });

  it('keeps the prior warning visible while status is stale', () => {
    render(<AuditCapacityNotice controller={makeController({ state: 'stale' })} />, {
      wrapper: LanguageProvider,
    });

    expect(screen.getByRole('alert')).toHaveTextContent('90 of 100 audit records');
    expect(screen.getByRole('alert')).toHaveTextContent(
      'Capacity status may be out of date.',
    );
  });
});
