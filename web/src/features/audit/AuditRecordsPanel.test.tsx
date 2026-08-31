import '@testing-library/jest-dom/vitest';

// @ts-expect-error Vitest provides Node built-ins outside the browser bundle.
import { readFileSync } from 'node:fs';
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { CameraApiClient } from '../../api/types';
import type { AuditStatusController } from './useAuditStatus';
import {
  useAuditRecords,
  type AuditRecordsController,
} from './useAuditRecords';
import { AuditRecordsPanel } from './AuditRecordsPanel';

vi.mock('./useAuditRecords', () => ({ useAuditRecords: vi.fn() }));

const timestampSeconds = Date.UTC(2026, 6, 18, 1, 2, 3) / 1_000;
const defaultInnerWidth = window.innerWidth;
const styles = readFileSync('src/styles.css', 'utf8');

const events = [{
  sequence: 381,
  server_timestamp_seconds: timestampSeconds,
  event_type: 'viewer_disabled',
  outcome: 'success' as const,
  actor_identity: 'cameraowner',
  peer_ip: '198.51.100.61',
  detail_code: 'policy_applied',
  subject_type: 'user',
  subject_identity: 'viewer01',
}, {
  sequence: 380,
  server_timestamp_seconds: timestampSeconds - 1,
  event_type: 'login_failed',
  outcome: 'failure' as const,
  actor_identity: 'unknown',
  peer_ip: '2001:db8::10',
  detail_code: '',
  subject_type: '',
  subject_identity: '',
}];

const makeClient = (): CameraApiClient => ({
  getJson: vi.fn(),
  deleteJson: vi.fn(),
  putJson: vi.fn(),
  postJson: vi.fn(),
  getBlob: vi.fn(),
  setUnauthorizedHandler: vi.fn(),
});

const makeRecordsController = (
  overrides: Partial<AuditRecordsController> = {},
): AuditRecordsController => ({
  state: 'ready',
  page: { events, next_cursor: 'next-page' },
  query: { sort_by: 'timestamp', sort_direction: 'desc', limit: 50 },
  canGoBack: false,
  applyQuery: vi.fn(async () => undefined),
  refresh: vi.fn(async () => undefined),
  nextPage: vi.fn(async () => undefined),
  previousPage: vi.fn(async () => undefined),
  ...overrides,
});

const auditStatus: AuditStatusController = {
  state: 'ready',
  data: {
    current_events: 90,
    max_events: 100,
    usage_percent: 90,
    warning: true,
    rotated_event_count: 4,
    last_rotation_at_seconds: timestampSeconds,
    last_rotated_sequence: 377,
  },
  refresh: vi.fn(async () => undefined),
};

let client: CameraApiClient;
let recordsController: AuditRecordsController;

beforeEach(() => {
  client = makeClient();
  recordsController = makeRecordsController();
  vi.mocked(useAuditRecords).mockImplementation(() => recordsController);
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
  Object.defineProperty(window, 'innerWidth', {
    configurable: true,
    value: defaultInnerWidth,
  });
});

const renderPanel = () => render(
  <AuditRecordsPanel client={client} auditStatus={auditStatus} />,
);

function topLevelRules(): CSSRule[] {
  const style = document.createElement('style');
  style.textContent = styles;
  document.head.append(style);
  const rules = Array.from(style.sheet?.cssRules ?? []);
  style.remove();
  if (rules.length === 0) {
    throw new Error(`CSSOM parsed no rules from ${typeof styles} source (${styles.length} bytes)`);
  }
  return rules;
}

function mediaRules(rules: readonly CSSRule[], conditionText: string): CSSRule[] {
  const media = rules.find((rule) =>
    rule.type === 4 &&
    (rule as CSSMediaRule).media.mediaText === conditionText) as CSSMediaRule | undefined;
  if (media === undefined) {
    throw new Error(`Missing ${conditionText} media rule; parsed ${rules.length} rules`);
  }
  return Array.from(media.cssRules);
}

function styleRule(rules: readonly CSSRule[], selector: string): CSSStyleDeclaration {
  const rule = rules.find((candidate) =>
    candidate.type === 1 &&
    (candidate as CSSStyleRule).selectorText === selector) as CSSStyleRule | undefined;
  if (rule === undefined) {
    throw new Error(`Missing ${selector} style rule`);
  }
  return rule.style;
}

describe('AuditRecordsPanel', () => {
  it('applies all labelled filters and resets to the first-page defaults', async () => {
    const user = userEvent.setup();
    renderPanel();

    const labels = [
      'From (UTC)',
      'To (UTC)',
      'Event type',
      'Outcome',
      'Actor',
      'IP address',
      'Subject type',
      'Subject identity',
    ];
    for (const label of labels) {
      expect(screen.getByLabelText(label)).toBeVisible();
    }

    fireEvent.change(screen.getByLabelText('From (UTC)'), {
      target: { value: '2026-07-18T01:00' },
    });
    fireEvent.change(screen.getByLabelText('To (UTC)'), {
      target: { value: '2026-07-18T02:00' },
    });
    await user.type(screen.getByLabelText('Event type'), 'viewer_disabled');
    await user.selectOptions(screen.getByLabelText('Outcome'), 'success');
    await user.type(screen.getByLabelText('Actor'), 'cameraowner');
    await user.type(screen.getByLabelText('IP address'), '198.51.100.61');
    await user.type(screen.getByLabelText('Subject type'), 'user');
    await user.type(screen.getByLabelText('Subject identity'), 'viewer01');
    await user.click(screen.getByRole('button', { name: 'Apply filters' }));

    expect(recordsController.applyQuery).toHaveBeenCalledWith({
      from_seconds: Date.UTC(2026, 6, 18, 1, 0) / 1_000,
      to_seconds: Date.UTC(2026, 6, 18, 2, 0) / 1_000,
      event_type: 'viewer_disabled',
      outcome: 'success',
      actor_identity: 'cameraowner',
      peer_ip: '198.51.100.61',
      subject_type: 'user',
      subject_identity: 'viewer01',
      sort_by: 'timestamp',
      sort_direction: 'desc',
      limit: 50,
    });

    await user.click(screen.getByRole('button', { name: 'Reset filters' }));
    expect(recordsController.applyQuery).toHaveBeenLastCalledWith({
      sort_by: 'timestamp',
      sort_direction: 'desc',
      limit: 50,
    });
    for (const label of labels.filter((label) => label !== 'Outcome')) {
      expect(screen.getByLabelText(label)).toHaveValue('');
    }
    expect(screen.getByLabelText('Outcome')).toHaveValue('');

    expect(screen.queryByRole('button', { name: /export/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /delete/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /remove/i })).not.toBeInTheDocument();
  });

  it.each([
    ['Timestamp', 'timestamp'],
    ['Event type', 'event_type'],
    ['Outcome', 'outcome'],
    ['Actor', 'actor'],
    ['IP address', 'peer_ip'],
    ['Subject', 'subject'],
  ] as const)(
    'sorts by %s using an accessible keyboard command',
    async (label, sortField) => {
      const user = userEvent.setup();
      renderPanel();

      const timestampHeader = screen.getByRole('columnheader', { name: /Timestamp/ });
      expect(timestampHeader).toHaveAttribute('aria-sort', 'descending');
      const sortButton = screen.getByRole('button', { name: `Sort by ${label}` });
      sortButton.focus();
      await user.keyboard('{Enter}');

      expect(recordsController.applyQuery).toHaveBeenCalledWith({
        sort_by: sortField,
        sort_direction: 'asc',
        limit: 50,
      });
      expect(sortButton).toHaveFocus();
    },
  );

  it('toggles an ascending sort to descending without dropping applied filters', async () => {
    const user = userEvent.setup();
    recordsController = makeRecordsController({
      query: {
        actor_identity: 'cameraowner',
        sort_by: 'actor',
        sort_direction: 'asc',
        limit: 50,
      },
    });
    renderPanel();

    await user.click(screen.getByRole('button', { name: 'Sort by Actor' }));

    expect(recordsController.applyQuery).toHaveBeenCalledWith({
      actor_identity: 'cameraowner',
      sort_by: 'actor',
      sort_direction: 'desc',
      limit: 50,
    });
  });

  it('renders exact UTC values, accessible outcome badges, and every record field', () => {
    renderPanel();

    expect(screen.getByText('2026-07-18 01:02:03 UTC')).toBeVisible();
    expect(screen.getByLabelText('Outcome: success')).toHaveTextContent('Success');
    expect(screen.getByLabelText('Outcome: failure')).toHaveTextContent('Failure');
    expect(screen.getByText('viewer_disabled')).toBeVisible();
    expect(screen.getByText('cameraowner')).toBeVisible();
    expect(screen.getByText('198.51.100.61')).toBeVisible();
    expect(screen.getByText('viewer01')).toBeVisible();
    expect(screen.getByText('policy_applied')).toBeVisible();
    expect(screen.getByText('#381')).toBeVisible();
  });

  it('renders valid expanded-year UTC timestamps with seconds and ISO datetime', () => {
    recordsController = makeRecordsController({
      page: {
        events: [{
          ...events[0],
          server_timestamp_seconds: 253402300800,
        }],
        next_cursor: null,
      },
    });

    renderPanel();

    const time = screen.getByText('+010000-01-01 00:00:00 UTC');
    expect(time).toHaveAttribute('datetime', '+010000-01-01T00:00:00.000Z');
  });

  it('renders parser-accepted timestamps outside the Date range without invalid ISO', () => {
    recordsController = makeRecordsController({
      page: {
        events: [{
          ...events[0],
          sequence: Number.MAX_SAFE_INTEGER,
          server_timestamp_seconds: Number.MAX_SAFE_INTEGER,
        }],
        next_cursor: null,
      },
    });

    renderPanel();

    const time = screen.getByText('UTC timestamp unavailable');
    expect(time.tagName).toBe('TIME');
    expect(time).not.toHaveAttribute('datetime');
  });

  it('keeps a semantic table and labelled mobile cells in the 390px DOM fixture', () => {
    Object.defineProperty(window, 'innerWidth', { configurable: true, value: 390 });
    window.dispatchEvent(new Event('resize'));
    const { container } = renderPanel();

    const table = screen.getByRole('table', { name: 'Audit records' });
    expect(table.tagName).toBe('TABLE');
    const rows = within(table).getAllByRole('row').slice(1);
    expect(rows).toHaveLength(2);
    for (const row of rows) {
      const cells = within(row).getAllByRole('cell');
      expect(cells.map((cell) => cell.getAttribute('data-label'))).toEqual([
        'Timestamp',
        'Event type',
        'Outcome',
        'Actor',
        'IP address',
        'Subject',
        'Detail',
      ]);
    }
    expect(container.querySelector('.audit-records-table-wrap'))
      .toHaveClass('audit-records-table-wrap');
  });

  it('locks mobile CSS contracts while leaving real geometry to Task 8 Playwright', () => {
    const baseRules = topLevelRules();
    const mediumRules = mediaRules(baseRules, '(max-width: 1100px)');
    const narrowRules = mediaRules(baseRules, '(max-width: 420px)');

    const icon = styleRule(baseRules, '.icon-button');
    expect(icon.getPropertyValue('flex')).toBe('0 0 36px');
    expect(icon.getPropertyValue('width')).toBe('36px');
    expect(icon.getPropertyValue('height')).toBe('36px');
    const auditFocus = styleRule(baseRules, '.audit-records-section:focus');
    expect(auditFocus.getPropertyValue('outline')).toBe('3px solid #22a7a0');
    expect(auditFocus.getPropertyValue('outline-offset')).toBe('3px');

    const desktopWrap = styleRule(baseRules, '.audit-records-table-wrap');
    expect(desktopWrap.getPropertyValue('min-width')).toBe('0');
    expect(desktopWrap.getPropertyValue('overflow-x')).toBe('auto');
    const desktopCells = styleRule(
      baseRules,
      '.audit-records-table th,\n.audit-records-table td',
    );
    expect(desktopCells.getPropertyValue('min-width')).toBe('0');
    expect(desktopCells.getPropertyValue('overflow-wrap')).toBe('anywhere');

    expect(styleRule(mediumRules, '.audit-filter-form')
      .getPropertyValue('grid-template-columns'))
      .toBe('repeat(2, minmax(0, 1fr))');
    expect(styleRule(mediumRules, '.audit-records-table-wrap')
      .getPropertyValue('overflow')).toBe('visible');
    expect(styleRule(mediumRules, '.audit-records-table')
      .getPropertyValue('min-width')).toBe('0');
    const mediumRows = styleRule(mediumRules, '.audit-records-table tbody tr');
    expect(mediumRows.getPropertyValue('grid-template-columns'))
      .toBe('minmax(0, 1fr)');
    expect(mediumRows.getPropertyValue('min-width')).toBe('0');
    const mediumCells = styleRule(mediumRules, '.audit-records-table td');
    expect(mediumCells.getPropertyValue('grid-template-columns'))
      .toBe('minmax(108px, 34%) minmax(0, 1fr)');
    expect(mediumCells.getPropertyValue('min-width')).toBe('0');
    expect(styleRule(mediumRules, '.audit-records-table td::before')
      .getPropertyValue('content')).toBe('attr(data-label)');

    expect(styleRule(narrowRules, '.audit-filter-form')
      .getPropertyValue('grid-template-columns')).toBe('minmax(0, 1fr)');
    expect(styleRule(narrowRules, '.audit-records-table td')
      .getPropertyValue('grid-template-columns'))
      .toBe('minmax(96px, 34%) minmax(0, 1fr)');
    expect(styleRule(narrowRules, '.audit-records-table thead tr')
      .getPropertyValue('grid-template-columns'))
      .toBe('repeat(2, minmax(0, 1fr))');
  });

  it('announces loading, refreshing, stale, empty, and unavailable states', async () => {
    const user = userEvent.setup();
    recordsController = makeRecordsController({ state: 'loading', page: null });
    const view = renderPanel();
    expect(screen.getByRole('status')).toHaveTextContent('Loading audit records');

    recordsController = makeRecordsController({ state: 'refreshing' });
    view.rerender(<AuditRecordsPanel client={client} auditStatus={auditStatus} />);
    expect(screen.getByRole('status')).toHaveTextContent(
      'Refreshing audit records. Showing current results.',
    );
    expect(screen.getByRole('table')).toHaveAttribute('aria-busy', 'true');

    recordsController = makeRecordsController({ state: 'stale' });
    view.rerender(<AuditRecordsPanel client={client} auditStatus={auditStatus} />);
    expect(screen.getByRole('status')).toHaveTextContent(
      'Showing the last available audit records.',
    );
    expect(screen.getByText('viewer_disabled')).toBeVisible();

    recordsController = makeRecordsController({
      page: { events: [], next_cursor: null },
    });
    view.rerender(<AuditRecordsPanel client={client} auditStatus={auditStatus} />);
    expect(screen.getByRole('status')).toHaveTextContent(
      'No audit records match the current filters.',
    );

    const refresh = vi.fn(async () => undefined);
    recordsController = makeRecordsController({
      state: 'unavailable',
      page: null,
      refresh,
    });
    view.rerender(<AuditRecordsPanel client={client} auditStatus={auditStatus} />);
    expect(screen.getByRole('alert')).toHaveTextContent(
      'Audit records are temporarily unavailable.',
    );
    await user.click(screen.getByRole('button', { name: 'Retry audit records' }));
    expect(refresh).toHaveBeenCalledOnce();
  });

  it('shows capacity and rotation status including stale status copy', () => {
    const staleStatus: AuditStatusController = { ...auditStatus, state: 'stale' };
    render(<AuditRecordsPanel client={client} auditStatus={staleStatus} />);

    const summary = screen.getByLabelText('Audit capacity summary');
    expect(summary).toHaveTextContent('90 of 100 records');
    expect(summary).toHaveTextContent('90% used');
    expect(summary).toHaveTextContent('4 rotated');
    expect(summary).toHaveTextContent('Last rotation 2026-07-18 01:02:03 UTC');
    expect(summary).toHaveTextContent('through #377');
    expect(screen.getByRole('status')).toHaveTextContent(
      'Capacity status may be out of date.',
    );
  });

  it('uses stable previous, next, and refresh icon commands', async () => {
    const user = userEvent.setup();
    const view = renderPanel();
    const previous = screen.getByRole('button', { name: 'Previous audit page' });
    const next = screen.getByRole('button', { name: 'Next audit page' });
    const refresh = screen.getByRole('button', { name: 'Refresh audit records' });

    expect(previous).toBeDisabled();
    expect(next).toBeEnabled();
    for (const button of [previous, next, refresh]) {
      expect(button).toHaveAttribute('title', button.getAttribute('aria-label'));
      expect(button).toHaveClass('icon-button');
    }

    await user.click(next);
    expect(recordsController.nextPage).toHaveBeenCalledOnce();
    expect(screen.getByText('Page 2')).toBeVisible();
    await user.click(refresh);
    expect(recordsController.refresh).toHaveBeenCalledOnce();

    recordsController = makeRecordsController({
      page: { events, next_cursor: null },
      canGoBack: true,
    });
    view.rerender(<AuditRecordsPanel client={client} auditStatus={auditStatus} />);
    expect(screen.getByRole('button', { name: 'Previous audit page' })).toBeEnabled();
    expect(screen.getByRole('button', { name: 'Next audit page' })).toBeDisabled();
    await user.click(screen.getByRole('button', { name: 'Previous audit page' }));
    await waitFor(() => expect(recordsController.previousPage).toHaveBeenCalledOnce());
  });
});
