import {
  ArrowDown,
  ArrowUp,
  ChevronLeft,
  ChevronRight,
  ChevronsUpDown,
  Filter,
  RefreshCw,
  RotateCcw,
} from 'lucide-react';
import { type FormEvent, useEffect, useRef, useState } from 'react';

import type { CameraApiClient } from '../../api/types';
import { IconButton } from '../../components/IconButton';
import { useTranslation } from '../../i18n/LanguageContext';
import {
  DEFAULT_AUDIT_LIST_QUERY,
  type AuditEvent,
  type AuditListQuery,
  type AuditSortField,
} from './contracts';
import { auditErrorMessage } from './publicError';
import { useAuditRecords } from './useAuditRecords';
import type { AuditStatusController } from './useAuditStatus';

interface AuditRecordsPanelProps {
  client: CameraApiClient;
  auditStatus?: AuditStatusController;
  routeFragment?: string;
}

interface FilterDraft {
  from: string;
  to: string;
  eventType: string;
  outcome: '' | 'success' | 'failure';
  actor: string;
  peerIp: string;
  subjectType: string;
  subjectIdentity: string;
}

const emptyFilterDraft = (): FilterDraft => ({
  from: '',
  to: '',
  eventType: '',
  outcome: '',
  actor: '',
  peerIp: '',
  subjectType: '',
  subjectIdentity: '',
});

const sortColumns: ReadonlyArray<{
  field: AuditSortField;
  labelKey: string;
}> = [
  { field: 'timestamp', labelKey: 'audit.timestamp' },
  { field: 'event_type', labelKey: 'audit.eventType' },
  { field: 'outcome', labelKey: 'audit.outcome' },
  { field: 'actor', labelKey: 'audit.actor' },
  { field: 'peer_ip', labelKey: 'audit.ipAddress' },
  { field: 'subject', labelKey: 'audit.subject' },
];

interface FormattedUtc {
  text: string;
  dateTime?: string;
}

// Returns null when the timestamp cannot be formatted; callers resolve the
// fallback copy via t('audit.timestampUnavailable') since this module-scope
// helper has no access to the translator.
function formatUtc(seconds: number): FormattedUtc | null {
  const date = new Date(seconds * 1_000);
  if (!Number.isFinite(date.getTime())) {
    return null;
  }
  const dateTime = date.toISOString();
  return {
    text: dateTime.replace(/T(\d{2}:\d{2}:\d{2})\.\d{3}Z$/, ' $1 UTC'),
    dateTime,
  };
}

function utcInputSeconds(value: string): number | undefined {
  if (value === '') {
    return undefined;
  }
  const milliseconds = Date.parse(`${value}Z`);
  return Number.isFinite(milliseconds)
    ? Math.floor(milliseconds / 1_000)
    : undefined;
}

function trimmed(value: string): string | undefined {
  const next = value.trim();
  return next === '' ? undefined : next;
}

function queryFromDraft(
  draft: FilterDraft,
  current: Readonly<AuditListQuery>,
): AuditListQuery {
  const query: AuditListQuery = {
    sort_by: current.sort_by,
    sort_direction: current.sort_direction,
    limit: current.limit,
  };
  const from = utcInputSeconds(draft.from);
  const to = utcInputSeconds(draft.to);
  const eventType = trimmed(draft.eventType);
  const actor = trimmed(draft.actor);
  const peerIp = trimmed(draft.peerIp);
  const subjectType = trimmed(draft.subjectType);
  const subjectIdentity = trimmed(draft.subjectIdentity);
  if (from !== undefined) query.from_seconds = from;
  if (to !== undefined) query.to_seconds = to;
  if (eventType !== undefined) query.event_type = eventType;
  if (draft.outcome !== '') query.outcome = draft.outcome;
  if (actor !== undefined) query.actor_identity = actor;
  if (peerIp !== undefined) query.peer_ip = peerIp;
  if (subjectType !== undefined) query.subject_type = subjectType;
  if (subjectIdentity !== undefined) query.subject_identity = subjectIdentity;
  return query;
}

function SortIcon({ field, query }: {
  field: AuditSortField;
  query: Readonly<AuditListQuery>;
}) {
  if (query.sort_by !== field) {
    return <ChevronsUpDown size={14} aria-hidden="true" />;
  }
  return query.sort_direction === 'asc'
    ? <ArrowUp size={14} aria-hidden="true" />
    : <ArrowDown size={14} aria-hidden="true" />;
}

const OUTCOME_LABEL_KEYS: Record<AuditEvent['outcome'], string> = {
  success: 'audit.outcomeSuccess',
  failure: 'audit.outcomeFailure',
};

function CapacitySummary({ controller }: {
  controller?: AuditStatusController;
}) {
  const { t } = useTranslation();
  const status = controller?.data;
  if (status === null || status === undefined) {
    return controller?.state === 'unavailable'
      ? <p className="audit-capacity-state" role="alert">{t('audit.capacityUnavailable')}</p>
      : <p className="audit-capacity-state" role="status">{t('audit.loadingCapacity')}</p>;
  }

  const lastRotationText = status.last_rotation_at_seconds === null
    ? null
    : formatUtc(status.last_rotation_at_seconds)?.text ?? t('audit.timestampUnavailable');

  return (
    <div className="audit-capacity-summary" aria-label={t('audit.capacitySummaryLabel')}>
      <span><strong>{t('audit.capacityCount', {
        current: status.current_events,
        max: status.max_events,
      })}</strong></span>
      <span>{t('audit.usagePercent', { percent: status.usage_percent })}</span>
      <span>{t('audit.rotatedCount', { count: status.rotated_event_count })}</span>
      <span>
        {lastRotationText === null
          ? t('audit.lastRotationNever')
          : status.last_rotated_sequence === null
            ? t('audit.lastRotationAt', { timestamp: lastRotationText })
            : t('audit.lastRotationAtWithSequence', {
              timestamp: lastRotationText,
              sequence: status.last_rotated_sequence,
            })}
      </span>
      {controller?.state === 'stale' && (
        <span className="audit-capacity-stale" role="status">
          {t('audit.capacityStale')}
        </span>
      )}
    </div>
  );
}

function EventRow({ event }: { event: AuditEvent }) {
  const { t } = useTranslation();
  const timestamp = formatUtc(event.server_timestamp_seconds);
  const subject = event.subject_type === '' && event.subject_identity === ''
    ? null
    : (
      <span className="audit-subject-value">
        {event.subject_type !== '' && <strong>{event.subject_type}</strong>}
        {event.subject_identity !== '' && <span>{event.subject_identity}</span>}
      </span>
    );
  return (
    <tr>
      <td data-label={t('audit.timestamp')}>
        <time dateTime={timestamp?.dateTime}>
          {timestamp?.text ?? t('audit.timestampUnavailable')}
        </time>
      </td>
      <td data-label={t('audit.eventType')}>
        <span className="audit-event-value">
          <strong>{event.event_type}</strong>
          <span>#{event.sequence}</span>
        </span>
      </td>
      <td data-label={t('audit.outcome')}>
        <span className={`audit-outcome-badge audit-outcome-${event.outcome}`}
          aria-label={t('audit.outcomeAriaLabel', { outcome: event.outcome })}>
          {t(OUTCOME_LABEL_KEYS[event.outcome])}
        </span>
      </td>
      <td data-label={t('audit.actor')}>{event.actor_identity}</td>
      <td data-label={t('audit.ipAddress')}><code>{event.peer_ip}</code></td>
      <td data-label={t('audit.subject')}>{subject ?? '-'}</td>
      <td data-label={t('audit.detail')}>{event.detail_code === '' ? '-' : event.detail_code}</td>
    </tr>
  );
}

export function AuditRecordsPanel({
  client,
  auditStatus,
  routeFragment = '',
}: AuditRecordsPanelProps) {
  const { t } = useTranslation();
  const controller = useAuditRecords(client);
  const sectionRef = useRef<HTMLElement>(null);
  const handledFragment = useRef<string>();
  const [draft, setDraft] = useState<FilterDraft>(emptyFilterDraft);
  const [pageNumber, setPageNumber] = useState(1);
  const [commandPending, setCommandPending] = useState(false);
  const [commandError, setCommandError] = useState<string | null>(null);
  const busy = commandPending || controller.state === 'loading' ||
    controller.state === 'refreshing';

  useEffect(() => {
    if (handledFragment.current === routeFragment) {
      return;
    }
    handledFragment.current = routeFragment;
    if (routeFragment !== '#audit-records') {
      return;
    }
    sectionRef.current?.focus({ preventScroll: true });
    sectionRef.current?.scrollIntoView({ block: 'start' });
  }, [routeFragment]);

  const runCommand = async (
    command: () => Promise<void>,
    onSuccess?: () => void,
  ) => {
    setCommandPending(true);
    setCommandError(null);
    try {
      await command();
      onSuccess?.();
    } catch (error) {
      setCommandError(auditErrorMessage(error));
    } finally {
      setCommandPending(false);
    }
  };

  const applyFilters = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const query = queryFromDraft(draft, controller.query);
    void runCommand(() => controller.applyQuery(query), () => setPageNumber(1));
  };

  const resetFilters = () => {
    const nextDraft = emptyFilterDraft();
    setDraft(nextDraft);
    void runCommand(
      () => controller.applyQuery({ ...DEFAULT_AUDIT_LIST_QUERY }),
      () => setPageNumber(1),
    );
  };

  const sortBy = (field: AuditSortField) => {
    const direction = controller.query.sort_by === field &&
        controller.query.sort_direction === 'desc'
      ? 'asc'
      : controller.query.sort_by === field
        ? 'desc'
        : 'asc';
    void runCommand(
      () => controller.applyQuery({
        ...controller.query,
        sort_by: field,
        sort_direction: direction,
      }),
      () => setPageNumber(1),
    );
  };

  return (
    <section ref={sectionRef} id="audit-records" tabIndex={-1}
      className="operational-section audit-records-section"
      aria-labelledby="audit-records-heading">
      <div className="section-heading audit-records-heading">
        <div>
          <h2 id="audit-records-heading">{t('audit.title')}</h2>
          <CapacitySummary controller={auditStatus} />
        </div>
        <IconButton label={t('audit.refreshRecords')} disabled={busy}
          onClick={() => void runCommand(() => controller.refresh())}>
          <RefreshCw size={17} aria-hidden="true" />
        </IconButton>
      </div>

      <form className="audit-filter-form" aria-label={t('audit.filtersLabel')}
        onSubmit={applyFilters}>
        <label className="audit-filter-field">
          <span>{t('audit.filterFrom')}</span>
          <input type="datetime-local" value={draft.from}
            onChange={(event) => setDraft({ ...draft, from: event.target.value })} />
        </label>
        <label className="audit-filter-field">
          <span>{t('audit.filterTo')}</span>
          <input type="datetime-local" value={draft.to}
            onChange={(event) => setDraft({ ...draft, to: event.target.value })} />
        </label>
        <label className="audit-filter-field">
          <span>{t('audit.eventType')}</span>
          <input value={draft.eventType} maxLength={64}
            onChange={(event) => setDraft({ ...draft, eventType: event.target.value })} />
        </label>
        <label className="audit-filter-field">
          <span>{t('audit.outcome')}</span>
          <select value={draft.outcome}
            onChange={(event) => setDraft({
              ...draft,
              outcome: event.target.value as FilterDraft['outcome'],
            })}>
            <option value="">{t('audit.allOutcomes')}</option>
            <option value="success">{t('audit.outcomeSuccess')}</option>
            <option value="failure">{t('audit.outcomeFailure')}</option>
          </select>
        </label>
        <label className="audit-filter-field">
          <span>{t('audit.actor')}</span>
          <input value={draft.actor} maxLength={64}
            onChange={(event) => setDraft({ ...draft, actor: event.target.value })} />
        </label>
        <label className="audit-filter-field">
          <span>{t('audit.ipAddress')}</span>
          <input value={draft.peerIp} maxLength={45} inputMode="text"
            onChange={(event) => setDraft({ ...draft, peerIp: event.target.value })} />
        </label>
        <label className="audit-filter-field">
          <span>{t('audit.filterSubjectType')}</span>
          <input value={draft.subjectType} maxLength={64}
            onChange={(event) => setDraft({ ...draft, subjectType: event.target.value })} />
        </label>
        <label className="audit-filter-field">
          <span>{t('audit.filterSubjectIdentity')}</span>
          <input value={draft.subjectIdentity} maxLength={64}
            onChange={(event) => setDraft({ ...draft, subjectIdentity: event.target.value })} />
        </label>
        <div className="audit-filter-actions">
          <button type="submit" className="audit-command-button" disabled={busy}>
            <Filter size={16} aria-hidden="true" />
            {t('audit.applyFilters')}
          </button>
          <button type="button" className="audit-command-button audit-command-secondary"
            disabled={busy} onClick={resetFilters}>
            <RotateCcw size={16} aria-hidden="true" />
            {t('audit.resetFilters')}
          </button>
        </div>
      </form>

      {commandError !== null && <p className="audit-error" role="alert">{commandError}</p>}
      {controller.state === 'loading' && controller.page === null && (
        <p className="audit-record-state" role="status">{t('audit.loadingRecords')}</p>
      )}
      {controller.state === 'unavailable' && controller.page === null && (
        <div className="audit-record-state audit-record-error" role="alert">
          <span>{t('audit.recordsUnavailable')}</span>
          <button type="button" className="audit-command-button"
            aria-label={t('audit.retryRecords')}
            onClick={() => void runCommand(() => controller.refresh())}>
            <RefreshCw size={16} aria-hidden="true" />
            {t('common.retry')}
          </button>
        </div>
      )}
      {controller.state === 'refreshing' && controller.page !== null && (
        <p className="audit-record-state audit-record-stale" role="status">
          {t('audit.refreshingRecords')}
        </p>
      )}
      {controller.state === 'stale' && controller.page !== null && (
        <p className="audit-record-state audit-record-stale" role="status">
          {t('audit.staleRecords')}
        </p>
      )}
      {controller.state === 'ready' && controller.page?.events.length === 0 && (
        <p className="audit-record-state" role="status">
          {t('audit.noRecordsMatch')}
        </p>
      )}

      {controller.page !== null && controller.page.events.length > 0 && (
        <div className="audit-records-table-wrap">
          <table className={controller.state === 'refreshing' || controller.state === 'stale'
            ? 'audit-records-table audit-records-table-stale'
            : 'audit-records-table'}
            aria-label={t('audit.title')}
            aria-busy={controller.state === 'refreshing'}>
            <thead>
              <tr>
                {sortColumns.map(({ field, labelKey }) => (
                  <th key={field} scope="col"
                    aria-sort={controller.query.sort_by === field
                      ? controller.query.sort_direction === 'asc'
                        ? 'ascending'
                        : 'descending'
                      : 'none'}>
                    <button type="button" className="audit-sort-button"
                      aria-label={t('audit.sortBy', { field: t(labelKey) })}
                      title={t('audit.sortBy', { field: t(labelKey) })}
                      disabled={busy} onClick={() => sortBy(field)}>
                      <span>{t(labelKey)}</span>
                      <SortIcon field={field} query={controller.query} />
                    </button>
                  </th>
                ))}
                <th scope="col">{t('audit.detail')}</th>
              </tr>
            </thead>
            <tbody>
              {controller.page.events.map((event) => (
                <EventRow key={event.sequence} event={event} />
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="audit-pagination" aria-label={t('audit.paginationLabel')}>
        <IconButton label={t('audit.previousPage')}
          disabled={busy || !controller.canGoBack}
          onClick={() => void runCommand(
            () => controller.previousPage(),
            () => setPageNumber((value) => Math.max(1, value - 1)),
          )}>
          <ChevronLeft size={18} aria-hidden="true" />
        </IconButton>
        <span>{t('audit.pageNumber', { n: pageNumber })}</span>
        <IconButton label={t('audit.nextPage')}
          disabled={busy || controller.page?.next_cursor == null}
          onClick={() => void runCommand(
            () => controller.nextPage(),
            () => setPageNumber((value) => value + 1),
          )}>
          <ChevronRight size={18} aria-hidden="true" />
        </IconButton>
      </div>
    </section>
  );
}
