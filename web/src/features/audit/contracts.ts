export interface AuditStatus {
  current_events: number;
  max_events: number;
  usage_percent: number;
  warning: boolean;
  rotated_event_count: number;
  last_rotation_at_seconds: number | null;
  last_rotated_sequence: number | null;
}

export type AuditOutcome = 'success' | 'failure';

export interface AuditEvent {
  sequence: number;
  server_timestamp_seconds: number;
  event_type: string;
  outcome: AuditOutcome;
  actor_identity: string;
  peer_ip: string;
  detail_code: string;
  subject_type: string;
  subject_identity: string;
}

export interface AuditEventPage {
  events: AuditEvent[];
  next_cursor: string | null;
}

export type AuditSortField =
  | 'timestamp'
  | 'event_type'
  | 'outcome'
  | 'actor'
  | 'peer_ip'
  | 'subject';

export type AuditSortDirection = 'asc' | 'desc';

export interface AuditListQuery {
  from_seconds?: number;
  to_seconds?: number;
  event_type?: string;
  outcome?: AuditOutcome;
  actor_identity?: string;
  peer_ip?: string;
  subject_type?: string;
  subject_identity?: string;
  sort_by: AuditSortField;
  sort_direction: AuditSortDirection;
  limit: number;
}

export const DEFAULT_AUDIT_LIST_QUERY: Readonly<AuditListQuery> = {
  sort_by: 'timestamp',
  sort_direction: 'desc',
  limit: 50,
};

const statusKeys = [
  'current_events',
  'max_events',
  'usage_percent',
  'warning',
  'rotated_event_count',
  'last_rotation_at_seconds',
  'last_rotated_sequence',
] as const;

const eventKeys = [
  'sequence',
  'server_timestamp_seconds',
  'event_type',
  'outcome',
  'actor_identity',
  'peer_ip',
  'detail_code',
  'subject_type',
  'subject_identity',
] as const;

const encoder = new TextEncoder();

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const hasExactKeys = (
  value: unknown,
  keys: readonly string[],
): value is Record<string, unknown> => isRecord(value) &&
  Object.keys(value).length === keys.length &&
  keys.every((key) => Object.prototype.hasOwnProperty.call(value, key));

const isSafeNonnegativeInteger = (value: unknown): value is number =>
  Number.isSafeInteger(value) && (value as number) >= 0;

const isSafePositiveInteger = (value: unknown): value is number =>
  Number.isSafeInteger(value) && (value as number) > 0;

const isBoundedText = (
  value: unknown,
  minimumBytes: number,
  maximumBytes: number,
): value is string => typeof value === 'string' &&
  !value.includes('\0') &&
  encoder.encode(value).length >= minimumBytes &&
  encoder.encode(value).length <= maximumBytes;

const isAuditOutcome = (value: unknown): value is AuditOutcome =>
  value === 'success' || value === 'failure';

const isNullableSafeInteger = (value: unknown): value is number | null =>
  value === null || isSafeNonnegativeInteger(value);

const isCursor = (value: unknown): value is string | null => value === null ||
  (typeof value === 'string' && value.length <= 512 && value.length % 4 !== 1 &&
   /^[A-Za-z0-9_-]+$/.test(value));

function invalidStatus(): never {
  throw new Error('Invalid audit status response');
}

function invalidEvent(): never {
  throw new Error('Invalid audit event response');
}

export function parseAuditStatus(value: unknown): AuditStatus {
  if (!hasExactKeys(value, statusKeys) ||
      !isSafeNonnegativeInteger(value.current_events) ||
      !isSafePositiveInteger(value.max_events) || value.max_events > 1_000_000 ||
      !isSafeNonnegativeInteger(value.usage_percent) || value.usage_percent > 100 ||
      typeof value.warning !== 'boolean' ||
      !isSafeNonnegativeInteger(value.rotated_event_count) ||
      !isNullableSafeInteger(value.last_rotation_at_seconds) ||
      !isNullableSafeInteger(value.last_rotated_sequence) ||
      ((value.last_rotation_at_seconds === null) !==
       (value.last_rotated_sequence === null))) {
    return invalidStatus();
  }
  return {
    current_events: value.current_events,
    max_events: value.max_events,
    usage_percent: value.usage_percent,
    warning: value.warning,
    rotated_event_count: value.rotated_event_count,
    last_rotation_at_seconds: value.last_rotation_at_seconds,
    last_rotated_sequence: value.last_rotated_sequence,
  };
}

function parseAuditEvent(value: unknown): AuditEvent {
  if (!hasExactKeys(value, eventKeys) ||
      !isSafeNonnegativeInteger(value.sequence) ||
      !isSafeNonnegativeInteger(value.server_timestamp_seconds) ||
      !isBoundedText(value.event_type, 1, 64) ||
      !isAuditOutcome(value.outcome) ||
      !isBoundedText(value.actor_identity, 1, 64) ||
      !isBoundedText(value.peer_ip, 1, 45) ||
      !isBoundedText(value.detail_code, 0, 64) ||
      !isBoundedText(value.subject_type, 0, 64) ||
      !isBoundedText(value.subject_identity, 0, 64)) {
    return invalidEvent();
  }
  return {
    sequence: value.sequence,
    server_timestamp_seconds: value.server_timestamp_seconds,
    event_type: value.event_type,
    outcome: value.outcome,
    actor_identity: value.actor_identity,
    peer_ip: value.peer_ip,
    detail_code: value.detail_code,
    subject_type: value.subject_type,
    subject_identity: value.subject_identity,
  };
}

export function parseAuditEventPage(value: unknown): AuditEventPage {
  if (!hasExactKeys(value, ['events', 'next_cursor']) ||
      !Array.isArray(value.events) || value.events.length > 100 ||
      !isCursor(value.next_cursor)) {
    return invalidEvent();
  }
  return {
    events: value.events.map(parseAuditEvent),
    next_cursor: value.next_cursor,
  };
}

const appendTextFilter = (
  parameters: URLSearchParams,
  name: string,
  value: string | undefined,
): void => {
  if (value !== undefined && value.length > 0) {
    parameters.append(name, value);
  }
};

export function buildAuditEventsUrl(
  query: Readonly<AuditListQuery>,
  cursor?: string,
): string {
  const parameters = new URLSearchParams();
  if (query.from_seconds !== undefined) {
    parameters.append('from_seconds', String(query.from_seconds));
  }
  if (query.to_seconds !== undefined) {
    parameters.append('to_seconds', String(query.to_seconds));
  }
  appendTextFilter(parameters, 'event_type', query.event_type);
  appendTextFilter(parameters, 'outcome', query.outcome);
  appendTextFilter(parameters, 'actor_identity', query.actor_identity);
  appendTextFilter(parameters, 'peer_ip', query.peer_ip);
  appendTextFilter(parameters, 'subject_type', query.subject_type);
  appendTextFilter(parameters, 'subject_identity', query.subject_identity);
  parameters.append('sort_by', query.sort_by);
  parameters.append('sort_direction', query.sort_direction);
  parameters.append('limit', String(query.limit));
  appendTextFilter(parameters, 'cursor', cursor);
  return `/api/v1/audit/events?${parameters.toString()}`;
}
