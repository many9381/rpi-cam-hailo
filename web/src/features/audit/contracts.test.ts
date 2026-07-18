import { describe, expect, it } from 'vitest';

import {
  DEFAULT_AUDIT_LIST_QUERY,
  buildAuditEventsUrl,
  parseAuditEventPage,
  parseAuditStatus,
  type AuditListQuery,
} from './contracts';

const status = () => ({
  current_events: 75,
  max_events: 50,
  usage_percent: 100,
  warning: true,
  rotated_event_count: 25,
  last_rotation_at_seconds: 1_784_300_000,
  last_rotated_sequence: 25,
});

const event = () => ({
  sequence: 381,
  server_timestamp_seconds: 1_784_300_000,
  event_type: 'viewer_disabled',
  outcome: 'success',
  actor_identity: 'cameraowner',
  peer_ip: '2001:db8::1',
  detail_code: '',
  subject_type: 'user',
  subject_identity: 'viewer01',
});

const without = (value: Record<string, unknown>, key: string) => {
  const copy = { ...value };
  delete copy[key];
  return copy;
};

describe('audit status contract', () => {
  it('parses exact status keys and permits current events above the startup limit', () => {
    const raw = status();

    const parsed = parseAuditStatus(raw);

    expect(parsed).toEqual(raw);
    expect(parsed).not.toBe(raw);
  });

  it('accepts the authoritative all-null rotation pair', () => {
    expect(parseAuditStatus({
      ...status(),
      current_events: 0,
      usage_percent: 0,
      warning: false,
      rotated_event_count: 0,
      last_rotation_at_seconds: null,
      last_rotated_sequence: null,
    })).toMatchObject({
      last_rotation_at_seconds: null,
      last_rotated_sequence: null,
    });
  });

  it.each([
    ['an extra key', () => ({ ...status(), database_path: '/private/audit.db' })],
    ['a missing key', () => without(status(), 'warning')],
    ['a negative count', () => ({ ...status(), current_events: -1 })],
    ['a fractional count', () => ({ ...status(), rotated_event_count: 1.5 })],
    ['an unsafe count', () => ({ ...status(), current_events: Number.MAX_SAFE_INTEGER + 1 })],
    ['a zero maximum', () => ({ ...status(), max_events: 0 })],
    ['an excessive maximum', () => ({ ...status(), max_events: 1_000_001 })],
    ['usage below zero', () => ({ ...status(), usage_percent: -1 })],
    ['usage above 100', () => ({ ...status(), usage_percent: 101 })],
    ['a non-boolean warning', () => ({ ...status(), warning: 1 })],
    ['a fractional rotation timestamp', () => ({ ...status(), last_rotation_at_seconds: 1.5 })],
    ['an inconsistent null pair', () => ({ ...status(), last_rotated_sequence: null })],
  ])('rejects %s without echoing response data', (_name, makeValue) => {
    expect(() => parseAuditStatus(makeValue())).toThrow('Invalid audit status response');
  });
});

describe('audit event page contract', () => {
  it('parses exact event/page keys into fresh values', () => {
    const rawEvent = event();
    const raw = { events: [rawEvent], next_cursor: null };

    const parsed = parseAuditEventPage(raw);

    expect(parsed).toEqual(raw);
    expect(parsed).not.toBe(raw);
    expect(parsed.events).not.toBe(raw.events);
    expect(parsed.events[0]).not.toBe(rawEvent);
  });

  it('accepts byte-bounded text and possibly empty detail and subject fields', () => {
    const bounded = {
      ...event(),
      event_type: '\u00e9'.repeat(32),
      actor_identity: 'a'.repeat(64),
      peer_ip: 'f'.repeat(45),
      detail_code: '',
      subject_type: '',
      subject_identity: '',
    };

    expect(parseAuditEventPage({ events: [bounded], next_cursor: 'AQID-_9' }))
      .toEqual({ events: [bounded], next_cursor: 'AQID-_9' });
  });

  it.each([
    ['an extra page key', () => ({ events: [event()], next_cursor: null, sql: 'private' })],
    ['a missing event key', () => ({ events: [without(event(), 'outcome')], next_cursor: null })],
    ['an extra event key', () => ({ events: [{ ...event(), actor_user_id: 7 }], next_cursor: null })],
    ['a negative sequence', () => ({ events: [{ ...event(), sequence: -1 }], next_cursor: null })],
    ['an unsafe timestamp', () => ({ events: [{ ...event(), server_timestamp_seconds: Number.MAX_SAFE_INTEGER + 1 }], next_cursor: null })],
    ['an invalid outcome', () => ({ events: [{ ...event(), outcome: 'partial' }], next_cursor: null })],
    ['an empty event type', () => ({ events: [{ ...event(), event_type: '' }], next_cursor: null })],
    ['an oversized multibyte event type', () => ({ events: [{ ...event(), event_type: '\u00e9'.repeat(33) }], next_cursor: null })],
    ['an empty actor identity', () => ({ events: [{ ...event(), actor_identity: '' }], next_cursor: null })],
    ['an oversized peer IP', () => ({ events: [{ ...event(), peer_ip: 'f'.repeat(46) }], next_cursor: null })],
    ['an oversized detail code', () => ({ events: [{ ...event(), detail_code: 'd'.repeat(65) }], next_cursor: null })],
    ['an embedded NUL', () => ({ events: [{ ...event(), subject_identity: 'viewer\0secret' }], next_cursor: null })],
    ['more than 100 events', () => ({ events: Array.from({ length: 101 }, event), next_cursor: null })],
    ['an empty cursor', () => ({ events: [event()], next_cursor: '' })],
    ['a padded cursor', () => ({ events: [event()], next_cursor: 'AQID=' })],
    ['an impossible base64url length', () => ({ events: [event()], next_cursor: 'A' })],
    ['an oversized cursor', () => ({ events: [event()], next_cursor: 'A'.repeat(513) })],
  ])('rejects %s without echoing response data', (_name, makeValue) => {
    expect(() => parseAuditEventPage(makeValue())).toThrow('Invalid audit event response');
  });
});

describe('audit event URL builder', () => {
  it('emits only approved fields through URLSearchParams with safe text encoding', () => {
    const query = {
      from_seconds: 0,
      to_seconds: 1_784_300_000,
      event_type: 'user enabled/disabled',
      outcome: 'failure',
      actor_identity: 'owner+east',
      peer_ip: '2001:db8::1',
      subject_type: 'user role',
      subject_identity: 'viewer+1/east',
      sort_by: 'event_type',
      sort_direction: 'asc',
      limit: 25,
      private_field: 'must-not-leak',
    } as AuditListQuery & { private_field: string };

    const url = buildAuditEventsUrl(query, 'AQID-_9');
    const parsed = new URL(url, 'https://camera.invalid');

    expect(parsed.pathname).toBe('/api/v1/audit/events');
    expect([...parsed.searchParams.keys()]).toEqual([
      'from_seconds', 'to_seconds', 'event_type', 'outcome', 'actor_identity',
      'peer_ip', 'subject_type', 'subject_identity', 'sort_by',
      'sort_direction', 'limit', 'cursor',
    ]);
    expect(parsed.searchParams.get('event_type')).toBe('user enabled/disabled');
    expect(parsed.searchParams.get('actor_identity')).toBe('owner+east');
    expect(parsed.searchParams.get('peer_ip')).toBe('2001:db8::1');
    expect(parsed.searchParams.get('subject_identity')).toBe('viewer+1/east');
    expect(parsed.searchParams.get('cursor')).toBe('AQID-_9');
    expect(url).toContain('peer_ip=2001%3Adb8%3A%3A1');
    expect(url).not.toContain('private');
  });

  it('omits undefined and empty filters plus an absent cursor', () => {
    const url = buildAuditEventsUrl({
      ...DEFAULT_AUDIT_LIST_QUERY,
      event_type: '',
      actor_identity: undefined,
      peer_ip: '',
      subject_type: '',
      subject_identity: '',
    });

    expect(url).toBe(
      '/api/v1/audit/events?sort_by=timestamp&sort_direction=desc&limit=50',
    );
  });

  it('does not emit an empty optional cursor', () => {
    expect(buildAuditEventsUrl(DEFAULT_AUDIT_LIST_QUERY, '')).toBe(
      '/api/v1/audit/events?sort_by=timestamp&sort_direction=desc&limit=50',
    );
  });
});
