import { describe, expect, it } from 'vitest';

import {
  parseProtectionSnapshot,
  type ProtectionSnapshot,
  type ProtectionSuiteResult,
} from './contracts';

const selfTest = (): ProtectionSuiteResult => ({
  suite: 'self_test',
  trigger: 'startup',
  passed: true,
  started_at_seconds: 1_721_358_300,
  finished_at_seconds: 1_721_358_301,
  items: [{ id: 'crypto.sha256', category: null, passed: true, code: 'OK' }],
});

const integrity = (): ProtectionSuiteResult => ({
  suite: 'integrity',
  trigger: 'periodic',
  passed: false,
  started_at_seconds: 1_721_358_400,
  finished_at_seconds: 1_721_358_402,
  items: [{ id: 'kernel', category: 'kernel', passed: false, code: 'E_INTEGRITY_MISMATCH' }],
});

const snapshot = (): ProtectionSnapshot => ({
  state: 'operational',
  check_running: false,
  next_periodic_at_seconds: 1_721_444_800,
  self_test: selfTest(),
  integrity: integrity(),
});

const without = (value: object, key: string) => {
  const copy: Record<string, unknown> = { ...value };
  delete copy[key];
  return copy;
};

describe('system protection contract', () => {
  it('parses an exact snapshot into fresh nested values', () => {
    const raw = snapshot();

    const parsed = parseProtectionSnapshot(raw);

    expect(parsed).toEqual(raw);
    expect(parsed).not.toBe(raw);
    expect(parsed.self_test).not.toBe(raw.self_test);
    expect(parsed.self_test?.items).not.toBe(raw.self_test?.items);
    expect(parsed.self_test?.items[0]).not.toBe(raw.self_test?.items[0]);
  });

  it('accepts item ids and codes at the UTF-8 byte boundary', () => {
    const bounded = '\u00e9'.repeat(32);

    expect(parseProtectionSnapshot({
      ...snapshot(),
      self_test: { ...selfTest(), items: [{
        id: bounded, category: null, passed: true, code: bounded,
      }] },
    }).self_test?.items[0]).toMatchObject({ id: bounded, code: bounded });
  });

  it.each(['restricted', 'operational'] as const)(
    'accepts a running check after the native state becomes %s',
    (state) => {
      expect(parseProtectionSnapshot({
        ...snapshot(), state, check_running: true,
      })).toMatchObject({ state, check_running: true });
    },
  );

  it.each([
    ['an extra snapshot key', () => ({ ...snapshot(), private_detail: '/private/hash' })],
    ['a missing snapshot key', () => without(snapshot(), 'integrity')],
    ['an unsafe periodic timestamp', () => ({
      ...snapshot(), next_periodic_at_seconds: Number.MAX_SAFE_INTEGER + 1,
    })],
    ['a fractional suite timestamp', () => ({
      ...snapshot(), self_test: { ...selfTest(), started_at_seconds: 1.5 },
    })],
    ['a negative suite timestamp', () => ({
      ...snapshot(), integrity: { ...integrity(), finished_at_seconds: -1 },
    })],
    ['an unknown state', () => ({ ...snapshot(), state: 'starting' })],
    ['an unknown suite', () => ({ ...snapshot(), self_test: { ...selfTest(), suite: 'startup' } })],
    ['an unknown trigger', () => ({ ...snapshot(), integrity: { ...integrity(), trigger: 'automatic' } })],
    ['a non-running checking state after results exist', () => ({
      ...snapshot(), state: 'checking', check_running: false,
    })],
    ['a non-running initial checking state', () => ({
      ...snapshot(), state: 'checking', check_running: false,
      next_periodic_at_seconds: 0, self_test: null, integrity: null,
    })],
    ['an extra suite key', () => ({ ...snapshot(), self_test: { ...selfTest(), detail: 'private' } })],
    ['a missing item key', () => ({
      ...snapshot(), self_test: { ...selfTest(), items: [without(selfTest().items[0], 'code')] },
    })],
    ['an extra item key', () => ({
      ...snapshot(), integrity: { ...integrity(), items: [{ ...integrity().items[0], path: '/private' }] },
    })],
    ['an invalid integrity category', () => ({
      ...snapshot(), integrity: { ...integrity(), items: [{ ...integrity().items[0], category: 'bootloader' }] },
    })],
    ['an integrity item without a category', () => ({
      ...snapshot(), integrity: { ...integrity(), items: [{ ...integrity().items[0], category: null }] },
    })],
    ['a self-test item with an integrity category', () => ({
      ...snapshot(), self_test: { ...selfTest(), items: [{ ...selfTest().items[0], category: 'firmware' }] },
    })],
    ['an oversized UTF-8 item id', () => ({
      ...snapshot(), self_test: { ...selfTest(), items: [{
        ...selfTest().items[0], id: '\u00e9'.repeat(33),
      }] },
    })],
    ['an oversized item code', () => ({
      ...snapshot(), integrity: { ...integrity(), items: [{
        ...integrity().items[0], code: 'x'.repeat(65),
      }] },
    })],
    ['more than 4096 items', () => ({
      ...snapshot(), self_test: { ...selfTest(), items: Array.from({ length: 4097 }, () => selfTest().items[0]) },
    })],
  ])('rejects %s without echoing response data', (_name, makeValue) => {
    expect(() => parseProtectionSnapshot(makeValue())).toThrow(
      'Invalid system protection response',
    );
  });
});
