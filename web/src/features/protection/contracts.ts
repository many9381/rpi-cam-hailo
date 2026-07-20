export type ProtectionState = 'checking' | 'operational' | 'restricted';
export type ProtectionSuite = 'self_test' | 'integrity';
export type ProtectionTrigger = 'startup' | 'manual' | 'periodic';
export type IntegrityCategory =
  | 'firmware'
  | 'library'
  | 'configuration'
  | 'web_asset'
  | 'kernel'
  | 'kernel_module';

export interface ProtectionItemResult {
  id: string;
  category: IntegrityCategory | null;
  passed: boolean;
  code: string;
}

export interface ProtectionSuiteResult {
  suite: ProtectionSuite;
  trigger: ProtectionTrigger;
  passed: boolean;
  started_at_seconds: number;
  finished_at_seconds: number;
  items: ProtectionItemResult[];
}

export interface ProtectionSnapshot {
  state: ProtectionState;
  check_running: boolean;
  next_periodic_at_seconds: number;
  self_test: ProtectionSuiteResult | null;
  integrity: ProtectionSuiteResult | null;
}

const snapshotKeys = [
  'state',
  'check_running',
  'next_periodic_at_seconds',
  'self_test',
  'integrity',
] as const;

const suiteKeys = [
  'suite',
  'trigger',
  'passed',
  'started_at_seconds',
  'finished_at_seconds',
  'items',
] as const;

const itemKeys = ['id', 'category', 'passed', 'code'] as const;
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

const isBoundedText = (value: unknown): value is string =>
  typeof value === 'string' && !value.includes('\0') && encoder.encode(value).length <= 64;

const isState = (value: unknown): value is ProtectionState =>
  value === 'checking' || value === 'operational' || value === 'restricted';

const isTrigger = (value: unknown): value is ProtectionTrigger =>
  value === 'startup' || value === 'manual' || value === 'periodic';

const isIntegrityCategory = (value: unknown): value is IntegrityCategory =>
  value === 'firmware' || value === 'library' || value === 'configuration' ||
  value === 'web_asset' || value === 'kernel' || value === 'kernel_module';

function invalidResponse(): never {
  throw new Error('Invalid system protection response');
}

function parseItem(
  value: unknown,
  suite: ProtectionSuite,
): ProtectionItemResult {
  if (!hasExactKeys(value, itemKeys) || !isBoundedText(value.id) ||
      typeof value.passed !== 'boolean' || !isBoundedText(value.code)) {
    return invalidResponse();
  }
  let category: IntegrityCategory | null;
  if (suite === 'self_test') {
    if (value.category !== null) {
      return invalidResponse();
    }
    category = null;
  } else {
    if (!isIntegrityCategory(value.category)) {
      return invalidResponse();
    }
    category = value.category;
  }
  return {
    id: value.id,
    category,
    passed: value.passed,
    code: value.code,
  };
}

function parseSuite(
  value: unknown,
  expectedSuite: ProtectionSuite,
): ProtectionSuiteResult {
  if (!hasExactKeys(value, suiteKeys) || value.suite !== expectedSuite ||
      !isTrigger(value.trigger) || typeof value.passed !== 'boolean' ||
      !isSafeNonnegativeInteger(value.started_at_seconds) ||
      !isSafeNonnegativeInteger(value.finished_at_seconds) ||
      !Array.isArray(value.items) || value.items.length > 4096) {
    return invalidResponse();
  }
  return {
    suite: expectedSuite,
    trigger: value.trigger,
    passed: value.passed,
    started_at_seconds: value.started_at_seconds,
    finished_at_seconds: value.finished_at_seconds,
    items: value.items.map((item) => parseItem(item, expectedSuite)),
  };
}

const parseNullableSuite = (
  value: unknown,
  expectedSuite: ProtectionSuite,
): ProtectionSuiteResult | null => value === null ? null : parseSuite(value, expectedSuite);

export function parseProtectionSnapshot(value: unknown): ProtectionSnapshot {
  if (!hasExactKeys(value, snapshotKeys) || !isState(value.state) ||
      typeof value.check_running !== 'boolean' ||
      !isSafeNonnegativeInteger(value.next_periodic_at_seconds)) {
    return invalidResponse();
  }

  const selfTest = parseNullableSuite(value.self_test, 'self_test');
  const integrity = parseNullableSuite(value.integrity, 'integrity');
  if (value.state === 'checking' && !value.check_running) {
    return invalidResponse();
  }

  return {
    state: value.state,
    check_running: value.check_running,
    next_periodic_at_seconds: value.next_periodic_at_seconds,
    self_test: selfTest,
    integrity,
  };
}
