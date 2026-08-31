// @ts-expect-error Vitest provides Node built-ins outside the browser bundle.
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

import {
  evaluatePasswordRequirements,
  validateSetupCredentials,
  type PasswordRequirementId,
} from './setupPolicy';

// Shared with tests/unit/security/PasswordPolicyTest.cpp: both suites read
// this one file so the server's password policy (src/security/PasswordPolicy.cpp)
// and this browser mirror cannot drift apart again without a test failing.
interface PasswordVector {
  username: string;
  password: string;
  accept: boolean;
  rule?: PasswordRequirementId;
}

const sharedVectors: PasswordVector[] = JSON.parse(
  readFileSync('../tests/data/password-policy-vectors.json', 'utf8'),
).vectors;

describe('validateSetupCredentials', () => {
  it('accepts credentials that meet the client-side policy', () => {
    expect(validateSetupCredentials(
      'operator.one',
      'NorthStar!9',
      'NorthStar!9',
    )).toEqual({});
    expect(validateSetupCredentials(
      'operator.one',
      'Aa!5bcDef',
      'Aa!5bcDef',
    )).toEqual({});
  });

  it.each([
    ['four', 'Username must be 5 to 32 characters.'],
    ['1operator', 'Username must begin with an ASCII letter.'],
    ['operator name', 'Username may contain only ASCII letters, numbers, periods, underscores, and hyphens.'],
  ])('reports username policy feedback for %s', (username, message) => {
    expect(validateSetupCredentials(username, 'NorthStar!9', 'NorthStar!9'))
      .toMatchObject({ username: message });
  });

  it.each([
    ['Short!9A', 'Password must be 9 to 128 characters.'],
    ['North Star!9', 'Password must use printable, non-space ASCII characters.'],
    ['northstar!9', 'Password must include uppercase, lowercase, number, and special characters.'],
    ['NORTHSTAR!9', 'Password must include uppercase, lowercase, number, and special characters.'],
    ['NorthStar!!', 'Password must include uppercase, lowercase, number, and special characters.'],
    ['NorthStar99', 'Password must include uppercase, lowercase, number, and special characters.'],
  ])('reports password policy feedback without echoing the secret', (password, message) => {
    const result = validateSetupCredentials('operator.one', password, password);

    expect(result).toMatchObject({ password: message });
    expect(JSON.stringify(result)).not.toContain(password);
  });

  it('rejects a password equal to the username, while reserved usernames stay server-only', () => {
    expect(validateSetupCredentials('Operator!9', 'Operator!9', 'Operator!9'))
      .toMatchObject({ password: 'Password must differ from the username.' });
    // Reserved/guessable usernames (e.g. "admin.user") are only rejected by
    // the server's ValidateInitialUsername; the client does not mirror that
    // list, so this is expected to pass client-side validation.
    expect(validateSetupCredentials('admin.user', 'ReserveMe!9', 'ReserveMe!9'))
      .toEqual({});
  });

  it.each([
    ['Repeeat!999', 'Password must not repeat a letter or number three times in a row.'],
    ['NorthQwer!9', 'Password must not contain a keyboard sequence.'],
  ])('reports the repeat and sequence policy that used to only be enforced server-side for %s', (password, message) => {
    expect(validateSetupCredentials('operator.one', password, password))
      .toMatchObject({ password: message });
  });

  it('reports password confirmation mismatch with a stable confirmation key', () => {
    expect(validateSetupCredentials('operator.one', 'NorthStar!9', 'Different!9'))
      .toMatchObject({ confirmation: 'Passwords do not match.' });
  });
});

describe('evaluatePasswordRequirements', () => {
  it('returns one entry per condition with a stable id', () => {
    const requirements = evaluatePasswordRequirements('operator.one', 'NorthStar!9');

    expect(requirements.map((requirement) => requirement.id)).toEqual([
      'length', 'charset', 'uppercase', 'lowercase', 'digit',
      'special', 'username', 'repeat', 'sequence',
    ]);
    expect(requirements.every((requirement) => requirement.met)).toBe(true);
  });

  it('flags the repeat and sequence conditions the same way the server does', () => {
    const repeated = evaluatePasswordRequirements('operator.one', 'NorthStaaar!9');
    expect(repeated.find((requirement) => requirement.id === 'repeat')?.met).toBe(false);

    const sequential = evaluatePasswordRequirements('operator.one', 'NorthQwer!9');
    expect(sequential.find((requirement) => requirement.id === 'sequence')?.met).toBe(false);

    // Runs of repeated special characters are explicitly allowed: the C++
    // HasRepeatedLetterOrDigit rule only covers ASCII letters and digits.
    const repeatedSpecials = evaluatePasswordRequirements('operator.one', 'Abc!!!!9xy');
    expect(repeatedSpecials.find((requirement) => requirement.id === 'repeat')?.met).toBe(true);
  });

  it('reaches the same verdict as the server on every shared vector', () => {
    expect(sharedVectors.length).toBeGreaterThan(0);

    for (const vector of sharedVectors) {
      const requirements = evaluatePasswordRequirements(vector.username, vector.password);
      const accepted = requirements.every((requirement) => requirement.met);

      expect(accepted).toBe(vector.accept);

      if (!vector.accept && vector.rule) {
        const requirement = requirements.find((entry) => entry.id === vector.rule);
        expect(requirement).toBeDefined();
        expect(requirement?.met).toBe(false);
      }
    }
  });
});
