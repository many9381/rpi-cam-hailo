import { describe, expect, it } from 'vitest';

import { validateSetupCredentials } from './setupPolicy';

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

  it('rejects a password equal to the username without enforcing server-only policy', () => {
    expect(validateSetupCredentials('Operator!9', 'Operator!9', 'Operator!9'))
      .toMatchObject({ password: 'Password must differ from the username.' });
    expect(validateSetupCredentials('admin.user', 'ReserveMe!9', 'ReserveMe!9'))
      .toEqual({});
    expect(validateSetupCredentials('operator.one', 'Repeeat!999', 'Repeeat!999'))
      .toEqual({});
  });

  it('reports password confirmation mismatch with a stable confirmation key', () => {
    expect(validateSetupCredentials('operator.one', 'NorthStar!9', 'Different!9'))
      .toMatchObject({ confirmation: 'Passwords do not match.' });
  });
});
