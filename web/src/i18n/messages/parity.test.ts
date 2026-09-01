import { expect, test } from 'vitest';

import { en } from './en';
import { ko } from './ko';

function keyPaths(obj: Record<string, unknown>, prefix = ''): string[] {
  return Object.entries(obj).flatMap(([k, v]) => {
    const path = prefix ? `${prefix}.${k}` : k;
    return v && typeof v === 'object'
      ? keyPaths(v as Record<string, unknown>, path)
      : [path];
  });
}

test('ko has exactly the same keys as en', () => {
  expect(keyPaths(ko).sort()).toEqual(keyPaths(en).sort());
});
