import { cleanup, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, expect, test } from 'vitest';

import { LanguageProvider } from '../i18n/LanguageContext';
import { LanguageSwitcher } from './LanguageSwitcher';

beforeEach(() => { try { localStorage.clear(); } catch { /* ignore */ } });
afterEach(cleanup);

function renderSwitcher() {
  return render(<LanguageProvider><LanguageSwitcher /></LanguageProvider>);
}

test('shows English active by default', () => {
  renderSwitcher();
  expect(screen.getByRole('button', { name: 'English' })).toHaveAttribute('aria-pressed', 'true');
  expect(screen.getByRole('button', { name: '한국어' })).toHaveAttribute('aria-pressed', 'false');
});

test('clicking 한국어 switches and persists', async () => {
  const user = userEvent.setup();
  renderSwitcher();
  await user.click(screen.getByRole('button', { name: '한국어' }));
  expect(screen.getByRole('button', { name: '한국어' })).toHaveAttribute('aria-pressed', 'true');
  expect(localStorage.getItem('cf.lang')).toBe('ko');
});
