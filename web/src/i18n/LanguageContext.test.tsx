import { render, screen, act, cleanup } from '@testing-library/react';
import { afterEach, beforeEach, expect, test } from 'vitest';

import { LanguageProvider, useTranslation } from './LanguageContext';

function Probe() {
  const { t, lang, setLang } = useTranslation();
  return (
    <div>
      <span data-testid="lang">{lang}</span>
      <span data-testid="known">{t('common.save')}</span>
      <span data-testid="interp">{t('test.greeting', { name: 'Kim' })}</span>
      <span data-testid="missing">{t('does.not.exist')}</span>
      <button onClick={() => setLang('ko')}>ko</button>
      <button onClick={() => setLang('en')}>en</button>
    </div>
  );
}

beforeEach(() => { try { localStorage.clear(); } catch { /* ignore */ } });
afterEach(cleanup);

test('defaults to English and looks up keys', () => {
  render(<LanguageProvider><Probe /></LanguageProvider>);
  expect(screen.getByTestId('lang').textContent).toBe('en');
  expect(screen.getByTestId('known').textContent).toBe('Save');
});

test('interpolates variables', () => {
  render(<LanguageProvider><Probe /></LanguageProvider>);
  expect(screen.getByTestId('interp').textContent).toBe('Hello, Kim');
});

test('returns the key itself for a missing key', () => {
  render(<LanguageProvider><Probe /></LanguageProvider>);
  expect(screen.getByTestId('missing').textContent).toBe('does.not.exist');
});

test('switching language updates text and persists to localStorage', () => {
  render(<LanguageProvider><Probe /></LanguageProvider>);
  act(() => { screen.getByText('ko').click(); });
  expect(screen.getByTestId('lang').textContent).toBe('ko');
  expect(screen.getByTestId('known').textContent).toBe('저장');
  expect(localStorage.getItem('cf.lang')).toBe('ko');
  expect(document.documentElement.lang).toBe('ko');
});

test('reads the initial language from localStorage', () => {
  localStorage.setItem('cf.lang', 'ko');
  render(<LanguageProvider><Probe /></LanguageProvider>);
  expect(screen.getByTestId('lang').textContent).toBe('ko');
});
