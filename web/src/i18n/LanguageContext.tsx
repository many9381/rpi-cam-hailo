import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react';

import { en, type Messages } from './messages/en';
import { ko } from './messages/ko';

export type Lang = 'en' | 'ko';

const DICTIONARIES: Record<Lang, Messages> = { en, ko };
const STORAGE_KEY = 'cf.lang';

function readInitialLang(): Lang {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored === 'en' || stored === 'ko') {
      return stored;
    }
  } catch {
    /* localStorage unavailable — fall through to default */
  }
  return 'en';
}

function lookup(dict: Messages, key: string): string | undefined {
  const value = key.split('.').reduce<unknown>((acc, part) => {
    if (acc && typeof acc === 'object') {
      return (acc as Record<string, unknown>)[part];
    }
    return undefined;
  }, dict);
  return typeof value === 'string' ? value : undefined;
}

type Translate = (key: string, vars?: Record<string, string | number>) => string;

interface LanguageContextValue {
  lang: Lang;
  setLang: (lang: Lang) => void;
  t: Translate;
}

const LanguageContext = createContext<LanguageContextValue | null>(null);

export function LanguageProvider({ children }: { children: ReactNode }) {
  const [lang, setLangState] = useState<Lang>(readInitialLang);

  useEffect(() => {
    try {
      document.documentElement.lang = lang;
    } catch {
      /* SSR/test env without document — ignore */
    }
  }, [lang]);

  const setLang = useCallback((next: Lang) => {
    setLangState(next);
    try {
      localStorage.setItem(STORAGE_KEY, next);
    } catch {
      /* persistence best-effort */
    }
  }, []);

  const t = useCallback<Translate>(
    (key, vars) => {
      let text = lookup(DICTIONARIES[lang], key);
      if (text === undefined) {
        text = lookup(en, key); // English fallback
      }
      if (text === undefined) {
        return key; // last resort: the key itself
      }
      if (vars) {
        for (const [name, value] of Object.entries(vars)) {
          // split/join replaces every occurrence, same as String#replaceAll
          // with a literal (non-regex) search string — kept lib-ES2020 safe.
          text = text.split(`{${name}}`).join(String(value));
        }
      }
      return text;
    },
    [lang],
  );

  const value = useMemo(() => ({ lang, setLang, t }), [lang, setLang, t]);

  return (
    <LanguageContext.Provider value={value}>
      {children}
    </LanguageContext.Provider>
  );
}

export function useTranslation(): LanguageContextValue {
  const ctx = useContext(LanguageContext);
  if (ctx === null) {
    throw new Error('useTranslation must be used within a LanguageProvider');
  }
  return ctx;
}
