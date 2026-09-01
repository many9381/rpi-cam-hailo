import { useTranslation, type Lang } from '../i18n/LanguageContext';

const OPTIONS: { lang: Lang; labelKey: string }[] = [
  { lang: 'en', labelKey: 'language.english' },
  { lang: 'ko', labelKey: 'language.korean' },
];

export function LanguageSwitcher() {
  const { lang, setLang, t } = useTranslation();
  return (
    <div className="language-switcher" role="group" aria-label={t('language.label')}>
      {OPTIONS.map(({ lang: option, labelKey }) => (
        <button
          key={option}
          type="button"
          className={option === lang ? 'lang-btn active' : 'lang-btn'}
          aria-pressed={option === lang}
          onClick={() => setLang(option)}
        >
          {t(labelKey)}
        </button>
      ))}
    </div>
  );
}
