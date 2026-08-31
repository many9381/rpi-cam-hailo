import { type FormEvent, useState } from 'react';

import { LanguageSwitcher } from '../components/LanguageSwitcher';
import { useTranslation } from '../i18n/LanguageContext';

export interface InitialCredential {
  username: string;
  password: string;
}

interface LoginPageProps {
  login(username: string, password: string): Promise<void>;
  initialCredential?: InitialCredential | null;
}

export function LoginPage({ login, initialCredential = null }: LoginPageProps) {
  const { t } = useTranslation();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [failure, setFailure] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setFailure(null);
    setSubmitting(true);
    try {
      await login(username, password);
    } catch {
      setFailure(t('auth.signInFailed'));
    } finally {
      setPassword('');
      setSubmitting(false);
    }
  };

  return (
    <main className="auth-surface">
      <LanguageSwitcher />
      <section className="auth-panel" aria-labelledby="login-heading">
        <div className="brand-mark" aria-hidden="true">{t('common.brandShort')}</div>
        <h1 id="login-heading">{t('auth.loginHeading')}</h1>
        <form className="auth-form" onSubmit={submit} noValidate>
          <div className="field">
            <label htmlFor="login-username">{t('common.username')}</label>
            <input
              id="login-username"
              name="username"
              autoComplete="username"
              value={username}
              required
              onChange={(event) => setUsername(event.target.value)}
            />
          </div>
          <div className="field">
            <label htmlFor="login-password">{t('common.password')}</label>
            <input
              id="login-password"
              name="password"
              type="password"
              autoComplete="current-password"
              value={password}
              required
              onChange={(event) => setPassword(event.target.value)}
            />
          </div>
          {failure && <p className="form-error" role="alert">{failure}</p>}
          <button className="primary-button" type="submit" disabled={submitting}>
            {submitting ? t('auth.signingIn') : t('auth.signIn')}
          </button>
        </form>
      </section>
      {initialCredential && (
        <section
          className="auth-panel initial-credential-panel"
          aria-labelledby="initial-credential-heading"
        >
          <h2 id="initial-credential-heading">{t('auth.initialSetupHeading')}</h2>
          <p>
            {t('auth.initialSetupDescription')}
          </p>
          <dl className="initial-credential-list">
            <div className="initial-credential-row">
              <dt>{t('common.username')}</dt>
              <dd>{initialCredential.username}</dd>
            </div>
            <div className="initial-credential-row">
              <dt>{t('common.password')}</dt>
              <dd>{initialCredential.password}</dd>
            </div>
          </dl>
        </section>
      )}
    </main>
  );
}
