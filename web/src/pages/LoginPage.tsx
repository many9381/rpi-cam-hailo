import { type FormEvent, useState } from 'react';

import { LanguageSwitcher } from '../components/LanguageSwitcher';

export interface InitialCredential {
  username: string;
  password: string;
}

interface LoginPageProps {
  login(username: string, password: string): Promise<void>;
  initialCredential?: InitialCredential | null;
}

const GENERIC_FAILURE = 'Sign in failed. Check your credentials and try again.';

export function LoginPage({ login, initialCredential = null }: LoginPageProps) {
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
      setFailure(GENERIC_FAILURE);
    } finally {
      setPassword('');
      setSubmitting(false);
    }
  };

  return (
    <main className="auth-surface">
      <LanguageSwitcher />
      <section className="auth-panel" aria-labelledby="login-heading">
        <div className="brand-mark" aria-hidden="true">CF</div>
        <h1 id="login-heading">Camera login</h1>
        <form className="auth-form" onSubmit={submit} noValidate>
          <div className="field">
            <label htmlFor="login-username">Username</label>
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
            <label htmlFor="login-password">Password</label>
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
            {submitting ? 'Signing in...' : 'Sign in'}
          </button>
        </form>
      </section>
      {initialCredential && (
        <section
          className="auth-panel initial-credential-panel"
          aria-labelledby="initial-credential-heading"
        >
          <h2 id="initial-credential-heading">Initial setup account</h2>
          <p>
            This account is for initial setup only and is removed once setup
            completes.
          </p>
          <dl className="initial-credential-list">
            <div className="initial-credential-row">
              <dt>Username</dt>
              <dd>{initialCredential.username}</dd>
            </div>
            <div className="initial-credential-row">
              <dt>Password</dt>
              <dd>{initialCredential.password}</dd>
            </div>
          </dl>
        </section>
      )}
    </main>
  );
}
