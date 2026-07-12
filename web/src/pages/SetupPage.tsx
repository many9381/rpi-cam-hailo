import { type FormEvent, useState } from 'react';

import { parseInitializeResult } from '../api/contracts';
import type { CameraApiClient } from '../api/types';
import {
  type SetupCredentialErrors,
  validateSetupCredentials,
} from '../security/setupPolicy';

interface SetupPageProps {
  client: CameraApiClient;
  peerIp: string;
  onInitialized: () => void;
  onInitializationFailed?: () => Promise<boolean>;
}

const GENERIC_FAILURE =
  'Camera initialization failed. Check the credentials and try again.';

export function SetupPage({
  client,
  peerIp,
  onInitialized,
  onInitializationFailed = async () => false,
}: SetupPageProps) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [errors, setErrors] = useState<SetupCredentialErrors>({});
  const [failure, setFailure] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const validation = validateSetupCredentials(username, password, confirmation);
    setErrors(validation);
    setFailure(null);
    if (Object.keys(validation).length > 0) {
      return;
    }

    setSubmitting(true);
    try {
      await client.postJson(
        '/api/v1/setup/initialize',
        { username, password, peer_ip: peerIp },
        parseInitializeResult,
      );
      onInitialized();
    } catch {
      setPassword('');
      setConfirmation('');
      const advanced = await onInitializationFailed();
      if (!advanced) {
        setFailure(GENERIC_FAILURE);
      }
    } finally {
      setPassword('');
      setConfirmation('');
      setSubmitting(false);
    }
  };

  return (
    <main>
      <h1>Create administrator</h1>
      <form onSubmit={submit} noValidate>
        <div>
          <label htmlFor="setup-peer-ip">Management peer address</label>
          <input id="setup-peer-ip" value={peerIp} readOnly />
        </div>
        <div>
          <label htmlFor="setup-username">Username</label>
          <input
            id="setup-username"
            name="username"
            autoComplete="username"
            value={username}
            aria-describedby={errors.username ? 'setup-username-error' : undefined}
            aria-invalid={errors.username ? true : undefined}
            onChange={(event) => setUsername(event.target.value)}
          />
          {errors.username && <p id="setup-username-error">{errors.username}</p>}
        </div>
        <div>
          <label htmlFor="setup-password">Password</label>
          <input
            id="setup-password"
            name="password"
            type="password"
            autoComplete="new-password"
            minLength={9}
            maxLength={128}
            value={password}
            aria-describedby={errors.password ? 'setup-password-error' : undefined}
            aria-invalid={errors.password ? true : undefined}
            onChange={(event) => setPassword(event.target.value)}
          />
          {errors.password && <p id="setup-password-error">{errors.password}</p>}
        </div>
        <div>
          <label htmlFor="setup-confirmation">Confirm password</label>
          <input
            id="setup-confirmation"
            name="confirmation"
            type="password"
            autoComplete="new-password"
            minLength={9}
            maxLength={128}
            value={confirmation}
            aria-describedby={errors.confirmation ? 'setup-confirmation-error' : undefined}
            aria-invalid={errors.confirmation ? true : undefined}
            onChange={(event) => setConfirmation(event.target.value)}
          />
          {errors.confirmation && (
            <p id="setup-confirmation-error">{errors.confirmation}</p>
          )}
        </div>
        {failure && <p role="alert">{failure}</p>}
        <button type="submit" disabled={submitting}>
          {submitting ? 'Initializing camera...' : 'Initialize camera'}
        </button>
      </form>
    </main>
  );
}
