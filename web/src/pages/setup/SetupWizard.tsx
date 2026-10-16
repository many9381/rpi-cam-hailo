import { useState } from 'react';

import { parseInitializeResult } from '../../api/contracts';
import type { CameraApiClient } from '../../api/types';
import { useTranslation } from '../../i18n/LanguageContext';
import { SetupCredentialsStep } from './SetupCredentialsStep';
import { SetupIpStep } from './SetupIpStep';
import { SetupReviewStep } from './SetupReviewStep';
import { setupErrorMessage } from './publicError';

export interface SetupWizardProps {
  client: CameraApiClient;
  peerIp: string;
  onInitialized: () => void;
  onInitializationFailed?: (error: unknown) => Promise<boolean>;
}

type WizardStep = 'credentials' | 'ip' | 'review';

/** Collects setup choices locally and submits them once at review. */
export function SetupWizard({
  client,
  peerIp,
  onInitialized,
  onInitializationFailed = async () => false,
}: SetupWizardProps) {
  const { t } = useTranslation();
  const [step, setStep] = useState<WizardStep>('credentials');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [hosts, setHosts] = useState<string[]>([]);
  const [restrictionEnabled, setRestrictionEnabled] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const addHost = (host: string) => {
    setHosts((current) => [...current, host]);
  };

  const submit = async () => {
    setFailure(null);
    setSubmitting(true);
    try {
      await client.postJson(
        '/api/v1/setup/initialize',
        {
          username,
          password,
          peer_ip: peerIp,
          management_ip_restriction_enabled: restrictionEnabled,
          management_ips: restrictionEnabled ? hosts : [],
        },
        parseInitializeResult,
      );
      // Cleared before notifying the caller, not after: the plaintext has
      // done its job and nothing downstream needs it, matching LoginPage's
      // same practice of never letting a submitted password outlive its
      // request.
      setPassword('');
      setConfirmation('');
      onInitialized();
    } catch (error) {
      setPassword('');
      setConfirmation('');
      const advanced = await onInitializationFailed(error);
      if (!advanced) {
        setStep('credentials');
        setFailure(setupErrorMessage(error, t));
      }
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <main className="auth-surface">
      <section className="auth-panel wizard-panel" aria-labelledby="wizard-heading">
        <div className="brand-mark" aria-hidden="true">{t('common.brandShort')}</div>
        {step === 'credentials' && (
          <SetupCredentialsStep
            username={username}
            password={password}
            confirmation={confirmation}
            onUsernameChange={setUsername}
            onPasswordChange={setPassword}
            onConfirmationChange={setConfirmation}
            onNext={() => setStep('ip')}
          />
        )}
        {step === 'ip' && (
          <SetupIpStep
            peerIp={peerIp}
            hosts={hosts}
            restrictionEnabled={restrictionEnabled}
            onRestrictionChange={setRestrictionEnabled}
            onAddHost={addHost}
            onBack={() => setStep('credentials')}
            onNext={() => setStep('review')}
          />
        )}
        {step === 'review' && (
          <SetupReviewStep
            username={username}
            password={password}
            peerIp={peerIp}
            hosts={hosts}
            restrictionEnabled={restrictionEnabled}
            submitting={submitting}
            onBack={() => setStep('ip')}
            onSubmit={() => { void submit(); }}
          />
        )}
        {failure && <p className="form-error" role="alert">{failure}</p>}
      </section>
    </main>
  );
}
