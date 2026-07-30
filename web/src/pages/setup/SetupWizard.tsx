import { useState } from 'react';

import { parseInitializeResult } from '../../api/contracts';
import type { CameraApiClient } from '../../api/types';
import { SetupCredentialsStep } from './SetupCredentialsStep';
import { SetupIpStep } from './SetupIpStep';
import { SetupReviewStep } from './SetupReviewStep';

export interface SetupWizardProps {
  client: CameraApiClient;
  peerIp: string;
  onInitialized: () => void;
  onInitializationFailed?: () => Promise<boolean>;
}

type WizardStep = 'credentials' | 'ip' | 'review';

const GENERIC_FAILURE =
  'Camera initialization failed. Check the credentials and try again.';

/**
 * Owns every value collected across the three setup steps and performs the
 * single submission to /api/v1/setup/initialize: username, password, and
 * peer_ip (unchanged from before this session requirement was added; see
 * src/service/ServiceApp.cpp and SecurityRequestGate::ParseSetupJson), plus
 * management_ips — the additional single hosts collected in step 2. The
 * confirming peer is registered unconditionally by the server before it
 * reads that list (SecurityStore::InitializeDevice), so it is never
 * included in `hosts` here. Steps are client state only: no request is
 * sent until review submits.
 */
export function SetupWizard({
  client,
  peerIp,
  onInitialized,
  onInitializationFailed = async () => false,
}: SetupWizardProps) {
  const [step, setStep] = useState<WizardStep>('credentials');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [hosts, setHosts] = useState<string[]>([]);
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
        { username, password, peer_ip: peerIp, management_ips: hosts },
        parseInitializeResult,
      );
      // Cleared before notifying the caller, not after: the plaintext has
      // done its job and nothing downstream needs it, matching LoginPage's
      // same practice of never letting a submitted password outlive its
      // request.
      setPassword('');
      setConfirmation('');
      onInitialized();
    } catch {
      setPassword('');
      setConfirmation('');
      const advanced = await onInitializationFailed();
      if (!advanced) {
        setStep('credentials');
        setFailure(GENERIC_FAILURE);
      }
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <main className="auth-surface">
      <section className="auth-panel wizard-panel" aria-labelledby="wizard-heading">
        <div className="brand-mark" aria-hidden="true">CF</div>
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
