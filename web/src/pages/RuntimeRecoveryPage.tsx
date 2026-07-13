import { useState } from 'react';

import { parseInitializeResult } from '../api/contracts';
import type { CameraApiClient } from '../api/types';

interface RuntimeRecoveryPageProps {
  client: CameraApiClient;
  peerIp: string;
  onStarted(): void;
  onStartFailed(): Promise<boolean>;
}

export function RuntimeRecoveryPage({
  client,
  peerIp,
  onStarted,
  onStartFailed,
}: RuntimeRecoveryPageProps) {
  const [submitting, setSubmitting] = useState(false);
  const [failed, setFailed] = useState(false);

  const start = async () => {
    setSubmitting(true);
    setFailed(false);
    try {
      await client.postJson(
        '/api/v1/setup/runtime',
        {},
        parseInitializeResult,
      );
      onStarted();
    } catch {
      const advanced = await onStartFailed();
      if (!advanced) {
        setFailed(true);
      }
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <main className="auth-surface">
      <section className="auth-panel" aria-labelledby="runtime-recovery-heading">
        <div className="brand-mark" aria-hidden="true">CF</div>
        <h1 id="runtime-recovery-heading">Start camera runtime</h1>
        <div className="auth-form">
          <div className="field">
            <label htmlFor="runtime-peer-ip">Management peer address</label>
            <input id="runtime-peer-ip" value={peerIp} readOnly />
          </div>
          {failed && (
            <p className="form-error" role="alert">
              Camera runtime could not be started. Try again.
            </p>
          )}
          <button
            className="primary-button"
            type="button"
            disabled={submitting}
            onClick={() => void start()}
          >
            {submitting ? 'Starting runtime...' : 'Start runtime'}
          </button>
        </div>
      </section>
    </main>
  );
}
