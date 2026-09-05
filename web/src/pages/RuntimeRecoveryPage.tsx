import { useState } from 'react';

import { parseInitializeResult } from '../api/contracts';
import type { CameraApiClient } from '../api/types';
import { useTranslation } from '../i18n/LanguageContext';

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
  const { t } = useTranslation();
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
        <div className="brand-mark" aria-hidden="true">{t('common.brandShort')}</div>
        <h1 id="runtime-recovery-heading">{t('auth.runtimeRecoveryHeading')}</h1>
        <div className="auth-form">
          <div className="field">
            <label htmlFor="runtime-peer-ip">{t('auth.managementPeerAddress')}</label>
            <input id="runtime-peer-ip" value={peerIp} readOnly />
          </div>
          {failed && (
            <p className="form-error" role="alert">
              {t('auth.runtimeStartFailed')}
            </p>
          )}
          <button
            className="primary-button"
            type="button"
            disabled={submitting}
            onClick={() => void start()}
          >
            {submitting ? t('auth.startingRuntime') : t('auth.startRuntime')}
          </button>
        </div>
      </section>
    </main>
  );
}
