import { type FormEvent, useEffect, useRef, useState } from 'react';

import { ApiError } from '../../api/client';
import type { CameraApiClient } from '../../api/types';
import { useTranslation } from '../../i18n/LanguageContext';
import { parseManagementIpPolicy } from './contracts';
import { userManagementErrorMessage } from './publicError';

interface ManagementIpPolicyPanelProps {
  client: CameraApiClient;
  disabled?: boolean;
  currentPeerIp: string;
  onSaved(): void;
}

const POLICY_PATH = '/api/v1/security/management-ip-policy';

export function ManagementIpPolicyPanel({
  client, disabled = false, currentPeerIp, onSaved,
}: ManagementIpPolicyPanelProps) {
  const { t } = useTranslation();
  const [savedEnabled, setSavedEnabled] = useState<boolean | null>(null);
  const [enabled, setEnabled] = useState(false);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [attempt, setAttempt] = useState(0);
  const activeSave = useRef<AbortController | null>(null);

  useEffect(() => {
    const request = new AbortController();
    setLoading(true);
    setLoadError(false);
    void client.getJson(POLICY_PATH, parseManagementIpPolicy, request.signal)
      .then((policy) => {
        if (!request.signal.aborted) {
          setSavedEnabled(policy.enabled);
          setEnabled(policy.enabled);
        }
      })
      .catch(() => {
        if (!request.signal.aborted) setLoadError(true);
      })
      .finally(() => {
        if (!request.signal.aborted) setLoading(false);
      });
    return () => request.abort();
  }, [attempt, client]);

  useEffect(() => () => activeSave.current?.abort(), []);

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (disabled || loading || savedEnabled === null || enabled === savedEnabled ||
        activeSave.current !== null) return;
    const request = new AbortController();
    activeSave.current = request;
    setSubmitting(true);
    setFailure(null);
    try {
      await client.putJson(POLICY_PATH, { enabled }, parseManagementIpPolicy, request.signal);
      // Policy changes revoke every server session; return to sign-in without
      // trying to refresh authenticated resources with the revoked cookie.
      if (!request.signal.aborted) onSaved();
    } catch (error) {
      if (!request.signal.aborted && !(error instanceof ApiError &&
          error.code === 'E_MANAGEMENT_REAUTHENTICATION_REQUIRED')) {
        setFailure(userManagementErrorMessage(error, t('users.policySaveFailed'), t));
      }
    } finally {
      if (activeSave.current === request) {
        activeSave.current = null;
        if (!request.signal.aborted) setSubmitting(false);
      }
    }
  };

  return (
    <form className="management-ip-policy" onSubmit={(event) => { void submit(event); }}
      aria-labelledby="management-ip-policy-heading">
      <h2 id="management-ip-policy-heading">{t('setup.managementPolicyLabel')}</h2>
      <label className="management-policy-toggle">
        <input type="checkbox" checked={enabled}
          disabled={disabled || loading || loadError || submitting || savedEnabled === null}
          aria-describedby="management-ip-policy-description"
          onChange={(event) => setEnabled(event.target.checked)} />
        {t('setup.restrictManagementAccess')}
      </label>
      <p id="management-ip-policy-description">{t('users.policyDescription')}</p>
      {currentPeerIp && <p>{t('users.policyCurrentAddress', { address: currentPeerIp })}</p>}
      {loading && <p role="status">{t('users.policyLoading')}</p>}
      {savedEnabled !== null && <p>{t('users.policyCurrent', {
        state: t(savedEnabled ? 'setup.restrictionsEnabled' : 'setup.restrictionsDisabled'),
      })}</p>}
      {loadError && <>
        <p className="form-error" role="alert">{t('users.policyLoadFailed')}</p>
        <button type="button" className="secondary-button"
          onClick={() => setAttempt((value) => value + 1)}>{t('users.policyRetry')}</button>
      </>}
      <p>{t('users.policySignInNotice')}</p>
      {failure && <p className="form-error" role="alert">{failure}</p>}
      <button className="primary-button" type="submit"
        disabled={disabled || loading || loadError || submitting || savedEnabled === null || enabled === savedEnabled}>
        {t(submitting ? 'users.policySaving' : 'users.policySave')}
      </button>
    </form>
  );
}
