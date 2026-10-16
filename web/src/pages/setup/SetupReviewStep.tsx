import { useTranslation } from '../../i18n/LanguageContext';

const PASSWORD_MASK = '••••••••••';

export interface SetupReviewStepProps {
  username: string;
  password: string;
  peerIp: string;
  hosts: string[];
  restrictionEnabled: boolean;
  submitting: boolean;
  onBack: () => void;
  onSubmit: () => void;
}

/**
 * Step 3 of the setup wizard: a read-only summary of everything collected
 * in steps 1 and 2, plus the single submit control. Nothing here mutates
 * server state — that happens once, in the wizard shell, when onSubmit
 * fires.
 */
export function SetupReviewStep({
  username,
  password,
  peerIp,
  hosts,
  restrictionEnabled,
  submitting,
  onBack,
  onSubmit,
}: SetupReviewStepProps) {
  const { t } = useTranslation();
  return (
    <>
      <h1 id="wizard-heading">{t('setup.reviewHeading')}</h1>
      <p className="wizard-progress">{t('setup.stepReviewProgress')}</p>
      <dl className="wizard-review-list">
        <div className="wizard-review-row">
          <dt>{t('common.username')}</dt>
          <dd>{username}</dd>
        </div>
        <div className="wizard-review-row">
          <dt>{t('common.password')}</dt>
          <dd aria-label={t('setup.passwordHiddenLabel')}>{PASSWORD_MASK}</dd>
        </div>
        <div className="wizard-review-row">
          <dt>{t('setup.managementPolicyLabel')}</dt>
          <dd>{t(restrictionEnabled ? 'setup.restrictionsEnabled' : 'setup.restrictionsDisabled')}</dd>
        </div>
        {restrictionEnabled && (
          <div className="wizard-review-row">
            <dt>{t('setup.managementAddressesLabel')}</dt>
            <dd>
              <ul className="management-host-list">
                <li>
                  {peerIp} <span className="management-host-tag">{t('setup.currentSessionTag')}</span>
                </li>
                {hosts.map((host) => <li key={host}>{host}</li>)}
              </ul>
            </dd>
          </div>
        )}
      </dl>
      <div className="wizard-actions">
        <button type="button" className="secondary-button" onClick={onBack} disabled={submitting}>
          {t('setup.back')}
        </button>
        <button
          type="button"
          className="primary-button"
          onClick={onSubmit}
          disabled={submitting}
        >
          {submitting ? t('setup.completingSetup') : t('setup.completeSetup')}
        </button>
      </div>
    </>
  );
}
