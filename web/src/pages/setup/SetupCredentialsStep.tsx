import { type FormEvent, useState } from 'react';

import { useTranslation } from '../../i18n/LanguageContext';
import {
  evaluatePasswordRequirements,
  validateSetupCredentials,
  type PasswordRequirementId,
  type SetupCredentialErrors,
} from '../../security/setupPolicy';

// evaluatePasswordRequirements (security/setupPolicy.ts) is shared with
// AccountsTab.tsx and mirrors src/security/PasswordPolicy.cpp, so its
// English `label` strings stay the single source of truth there; this map
// only resolves each stable requirement id to this step's own translation,
// keeping setupPolicy.ts (and its cross-file/C++ parity) untouched.
const REQUIREMENT_LABEL_KEYS: Record<PasswordRequirementId, string> = {
  length: 'setup.requirementLength',
  charset: 'setup.requirementCharset',
  uppercase: 'setup.requirementUppercase',
  lowercase: 'setup.requirementLowercase',
  digit: 'setup.requirementDigit',
  special: 'setup.requirementSpecial',
  username: 'setup.requirementUsername',
  repeat: 'setup.requirementRepeat',
  sequence: 'setup.requirementSequence',
};

export interface SetupCredentialsStepProps {
  username: string;
  password: string;
  confirmation: string;
  onUsernameChange: (value: string) => void;
  onPasswordChange: (value: string) => void;
  onConfirmationChange: (value: string) => void;
  onNext: () => void;
}

/**
 * Step 1 of the setup wizard: the administrator's username and password.
 * The password requirement list is the single presentation of
 * evaluatePasswordRequirements (Task 3) — no rule is re-implemented here.
 * A requirement is only styled unmet once the password field has been
 * touched (non-empty); met and untouched requirements render identically,
 * by design, so the operator only ever sees red for something still wrong.
 */
export function SetupCredentialsStep({
  username,
  password,
  confirmation,
  onUsernameChange,
  onPasswordChange,
  onConfirmationChange,
  onNext,
}: SetupCredentialsStepProps) {
  const { t } = useTranslation();
  const [errors, setErrors] = useState<SetupCredentialErrors>({});
  const requirements = evaluatePasswordRequirements(username, password);
  const passwordTouched = password.length > 0;

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const validation = validateSetupCredentials(username, password, confirmation);
    const allRequirementsMet = requirements.every((requirement) => requirement.met);
    const nextErrors: SetupCredentialErrors = {};
    if (validation.username) {
      nextErrors.username = validation.username;
    }
    if (!allRequirementsMet) {
      nextErrors.password = t('setup.resolveRequirements');
    }
    if (validation.confirmation) {
      nextErrors.confirmation = validation.confirmation;
    }
    setErrors(nextErrors);
    if (Object.keys(nextErrors).length > 0) {
      return;
    }
    onNext();
  };

  return (
    <>
      <h1 id="wizard-heading">{t('setup.createAdministratorHeading')}</h1>
      <p className="wizard-progress">{t('setup.stepAccountProgress')}</p>
      <form className="auth-form" onSubmit={submit} noValidate>
        <div className="field">
          <label htmlFor="wizard-username">{t('common.username')}</label>
          <input
            id="wizard-username"
            name="username"
            autoComplete="username"
            value={username}
            aria-describedby={errors.username ? 'wizard-username-error' : undefined}
            aria-invalid={errors.username ? true : undefined}
            onChange={(event) => onUsernameChange(event.target.value)}
          />
          {errors.username && (
            <p className="form-error" id="wizard-username-error">{errors.username}</p>
          )}
        </div>
        <div className="field">
          <label htmlFor="wizard-password">{t('common.password')}</label>
          <input
            id="wizard-password"
            name="password"
            type="password"
            autoComplete="new-password"
            minLength={9}
            maxLength={128}
            value={password}
            aria-describedby="wizard-password-requirements"
            aria-invalid={errors.password ? true : undefined}
            onChange={(event) => onPasswordChange(event.target.value)}
          />
          <ul id="wizard-password-requirements" className="password-requirements">
            {requirements.map((requirement) => {
              const unmet = passwordTouched && !requirement.met;
              return (
                <li
                  key={requirement.id}
                  className={unmet
                    ? 'password-requirement password-requirement-unmet'
                    : 'password-requirement'}
                  aria-invalid={unmet ? true : undefined}
                >
                  {t(REQUIREMENT_LABEL_KEYS[requirement.id])}
                  {unmet && (
                    <span className="password-requirement-marker">{t('setup.requirementNotMet')}</span>
                  )}
                </li>
              );
            })}
          </ul>
        </div>
        <div className="field">
          <label htmlFor="wizard-confirmation">{t('setup.confirmPassword')}</label>
          <input
            id="wizard-confirmation"
            name="confirmation"
            type="password"
            autoComplete="new-password"
            minLength={9}
            maxLength={128}
            value={confirmation}
            aria-describedby={errors.confirmation ? 'wizard-confirmation-error' : undefined}
            aria-invalid={errors.confirmation ? true : undefined}
            onChange={(event) => onConfirmationChange(event.target.value)}
          />
          {errors.confirmation && (
            <p className="form-error" id="wizard-confirmation-error">{errors.confirmation}</p>
          )}
        </div>
        <button className="primary-button" type="submit">{t('setup.next')}</button>
      </form>
    </>
  );
}
