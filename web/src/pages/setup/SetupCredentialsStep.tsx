import { type FormEvent, useState } from 'react';

import {
  evaluatePasswordRequirements,
  validateSetupCredentials,
  type SetupCredentialErrors,
} from '../../security/setupPolicy';

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
      nextErrors.password = 'Resolve the password requirements listed below.';
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
      <h1 id="wizard-heading">Create administrator</h1>
      <p className="wizard-progress">Step 1 of 3 &middot; Account</p>
      <form className="auth-form" onSubmit={submit} noValidate>
        <div className="field">
          <label htmlFor="wizard-username">Username</label>
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
          <label htmlFor="wizard-password">Password</label>
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
                  {requirement.label}
                  {unmet && (
                    <span className="password-requirement-marker"> &mdash; not met</span>
                  )}
                </li>
              );
            })}
          </ul>
        </div>
        <div className="field">
          <label htmlFor="wizard-confirmation">Confirm password</label>
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
        <button className="primary-button" type="submit">Next</button>
      </form>
    </>
  );
}
