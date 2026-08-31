const PASSWORD_MASK = '••••••••••';

export interface SetupReviewStepProps {
  username: string;
  password: string;
  peerIp: string;
  hosts: string[];
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
  submitting,
  onBack,
  onSubmit,
}: SetupReviewStepProps) {
  return (
    <>
      <h1 id="wizard-heading">Review and confirm</h1>
      <p className="wizard-progress">Step 3 of 3 &middot; Review</p>
      <dl className="wizard-review-list">
        <div className="wizard-review-row">
          <dt>Username</dt>
          <dd>{username}</dd>
        </div>
        <div className="wizard-review-row">
          <dt>Password</dt>
          <dd aria-label="Password (hidden)">{PASSWORD_MASK}</dd>
        </div>
        <div className="wizard-review-row">
          <dt>Management addresses</dt>
          <dd>
            <ul className="management-host-list">
              <li>
                {peerIp} <span className="management-host-tag">(current session)</span>
              </li>
              {hosts.map((host) => <li key={host}>{host}</li>)}
            </ul>
          </dd>
        </div>
      </dl>
      <div className="wizard-actions">
        <button type="button" className="secondary-button" onClick={onBack} disabled={submitting}>
          Back
        </button>
        <button
          type="button"
          className="primary-button"
          onClick={onSubmit}
          disabled={submitting}
        >
          {submitting ? 'Completing setup...' : 'Complete setup'}
        </button>
      </div>
    </>
  );
}
