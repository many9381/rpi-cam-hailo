import { type FormEvent, useState } from 'react';

const IPV4_PATTERN =
  /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

// Standard multi-alternative IPv6 pattern: full form, every valid "::"
// compression position, and the loopback/any shorthand.
const IPV6_SEGMENT = '(?:[0-9a-fA-F]{1,4})';
const IPV6_PATTERN = new RegExp(
  '^(' +
  `(${IPV6_SEGMENT}:){7}${IPV6_SEGMENT}` +
  `|(${IPV6_SEGMENT}:){1,7}:` +
  `|(${IPV6_SEGMENT}:){1,6}:${IPV6_SEGMENT}` +
  `|(${IPV6_SEGMENT}:){1,5}(:${IPV6_SEGMENT}){1,2}` +
  `|(${IPV6_SEGMENT}:){1,4}(:${IPV6_SEGMENT}){1,3}` +
  `|(${IPV6_SEGMENT}:){1,3}(:${IPV6_SEGMENT}){1,4}` +
  `|(${IPV6_SEGMENT}:){1,2}(:${IPV6_SEGMENT}){1,5}` +
  `|${IPV6_SEGMENT}:((:${IPV6_SEGMENT}){1,6})` +
  `|:((:${IPV6_SEGMENT}){1,7}|:)` +
  ')$',
);

const ONLY_SINGLE_HOSTS_REASON = 'Only single hosts may be registered.';

// The C++ side of this rule is g_inet_address_get_is_any() in
// NormalizeManagementIp (src/security/UserManagementService.cpp) — IPv6's
// unspecified address ("::") is the exact equivalent of 0.0.0.0 and must be
// rejected for the same reason. Every group in a valid IPv6 literal is zero
// if and only if every character other than ':' in the literal is '0': the
// full form ("0000:...:0000"), the fully compressed form ("::"), and every
// representation in between all reduce to this same check.
function isUnspecifiedIpv6(value: string): boolean {
  const withoutColons = value.replace(/:/g, '');
  return withoutColons.length === 0 || /^0+$/.test(withoutColons);
}

/**
 * Rejects any input that is not a single host literal. Ranges (`~`),
 * wildcards (`*`), CIDR (`/`), the unspecified address, and the literal
 * "any" are all certification-relevant failures for a management IP
 * allowlist, so they are rejected here before the value is ever considered
 * for IPv4/IPv6 literal validation.
 */
function validateManagementHost(rawValue: string): string | null {
  const value = rawValue.trim();
  if (value.length === 0) {
    return 'Enter a management IP address.';
  }
  const lowered = value.toLowerCase();
  if (
    value.includes('~') ||
    value.includes('*') ||
    value.includes('/') ||
    lowered === 'any' ||
    value === '0.0.0.0'
  ) {
    return ONLY_SINGLE_HOSTS_REASON;
  }
  const isIpv4 = IPV4_PATTERN.test(value);
  const isIpv6 = IPV6_PATTERN.test(value);
  if (!isIpv4 && !isIpv6) {
    return 'Enter a valid IPv4 or IPv6 address.';
  }
  if (isIpv6 && isUnspecifiedIpv6(value)) {
    return ONLY_SINGLE_HOSTS_REASON;
  }
  return null;
}

// Server-side cap is 32 management_ips rows per role, and the confirming
// peer always claims one of them (SecurityStore::AddManagementIp /
// InitializeDevice). Stopping the operator here means a full step 2 can
// never make the single submission at review fail on this account.
const MAXIMUM_ADDITIONAL_HOSTS = 31;

export interface SetupIpStepProps {
  peerIp: string;
  hosts: string[];
  onAddHost: (host: string) => void;
  onBack: () => void;
  onNext: () => void;
}

/**
 * Step 2 of the setup wizard: the current peer is already registered (it is
 * what /api/v1/setup/initialize confirms as the administrator's pinned
 * address), and the operator may stage further single-host addresses here
 * for review in step 3.
 */
export function SetupIpStep({ peerIp, hosts, onAddHost, onBack, onNext }: SetupIpStepProps) {
  const [draft, setDraft] = useState('');
  const [error, setError] = useState<string | null>(null);
  const atCapacity = hosts.length >= MAXIMUM_ADDITIONAL_HOSTS;

  const addHost = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (atCapacity) {
      return;
    }
    const validationError = validateManagementHost(draft);
    if (validationError) {
      setError(validationError);
      return;
    }
    onAddHost(draft.trim());
    setDraft('');
    setError(null);
  };

  return (
    <>
      <h1 id="wizard-heading">Register management access</h1>
      <p className="wizard-progress">Step 2 of 3 &middot; Management access</p>
      <p>
        Only single hosts may manage this camera &mdash; no ranges, wildcards,
        or CIDR blocks. Your current address is already registered.
      </p>
      <div className="field">
        <label htmlFor="wizard-current-peer">Current management address</label>
        <input id="wizard-current-peer" value={peerIp} readOnly />
      </div>
      <ul className="management-host-list" aria-label="Registered management hosts">
        <li>
          {peerIp} <span className="management-host-tag">(current session)</span>
        </li>
        {hosts.map((host) => <li key={host}>{host}</li>)}
      </ul>
      <form className="auth-form" onSubmit={addHost} noValidate>
        <div className="field">
          <label htmlFor="wizard-add-host">Add a management address</label>
          <input
            id="wizard-add-host"
            value={draft}
            disabled={atCapacity}
            aria-describedby={error ? 'wizard-add-host-error' : undefined}
            aria-invalid={error ? true : undefined}
            onChange={(event) => setDraft(event.target.value)}
          />
          {error && <p className="form-error" id="wizard-add-host-error">{error}</p>}
          {atCapacity && (
            <p className="form-error">
              Up to {MAXIMUM_ADDITIONAL_HOSTS} additional hosts may be registered
              (32 total, including your current session).
            </p>
          )}
        </div>
        <button className="secondary-button" type="submit" disabled={atCapacity}>
          Add host
        </button>
      </form>
      <div className="wizard-actions">
        <button type="button" className="secondary-button" onClick={onBack}>Back</button>
        <button type="button" className="primary-button" onClick={onNext}>Next</button>
      </div>
    </>
  );
}
