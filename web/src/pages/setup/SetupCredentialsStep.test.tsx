import '@testing-library/jest-dom/vitest';

// @ts-expect-error Vitest provides Node built-ins outside the browser bundle.
import { readFileSync } from 'node:fs';

import { cleanup, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { useState } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { LanguageProvider } from '../../i18n';
import { evaluatePasswordRequirements, type PasswordRequirementId } from '../../security/setupPolicy';
import { SetupCredentialsStep } from './SetupCredentialsStep';

afterEach(cleanup);

// Same shared vectors setupPolicy.test.ts reads (kept in lockstep with the
// C++ suite). Reused here so every one of the nine requirements — not just
// length and the username-dependent one — is exercised in its unmet state
// against a real rejecting example, rather than against a hand-picked
// password that might not actually isolate the rule it's meant to.
interface PasswordVector {
  username: string;
  password: string;
  accept: boolean;
  rule?: PasswordRequirementId;
}

const sharedVectors: PasswordVector[] = JSON.parse(
  readFileSync('../tests/data/password-policy-vectors.json', 'utf8'),
).vectors;

const unmetVectorByRule = new Map<PasswordRequirementId, PasswordVector>();
for (const vector of sharedVectors) {
  if (!vector.accept && vector.rule && !unmetVectorByRule.has(vector.rule)) {
    unmetVectorByRule.set(vector.rule, vector);
  }
}

function Harness({ onNext }: { onNext: () => void }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmation, setConfirmation] = useState('');
  return (
    <LanguageProvider>
      <SetupCredentialsStep
        username={username}
        password={password}
        confirmation={confirmation}
        onUsernameChange={setUsername}
        onPasswordChange={setPassword}
        onConfirmationChange={setConfirmation}
        onNext={onNext}
      />
    </LanguageProvider>
  );
}

describe('SetupCredentialsStep', () => {
  it('uses masked password controls carrying the authoritative length bounds', () => {
    render(<Harness onNext={vi.fn()} />);

    const password = screen.getByLabelText(/^password$/i);
    const confirmation = screen.getByLabelText(/confirm password/i);
    expect(password).toHaveAttribute('type', 'password');
    expect(confirmation).toHaveAttribute('type', 'password');
    expect(password).toHaveAttribute('minlength', '9');
    expect(password).toHaveAttribute('maxlength', '128');
    expect(confirmation).toHaveAttribute('minlength', '9');
    expect(confirmation).toHaveAttribute('maxlength', '128');
  });

  it('renders all nine requirements normally before the password field is touched', () => {
    render(<Harness onNext={vi.fn()} />);

    const requirements = evaluatePasswordRequirements('', '');
    expect(requirements).toHaveLength(9);
    for (const requirement of requirements) {
      const item = screen.getByText(requirement.label).closest('li');
      expect(item).not.toBeNull();
      expect(item).not.toHaveAttribute('aria-invalid');
      expect(item).not.toHaveTextContent(/not met/i);
    }
  });

  it('renders all nine requirements as met, identically to untouched, for a fully compliant password', async () => {
    const user = userEvent.setup();
    render(<Harness onNext={vi.fn()} />);

    await user.type(screen.getByLabelText(/^username$/i), 'operator.one');
    await user.type(screen.getByLabelText(/^password$/i), 'NorthStar!9');

    const requirements = evaluatePasswordRequirements('operator.one', 'NorthStar!9');
    expect(requirements).toHaveLength(9);
    expect(requirements.every((requirement) => requirement.met)).toBe(true);
    for (const requirement of requirements) {
      const item = screen.getByText(requirement.label).closest('li');
      expect(item).not.toHaveAttribute('aria-invalid');
      expect(item).not.toHaveTextContent(/not met/i);
    }
  });

  it.each(Array.from(unmetVectorByRule.entries()))(
    'marks the %s requirement unmet, with aria-invalid and a textual marker, for its rejecting vector',
    async (rule, vector) => {
      const user = userEvent.setup();
      render(<Harness onNext={vi.fn()} />);

      await user.type(screen.getByLabelText(/^username$/i), vector.username);
      await user.type(screen.getByLabelText(/^password$/i), vector.password);

      const requirement = evaluatePasswordRequirements(vector.username, vector.password)
        .find((entry) => entry.id === rule);
      expect(requirement?.met).toBe(false);
      const item = screen.getByText(requirement!.label).closest('li');
      expect(item).toHaveAttribute('aria-invalid', 'true');
      expect(item).toHaveTextContent(/not met/i);
    },
  );

  it('re-evaluates the username-dependent requirement when the username changes and the password does not', async () => {
    const user = userEvent.setup();
    render(<Harness onNext={vi.fn()} />);

    await user.type(screen.getByLabelText(/^password$/i), 'operator.one');
    await user.type(screen.getByLabelText(/^username$/i), 'operator.one');

    const usernameItem = screen.getByText('Different from the username').closest('li');
    expect(usernameItem).toHaveAttribute('aria-invalid', 'true');
    expect(usernameItem).toHaveTextContent(/not met/i);

    await user.clear(screen.getByLabelText(/^username$/i));
    await user.type(screen.getByLabelText(/^username$/i), 'someone.else');

    expect(usernameItem).not.toHaveAttribute('aria-invalid');
    expect(usernameItem).not.toHaveTextContent(/not met/i);
  });

  it('advances only once the username is valid, every requirement is met, and the passwords match', async () => {
    const user = userEvent.setup();
    const onNext = vi.fn();
    render(<Harness onNext={onNext} />);

    await user.click(screen.getByRole('button', { name: /next/i }));
    expect(onNext).not.toHaveBeenCalled();
    expect(screen.getByText('Username must be 5 to 32 characters.')).toBeVisible();

    await user.type(screen.getByLabelText(/^username$/i), 'operator.one');
    await user.type(screen.getByLabelText(/^password$/i), 'NorthStar!9');
    await user.type(screen.getByLabelText(/confirm password/i), 'Different!9');
    await user.click(screen.getByRole('button', { name: /next/i }));
    expect(onNext).not.toHaveBeenCalled();
    expect(screen.getByText('Passwords do not match.')).toBeVisible();

    await user.clear(screen.getByLabelText(/confirm password/i));
    await user.type(screen.getByLabelText(/confirm password/i), 'NorthStar!9');
    await user.click(screen.getByRole('button', { name: /next/i }));

    expect(onNext).toHaveBeenCalledTimes(1);
  });

  it('preserves entered values when re-rendered after navigating back', () => {
    const { rerender } = render(
      <LanguageProvider>
        <SetupCredentialsStep
          username="operator.one"
          password="NorthStar!9"
          confirmation="NorthStar!9"
          onUsernameChange={vi.fn()}
          onPasswordChange={vi.fn()}
          onConfirmationChange={vi.fn()}
          onNext={vi.fn()}
        />
      </LanguageProvider>,
    );

    expect(screen.getByLabelText(/^username$/i)).toHaveValue('operator.one');
    expect(screen.getByLabelText(/^password$/i)).toHaveValue('NorthStar!9');
    expect(screen.getByLabelText(/confirm password/i)).toHaveValue('NorthStar!9');

    rerender(
      <LanguageProvider>
        <SetupCredentialsStep
          username="operator.one"
          password="NorthStar!9"
          confirmation="NorthStar!9"
          onUsernameChange={vi.fn()}
          onPasswordChange={vi.fn()}
          onConfirmationChange={vi.fn()}
          onNext={vi.fn()}
        />
      </LanguageProvider>,
    );
    expect(screen.getByLabelText(/^username$/i)).toHaveValue('operator.one');
  });
});
