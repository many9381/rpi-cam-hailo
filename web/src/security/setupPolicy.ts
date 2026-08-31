export type SetupCredentialField = 'username' | 'password' | 'confirmation';

// Stable, English-free error identifiers: this module mirrors
// src/security/PasswordPolicy.cpp and carries no i18n knowledge of its own
// (see the REQUIREMENT_LABEL_KEYS precedent in SetupCredentialsStep.tsx).
// Each consumer maps a code to its own translation key at render time.
export type SetupCredentialErrorCode =
  | 'USERNAME_LENGTH'
  | 'USERNAME_START'
  | 'USERNAME_CHARSET'
  | 'PASSWORD_LENGTH'
  | 'PASSWORD_CHARSET'
  | 'PASSWORD_USERNAME'
  | 'PASSWORD_CLASSES'
  | 'PASSWORD_REPEAT'
  | 'PASSWORD_SEQUENCE'
  | 'CONFIRMATION_MISMATCH';

export type SetupCredentialErrors = Partial<Record<SetupCredentialField, SetupCredentialErrorCode>>;

const USERNAME_CHARACTERS = /^[A-Za-z][A-Za-z0-9._-]*$/;
const PRINTABLE_NON_SPACE_ASCII = /^[\x21-\x7e]+$/;

// Keep in lockstep with src/security/PasswordPolicy.cpp. The C++ constant is
// kProhibitedRepeatBytes.
const PROHIBITED_REPEAT_LENGTH = 3;

// Keep in lockstep with src/security/PasswordPolicy.cpp. The C++ constant is
// kProhibitedSequenceBytes.
const PROHIBITED_SEQUENCE_LENGTH = 4;

// Keep in lockstep with kKeyboardRows in src/security/PasswordPolicy.cpp.
const KEYBOARD_ROWS = ['1234567890', 'qwertyuiop', 'asdfghjkl', 'zxcvbnm'];

/**
 * Mirrors the C++ HasRepeatedLetterOrDigit rule exactly: three consecutive,
 * identical ASCII letters or digits. Repeated special characters (e.g. "!!!")
 * are intentionally not covered, matching the server.
 */
function hasRepeatedLetterOrDigit(password: string): boolean {
  let run = 1;
  for (let index = 1; index < password.length; index += 1) {
    const character = password[index];
    const covered = /[A-Za-z0-9]/.test(character);
    run = covered && character === password[index - 1] ? run + 1 : 1;
    if (run >= PROHIBITED_REPEAT_LENGTH) {
      return true;
    }
  }
  return false;
}

function matchesKeyboardRowAt(
  lowered: string,
  offset: number,
  row: string,
  reverse: boolean,
): boolean {
  for (let start = 0; start + PROHIBITED_SEQUENCE_LENGTH <= row.length; start += 1) {
    let matches = true;
    for (let index = 0; index < PROHIBITED_SEQUENCE_LENGTH; index += 1) {
      const rowIndex = reverse
        ? row.length - 1 - start - index
        : start + index;
      if (lowered[offset + index] !== row[rowIndex]) {
        matches = false;
        break;
      }
    }
    if (matches) {
      return true;
    }
  }
  return false;
}

/**
 * Mirrors the C++ HasKeyboardSequence rule exactly: any four-character run,
 * forward or backward, that appears within one of the keyboard rows.
 */
function hasKeyboardSequence(password: string): boolean {
  if (password.length < PROHIBITED_SEQUENCE_LENGTH) {
    return false;
  }
  const lowered = password.toLowerCase();
  for (let offset = 0; offset <= lowered.length - PROHIBITED_SEQUENCE_LENGTH; offset += 1) {
    for (const row of KEYBOARD_ROWS) {
      if (
        matchesKeyboardRowAt(lowered, offset, row, false) ||
        matchesKeyboardRowAt(lowered, offset, row, true)
      ) {
        return true;
      }
    }
  }
  return false;
}

export type PasswordRequirementId =
  | 'length'
  | 'charset'
  | 'uppercase'
  | 'lowercase'
  | 'digit'
  | 'special'
  | 'username'
  | 'repeat'
  | 'sequence';

export interface PasswordRequirement {
  id: PasswordRequirementId;
  label: string;
  met: boolean;
}

/**
 * Evaluates the password policy one condition at a time, so a live form can
 * show each requirement as met or unmet as the operator types. This is the
 * single implementation of every rule in src/security/PasswordPolicy.cpp;
 * validateSetupCredentials below is built on top of it rather than
 * duplicating the checks.
 */
export function evaluatePasswordRequirements(
  username: string,
  password: string,
): PasswordRequirement[] {
  return [
    {
      id: 'length',
      label: 'Between 9 and 128 characters',
      met: password.length >= 9 && password.length <= 128,
    },
    {
      id: 'charset',
      label: 'Printable, non-space ASCII characters only',
      met: PRINTABLE_NON_SPACE_ASCII.test(password),
    },
    {
      id: 'uppercase',
      label: 'At least one uppercase letter',
      met: /[A-Z]/.test(password),
    },
    {
      id: 'lowercase',
      label: 'At least one lowercase letter',
      met: /[a-z]/.test(password),
    },
    {
      id: 'digit',
      label: 'At least one number',
      met: /[0-9]/.test(password),
    },
    {
      id: 'special',
      label: 'At least one special character',
      met: /[^A-Za-z0-9]/.test(password),
    },
    {
      id: 'username',
      label: 'Different from the username',
      met: password.toLowerCase() !== username.toLowerCase(),
    },
    {
      id: 'repeat',
      label: 'No letter or number repeated three times in a row',
      met: !hasRepeatedLetterOrDigit(password),
    },
    {
      id: 'sequence',
      label: 'No four-character keyboard sequence (e.g. 1234, qwer)',
      met: !hasKeyboardSequence(password),
    },
  ];
}

export function validateSetupCredentials(
  username: string,
  password: string,
  confirmation: string,
): SetupCredentialErrors {
  const errors: SetupCredentialErrors = {};

  if (username.length < 5 || username.length > 32) {
    errors.username = 'USERNAME_LENGTH';
  } else if (!/^[A-Za-z]/.test(username)) {
    errors.username = 'USERNAME_START';
  } else if (!USERNAME_CHARACTERS.test(username)) {
    errors.username = 'USERNAME_CHARSET';
  }

  const requirements = evaluatePasswordRequirements(username, password);
  const isMet = (id: PasswordRequirementId): boolean =>
    requirements.find((requirement) => requirement.id === id)?.met ?? false;

  if (!isMet('length')) {
    errors.password = 'PASSWORD_LENGTH';
  } else if (!isMet('charset')) {
    errors.password = 'PASSWORD_CHARSET';
  } else if (!isMet('username')) {
    errors.password = 'PASSWORD_USERNAME';
  } else if (!isMet('uppercase') || !isMet('lowercase') || !isMet('digit') || !isMet('special')) {
    errors.password = 'PASSWORD_CLASSES';
  } else if (!isMet('repeat')) {
    errors.password = 'PASSWORD_REPEAT';
  } else if (!isMet('sequence')) {
    errors.password = 'PASSWORD_SEQUENCE';
  }

  if (password !== confirmation) {
    errors.confirmation = 'CONFIRMATION_MISMATCH';
  }

  return errors;
}
