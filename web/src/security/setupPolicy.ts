export type SetupCredentialField = 'username' | 'password' | 'confirmation';

export type SetupCredentialErrors = Partial<Record<SetupCredentialField, string>>;

const USERNAME_CHARACTERS = /^[A-Za-z][A-Za-z0-9._-]*$/;
const PRINTABLE_NON_SPACE_ASCII = /^[\x21-\x7e]+$/;

export function validateSetupCredentials(
  username: string,
  password: string,
  confirmation: string,
): SetupCredentialErrors {
  const errors: SetupCredentialErrors = {};

  if (username.length < 5 || username.length > 32) {
    errors.username = 'Username must be 5 to 32 characters.';
  } else if (!/^[A-Za-z]/.test(username)) {
    errors.username = 'Username must begin with an ASCII letter.';
  } else if (!USERNAME_CHARACTERS.test(username)) {
    errors.username =
      'Username may contain only ASCII letters, numbers, periods, underscores, and hyphens.';
  }

  if (password.length < 9 || password.length > 128) {
    errors.password = 'Password must be 9 to 128 characters.';
  } else if (!PRINTABLE_NON_SPACE_ASCII.test(password)) {
    errors.password = 'Password must use printable, non-space ASCII characters.';
  } else if (password.toLowerCase() === username.toLowerCase()) {
    errors.password = 'Password must differ from the username.';
  } else if (!/[A-Z]/.test(password) || !/[a-z]/.test(password) ||
             !/[0-9]/.test(password) || !/[^A-Za-z0-9]/.test(password)) {
    errors.password =
      'Password must include uppercase, lowercase, number, and special characters.';
  }

  if (password !== confirmation) {
    errors.confirmation = 'Passwords do not match.';
  }

  return errors;
}
