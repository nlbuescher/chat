// src/lib/security/password-policy.ts
// Password policy: min length 12 and at least 3 of 4 classes (upper, lower, digit, special)

export type PasswordPolicyResult = {
  valid: boolean;
  errors: string[];
  details: {
    length: number;
    hasUpper: boolean;
    hasLower: boolean;
    hasDigit: boolean;
    hasSpecial: boolean;
    classesSatisfied: number;
    minLength: number;
    requiredClasses: number;
  };
};

export const PASSWORD_MIN_LENGTH = 12;
export const PASSWORD_REQUIRED_CLASSES = 3;

const UPPER_RE = /[A-Z]/;
const LOWER_RE = /[a-z]/;
const DIGIT_RE = /[0-9]/;
// Accept a broad set of specials. Customize as needed.
const SPECIAL_RE = /[^A-Za-z0-9]/;

export function validatePassword(password: string): PasswordPolicyResult {
  const length = password.length;
  const hasUpper = UPPER_RE.test(password);
  const hasLower = LOWER_RE.test(password);
  const hasDigit = DIGIT_RE.test(password);
  const hasSpecial = SPECIAL_RE.test(password);

  const classesSatisfied =
    (hasUpper ? 1 : 0) + (hasLower ? 1 : 0) + (hasDigit ? 1 : 0) + (hasSpecial ? 1 : 0);

  const errors: string[] = [];

  if (length < PASSWORD_MIN_LENGTH) {
    errors.push(`Password must be at least ${PASSWORD_MIN_LENGTH} characters long.`);
  }
  if (classesSatisfied < PASSWORD_REQUIRED_CLASSES) {
    errors.push(
      `Password must include at least ${PASSWORD_REQUIRED_CLASSES} of: uppercase, lowercase, digit, special.`,
    );
  }

  return {
    valid: errors.length === 0,
    errors,
    details: {
      length,
      hasUpper,
      hasLower,
      hasDigit,
      hasSpecial,
      classesSatisfied,
      minLength: PASSWORD_MIN_LENGTH,
      requiredClasses: PASSWORD_REQUIRED_CLASSES,
    },
  };
}

export function passwordPolicyDescription(): string {
  return `Minimum length ${PASSWORD_MIN_LENGTH}; at least ${PASSWORD_REQUIRED_CLASSES} of: uppercase, lowercase, digit, special.`;
}
