// src/lib/validation/schemas.ts
import { z } from 'zod';
import { validatePassword, passwordPolicyDescription } from '../security/password-policy';

const USERNAME_RE = /^[a-z0-9_]{3,32}$/;

export const usernameSchema = z
  .string()
  .trim()
  .min(3)
  .max(32)
  .regex(USERNAME_RE, 'Username must be 3-32 chars of a-z, 0-9, or underscore')
  .transform((v) => v.toLowerCase());

export const emailSchema = z
  .string()
  .email('Invalid email address')
  .max(254);

export const passwordSchema = z.string().superRefine((val, ctx) => {
  const res = validatePassword(val);
  if (!res.valid) {
    for (const err of res.errors) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: err,
      });
    }
  }
});

export const registerSchema = z.object({
  username: usernameSchema,
  email: emailSchema.optional(),
  password: passwordSchema,
});

export const loginSchema = z.object({
  username: usernameSchema,
  password: z.string().min(1, 'Password is required'),
});

export const changePasswordSchema = z.object({
  currentPassword: z.string().min(1, 'Current password is required'),
  newPassword: passwordSchema,
});

export const requestPasswordResetSchema = z.object({
  identifier: z
    .string()
    .trim()
    .min(3, 'Provide username or email')
    .max(254, 'Identifier too long'),
});

export const resetPasswordSchema = z.object({
  token: z.string().min(1, 'Reset token is required'),
  newPassword: passwordSchema,
});

// Types
export type RegisterInput = z.infer<typeof registerSchema>;
export type LoginInput = z.infer<typeof loginSchema>;
export type ChangePasswordInput = z.infer<typeof changePasswordSchema>;
export type RequestPasswordResetInput = z.infer<typeof requestPasswordResetSchema>;
export type ResetPasswordInput = z.infer<typeof resetPasswordSchema>;

export const passwordPolicyText = passwordPolicyDescription();
