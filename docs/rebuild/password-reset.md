# Password Reset Rebuild Design

## Goal

Add the first forgot-password reset path.

## Scope

- `POST /password/reset`
- Requires login email, birth date, and new password.
- Birth date must match the registered profile value.

## Out of Scope

- Email reset link
- One-time reset token
- Abuse rate limiting

## Validation

- `dotnet build`
- `dotnet test`
