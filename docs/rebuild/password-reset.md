# Password Reset Rebuild Design

## Goal

Add the first forgot-password reset path.

## Scope

- `POST /password/reset`
- Requires login email, birth date, and new password.
- Birth date must match the registered profile value.
- The reset email code is delivered by the configured mail sender.
- Development environments write the email code to the application log for screen-based scenario execution.
- Non-development environments must configure real SMTP delivery before startup.

## Out of Scope

- Email reset link
- One-time reset link token

## Validation

- `dotnet build`
- `dotnet test`
