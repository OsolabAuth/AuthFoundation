# Password Change Rebuild Design

## Goal

Add password change protected by a 5-minute step-up authorization token.

## Scope

- `POST /account/password`
- Requires email, current password, new password, and `step_up_token`.
- Validates that the step-up grant subject matches the account subject.

## Out of Scope

- Password history
- Session invalidation after password change
- Notification email

## Validation

- `dotnet build`
- `dotnet test`
