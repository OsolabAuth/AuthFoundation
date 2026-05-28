# Account Withdrawal Rebuild Design

## Goal

Add account withdrawal protected by a 5-minute step-up authorization token.

## Scope

- `POST /account/withdrawal`
- Requires email, password, and `step_up_token`.
- Deletes the account from the development in-memory user store.

## Out of Scope

- Grace period
- Data export
- Audit-log persistence

## Validation

- `dotnet build`
- `dotnet test`
