# MFA / Step-Up Authorization Rebuild Design

## Goal

Add a short-lived strong authorization token that can protect high-risk account operations.

## Scope

- Email-code MFA challenge.
- Authenticator app TOTP setup and verification.
- `step_up_token` valid for 5 minutes.
- Development email delivery writes the code to the application log so local screen-based scenarios can be completed without a real mailbox.
- Non-development environments must configure a real mail sender.

## Endpoints

- `POST /mfa/email/start`
- `POST /mfa/email/verify`
- `POST /mfa/authenticator/setup`
- `POST /mfa/authenticator/verify`

## Out of Scope

- Real email delivery
- Recovery codes
- MFA enrollment policy
- Persistent MFA device table

## Validation

- `dotnet build`
- `dotnet test`
