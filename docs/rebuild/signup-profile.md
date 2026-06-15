# Signup / Profile Rebuild Design

## Goal

Add a minimal account creation path before migrating consent and account lifecycle features.

## Scope

- Register a user with `email`, `password`, `name`, and `birth_date`.
- Store users in SQL Server through the EF Core-backed user store.
- Let login authenticate against the user store instead of the single configured development user.
- Keep `birth_date` available for future password reset verification.

## Endpoint Contract

`POST /signup`

```json
{
  "email": "user@example.com",
  "password": "Passw0rd!",
  "name": "Takeru",
  "birth_date": "1990-01-01"
}
```

The endpoint returns the created subject and profile attributes, excluding the password.

## Out of Scope

- Persistent database migration
- Email verification
- Terms consent enforcement
- Duplicate account merge

## Validation

- `dotnet build`
- `dotnet test`
