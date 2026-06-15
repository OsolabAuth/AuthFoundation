# Terms / Consent Rebuild Design

## Goal

Register the OsolabAuth terms page for the development client and require consent during account creation.

## Scope

- Expose the current terms document through `GET /terms/current`.
- Require `terms_accepted = true` on `POST /signup`.
- Store the accepted terms version in SQL Server user term consent records.

## Development Client

The rebuild keeps the default client id:

```text
00000000000000000000000000000000
```

The terms document is treated as a shared OsolabAuth client document until the database-backed client and terms tables are migrated.

## Validation

- `dotnet build`
- `dotnet test`
