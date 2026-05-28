# Audit Log Rebuild Design

## Goal

Add a development audit log surface so authentication, step-up authorization, account lifecycle, and AI agent delegation events can be inspected.

## Scope

- In-memory audit log service with a bounded record count.
- `GET /audit/logs` endpoint for development inspection.
- Audit records for signup, login, logout, token revoke, MFA, step-up, password reset/change, withdrawal, agent creation, and agent token issuance.
- Portal audit log page for quick visual checks.

## Out of Scope

- Persistent audit log table.
- Tamper-evident log storage.
- Role-based access to audit logs.
- SIEM/export integration.

## Validation

- `dotnet build`
- `dotnet test`
- `npm run typecheck`
