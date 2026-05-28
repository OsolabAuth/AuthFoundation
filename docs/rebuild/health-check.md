# Health Check Rebuild Design

## Goal

Add operational health endpoints for local Docker, Cloud Run, and tunnel-based checks.

## Scope

- `GET /health/live`
- `GET /health/ready`
- Portal `/health` page
- Documentation for the check contract

## Interface

### GET /health/live

Liveness probe. The endpoint only verifies that the AuthFoundation process can return an HTTP response.

Response:

```http
HTTP/1.1 200 OK
Content-Type: application/json
```

```json
{
  "status": "ok",
  "check": "live",
  "checked_at": "2026-05-31T00:00:00+00:00"
}
```

### GET /health/ready

Readiness probe. The endpoint returns the runtime URLs that must be consistent before routing traffic to this service.

Response:

```http
HTTP/1.1 200 OK
Content-Type: application/json
```

```json
{
  "status": "ok",
  "check": "ready",
  "issuer": "https://auth.osolab-auth.jp",
  "auth_ui_base_url": "https://portal.osolab-auth.jp",
  "checked_at": "2026-05-31T00:00:00+00:00"
}
```

## Out of Scope

- Database connectivity checks
- Dependency-specific readiness
- Kubernetes probe manifests

## Validation

- `dotnet build`
- `dotnet test`
- Unit tests cover all response codes and response fields defined in this design.
- `npm run typecheck`
