# Local Docker Setup

## Start dependencies for Visual Studio debugging

Run SQL Server and Redis only.

```powershell
Copy-Item .env.example .env
# Edit .env and choose a local-only SA password that satisfies SQL Server complexity rules.
docker compose -f docker-compose.local.yml up -d auth-db auth-db-init redis
```

Then set `ConnectionStrings__AuthDb` in your OS environment or user-secrets, open
`AuthFoundation/AuthFoundation.csproj` in Visual Studio, and start the `AuthFoundation Local`
debug profile.

Example local connection string:

```text
Server=localhost,14333;Database=AuthFoundation;User Id=sa;Password=<AUTHFOUNDATION_SQL_PASSWORD>;TrustServerCertificate=True;Encrypt=True
```

The API runs at:

```text
http://localhost:5000
```

Useful checks:

```powershell
curl.exe http://localhost:5000/.well-known/openid-configuration
curl.exe http://localhost:5000/terms/current
```

## Run the API in Docker

```powershell
docker compose -f docker-compose.local.yml --profile api up -d --build
```

## Local ports

| Service | Host port | Container port |
| --- | ---: | ---: |
| AuthFoundation API | 5000 | 8080 |
| SQL Server | 14333 | 1433 |
| Redis | 63790 | 6379 |

## Local credentials

SQL Server password is read from `.env`:

```text
AUTHFOUNDATION_SQL_PASSWORD=<local-only password>
```

Redis:

```text
localhost:63790
```

## Notes

Development uses an ephemeral signing key when `SigningKey__KeyId` and
`SigningKey__PrivateKeyPem` are not configured. Production must configure a persistent signing key.

Production and Cloud Run must use external Auth DB and Redis. In-memory stores are only present in tests.
