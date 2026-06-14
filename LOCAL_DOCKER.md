# Local Docker Setup

## Start dependencies for Visual Studio debugging

Run SQL Server and Redis only.

```powershell
docker compose -f docker-compose.local.yml up -d auth-db auth-db-init redis
```

Then open `AuthFoundation/AuthFoundation.csproj` in Visual Studio and start the `AuthFoundation Local` debug profile.

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

SQL Server:

```text
Server=localhost,14333
Database=AuthFoundation
User Id=sa
Password=OsolabAuth_Passw0rd!
```

Redis:

```text
localhost:63790
```

## Notes

The local compose file uses a development-only signing key copied from the test fixture. Do not reuse it in production.

Production and Cloud Run must use external Auth DB and Redis. In-memory stores are only for local development and unit tests.
