# GCP Operations Commands

AuthFoundation の GCP 運用でよく使うコマンド集です。

Windows PowerShell では `gcloud` が `gcloud.ps1` として解決され、ExecutionPolicy で止まることがあります。
基本は `gcloud.cmd` を使ってください。

## 前提値

```powershell
$PROJECT_ID = "osolab"
$REGION = "us-west1"
$ZONE = "us-west1-b"
$API_SERVICE = "authfoundation-api"
$PORTAL_SERVICE = "authfoundation-portal"
$DB_VM = "authfoundation-db"
```

Cloud Shell / bash の場合:

```bash
PROJECT_ID=osolab
REGION=us-west1
ZONE=us-west1-b
API_SERVICE=authfoundation-api
PORTAL_SERVICE=authfoundation-portal
DB_VM=authfoundation-db
```

## gcloud が PowerShell で止まる場合

推奨:

```powershell
gcloud.cmd version
gcloud.cmd config set project osolab
```

フルパス:

```powershell
& "C:\Program Files (x86)\Google\Cloud SDK\google-cloud-sdk\bin\gcloud.cmd" version
```

一時的に現在の PowerShell セッションだけ許可する場合:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
gcloud version
```

## Project / Account

```powershell
gcloud.cmd config set project osolab
gcloud.cmd config get-value project
gcloud.cmd auth list
```

Cloud Shell:

```bash
gcloud config set project osolab
gcloud config get-value project
gcloud auth list
```

## VM 一覧と SSH

VM 一覧:

```powershell
gcloud.cmd compute instances list
```

DB VM に SSH:

```powershell
gcloud.cmd compute ssh authfoundation-db --zone=us-west1-b
```

ブラウザで SSH する場合:

```text
GCP Console
-> Compute Engine
-> VM インスタンス
-> authfoundation-db
-> SSH
```

## VM 内で SQL Server / Redis を確認

SSH 後:

```bash
docker ps
docker compose ps
```

SQL Server コンテナに入る例:

```bash
docker exec -it <sqlserver-container-name> /opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -P '<SA_PASSWORD>' -C
```

SQL Server の DB / table 確認:

```sql
SELECT name FROM sys.databases ORDER BY name;
GO

USE OsolabAuth;
GO

SELECT
  s.name AS schema_name,
  t.name AS table_name
FROM sys.tables t
JOIN sys.schemas s ON s.schema_id = t.schema_id
WHERE s.name = 'auth'
ORDER BY t.name;
GO
```

AuthFoundation が現在参照する主要 table:

```text
auth.client_data_key
auth.client_master
auth.client_scopes
auth.client_terms
auth.data_key_master
auth.osolab_user
auth.user_client_scopes
auth.user_info
auth.user_terms
```

`auth.client_scopes` が無い場合、Cloud Run の認可フローで SQL Server `Error Number:208` / `Invalid object name 'auth.client_scopes'` が出ます。

## Cloud Run 状態確認

API:

```powershell
gcloud.cmd run services describe authfoundation-api `
  --region=us-west1 `
  --format="table(status.url,status.latestReadyRevisionName,status.latestCreatedRevisionName,status.conditions[0].status)"
```

Portal:

```powershell
gcloud.cmd run services describe authfoundation-portal `
  --region=us-west1 `
  --format="table(status.url,status.latestReadyRevisionName,status.latestCreatedRevisionName,status.conditions[0].status)"
```

Cloud Shell:

```bash
gcloud run services describe authfoundation-api \
  --region=us-west1 \
  --format="table(status.url,status.latestReadyRevisionName,status.latestCreatedRevisionName,status.conditions[0].status)"
```

## Cloud Run URL 取得

```powershell
gcloud.cmd run services describe authfoundation-api --region=us-west1 --format="value(status.url)"
gcloud.cmd run services describe authfoundation-portal --region=us-west1 --format="value(status.url)"
```

## Health / 疎通確認

API:

```powershell
curl.exe -i https://auth.osolab-auth.jp/Version
curl.exe -i https://authfoundation-api-cj4cuw5dfa-uw.a.run.app/Version
```

Portal:

```powershell
curl.exe -I https://portal.osolab-auth.jp/
curl.exe -I https://portal.osolab-auth.jp/callback
curl.exe -I https://authfoundation-portal-cj4cuw5dfa-uw.a.run.app/
```

Cloud Shell:

```bash
curl -i https://auth.osolab-auth.jp/Version
curl -I https://portal.osolab-auth.jp/
```

## Cloud Run Logs

API の直近ログ:

```powershell
gcloud.cmd logging read 'resource.type="cloud_run_revision" AND resource.labels.service_name="authfoundation-api"' `
  --project=osolab `
  --freshness=1h `
  --limit=100 `
  --format="value(timestamp,severity,logName,textPayload)"
```

API の stderr のみ:

```powershell
gcloud.cmd logging read 'resource.type="cloud_run_revision" AND resource.labels.service_name="authfoundation-api" AND logName="projects/osolab/logs/run.googleapis.com%2Fstderr"' `
  --project=osolab `
  --freshness=24h `
  --limit=100 `
  --format="value(timestamp,textPayload)"
```

特定 revision:

```powershell
gcloud.cmd logging read 'resource.type="cloud_run_revision" AND resource.labels.service_name="authfoundation-api" AND resource.labels.revision_name="authfoundation-api-00005-np7"' `
  --project=osolab `
  --freshness=24h `
  --limit=100 `
  --format="value(timestamp,severity,logName,textPayload)"
```

Cloud Shell:

```bash
gcloud logging read 'resource.type="cloud_run_revision" AND resource.labels.service_name="authfoundation-api"' \
  --project=osolab \
  --freshness=1h \
  --limit=100 \
  --format='value(timestamp,severity,logName,textPayload)'
```

## Domain Mapping

一覧:

```powershell
gcloud.cmd beta run domain-mappings list --region=us-west1
```

API domain mapping:

```powershell
gcloud.cmd beta run domain-mappings describe `
  --domain=auth.osolab-auth.jp `
  --region=us-west1 `
  --format="yaml(resourceRecords,status.conditions)"
```

Portal domain mapping:

```powershell
gcloud.cmd beta run domain-mappings describe `
  --domain=portal.osolab-auth.jp `
  --region=us-west1 `
  --format="yaml(resourceRecords,status.conditions)"
```

## DNS 確認

PowerShell で `dig` がある場合:

```powershell
dig @1.1.1.1 NS osolab-auth.jp +short
dig @1.1.1.1 CNAME auth.osolab-auth.jp +short
dig @1.1.1.1 CNAME portal.osolab-auth.jp +short
dig @8.8.8.8 CNAME auth.osolab-auth.jp +short
dig @8.8.8.8 CNAME portal.osolab-auth.jp +short
```

Cloud Shell:

```bash
dig @1.1.1.1 NS osolab-auth.jp +short
dig @1.1.1.1 CNAME auth.osolab-auth.jp +short
dig @1.1.1.1 CNAME portal.osolab-auth.jp +short
```

Cloud Run domain mapping の CNAME は通常:

```text
ghs.googlehosted.com.
```

Cloudflare は証明書発行が終わるまで `DNS only` を優先します。

## GitHub Actions

Auth API deploy:

```powershell
cd D:\portfolio\Auth
& "C:\Program Files\GitHub CLI\gh.exe" workflow run deploy-cloud-run.yml -f deploy=true
& "C:\Program Files\GitHub CLI\gh.exe" run list --workflow deploy-cloud-run.yml --limit 5
& "C:\Program Files\GitHub CLI\gh.exe" run watch <run-id> --exit-status
```

Portal deploy:

```powershell
cd D:\portfolio\authfoundation-portal
& "C:\Program Files\GitHub CLI\gh.exe" workflow run deploy-cloud-run.yml -f deploy=true
& "C:\Program Files\GitHub CLI\gh.exe" run list --workflow deploy-cloud-run.yml --limit 5
& "C:\Program Files\GitHub CLI\gh.exe" run watch <run-id> --exit-status
```

## Secret Manager

Secret 一覧:

```powershell
gcloud.cmd secrets list --project=osolab
```

Secret version 一覧:

```powershell
gcloud.cmd secrets versions list auth-db-connection --project=osolab
```

値を追加する例:

```powershell
"<new-value>" | gcloud.cmd secrets versions add auth-db-connection --project=osolab --data-file=-
```

注意: Secret の中身はログやチャットに貼らないでください。

## Artifact Registry

Repository 確認:

```powershell
gcloud.cmd artifacts repositories describe auth --location=us-west1 --project=osolab
```

Image tags:

```powershell
gcloud.cmd artifacts docker tags list us-west1-docker.pkg.dev/osolab/auth/authfoundation-api --project=osolab
gcloud.cmd artifacts docker tags list us-west1-docker.pkg.dev/osolab/auth/authfoundation-auth-ui --project=osolab
```

## よくある切り分け

### `gcloud.ps1 cannot be loaded`

PowerShell が `gcloud.ps1` をブロックしています。

```powershell
gcloud.cmd <subcommand>
```

を使ってください。

### Cloud Run が `Invalid object name 'auth.client_scopes'`

接続先 SQL Server に現行 schema が反映されていません。
VM の SQL Server で `auth.client_scopes` があるか確認してください。

### Cloud Run revision が Ready にならない

```powershell
gcloud.cmd run services describe authfoundation-api --region=us-west1
gcloud.cmd logging read 'resource.type="cloud_run_revision" AND resource.labels.service_name="authfoundation-api"' --project=osolab --freshness=1h --limit=100
```

### Domain mapping が CertificatePending

DNS record が public resolver から見えているか確認します。

```powershell
dig @1.1.1.1 CNAME auth.osolab-auth.jp +short
dig @8.8.8.8 CNAME auth.osolab-auth.jp +short
```
