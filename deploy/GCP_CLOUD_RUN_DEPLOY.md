# GCP Cloud Run Deploy

AuthFoundation を Cloud Run に載せるための build/deploy 手順です。
RDB は SQL Server on VM、MDB は Redis on VM として扱い、Cloud Run には AuthFoundation のコンテナだけを置きます。

この手順は次の値を前提にしています。

```text
GCP project ID: osolab
GCP project number: 210279746180
GitHub repository: Takeru-k7a/Auth
Region: us-west1
Cloud Run service: authfoundation-api
Artifact Registry repository: auth
```

## 1. 値の取得元と設定先

GitHub の設定画面:

```text
https://github.com/Takeru-k7a/Auth/settings/secrets/actions
```

GitHub では `Secrets` タブと `Variables` タブを切り替えて登録します。
手動登録の代わりに、[deploy/github-actions.variables.json](../deploy/github-actions.variables.json) とローカル専用の `deploy/github-actions.secrets.json` から一括投入することもできます。

| 名前 | 取得元 | 設定先 |
| --- | --- | --- |
| `GCP_PROJECT_ID` | GCP Console の「プロジェクト ID」 | GitHub Variables |
| `GCP_REGION` | 自分で決める。今回は `us-west1` | GitHub Variables |
| `ARTIFACT_REGISTRY_REPOSITORY` | 自分で決める。今回は `auth` | GitHub Variables |
| `CLOUD_RUN_SERVICE` | 自分で決める。今回は `authfoundation-api` | GitHub Variables |
| `CLOUD_RUN_IMAGE_NAME` | 自分で決める。今回は `authfoundation-api` | GitHub Variables |
| `AUTH_ISSUER` | AuthFoundation の公開 issuer URL | GitHub Variables |
| `GCP_WORKLOAD_IDENTITY_PROVIDER` | Cloud Shell の setup command の出力 | GitHub Secrets |
| `GCP_SERVICE_ACCOUNT` | Cloud Shell の setup command の出力 | GitHub Secrets |
| `CLOUD_RUN_NETWORK` | `data-server` VM の network 名 | GitHub Variables |
| `CLOUD_RUN_SUBNET` | `data-server` VM の subnet 名 | GitHub Variables |
| `CLOUD_RUN_VPC_EGRESS` | 固定で `private-ranges-only` | GitHub Variables |
| `CLOUD_RUN_UPDATE_SECRETS` | Secret Manager の secret 名を並べる | GitHub Variables |

## 2. GCP 側の初期設定

GCP Console 右上の Cloud Shell で実行します。
`REPO=Takeru-k7a/Auth` は GitHub repository URL から取った値です。

```bash
PROJECT_ID=osolab
PROJECT_NUMBER=210279746180
REGION=us-west1
REPOSITORY=auth
REPO=Takeru-k7a/Auth
DEPLOYER_SA=github-auth-deployer

gcloud config set project "${PROJECT_ID}"

gcloud services enable \
  run.googleapis.com \
  artifactregistry.googleapis.com \
  cloudbuild.googleapis.com \
  secretmanager.googleapis.com \
  iamcredentials.googleapis.com \
  sts.googleapis.com

gcloud artifacts repositories describe "${REPOSITORY}" \
  --location="${REGION}" \
  --project="${PROJECT_ID}" \
  || gcloud artifacts repositories create "${REPOSITORY}" \
    --repository-format=docker \
    --location="${REGION}" \
    --description="AuthFoundation container images" \
    --project="${PROJECT_ID}"

gcloud iam service-accounts describe \
  "${DEPLOYER_SA}@${PROJECT_ID}.iam.gserviceaccount.com" \
  || gcloud iam service-accounts create "${DEPLOYER_SA}" \
    --display-name="GitHub AuthFoundation Cloud Run deployer"

gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
  --member="serviceAccount:${DEPLOYER_SA}@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/run.admin"

gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
  --member="serviceAccount:${DEPLOYER_SA}@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/artifactregistry.writer"

gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
  --member="serviceAccount:${DEPLOYER_SA}@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/iam.serviceAccountUser"

gcloud iam workload-identity-pools describe github-actions \
  --location=global \
  || gcloud iam workload-identity-pools create github-actions \
    --location=global \
    --display-name="GitHub Actions"

gcloud iam workload-identity-pools providers describe github \
  --location=global \
  --workload-identity-pool=github-actions \
  && gcloud iam workload-identity-pools providers update-oidc github \
    --location=global \
    --workload-identity-pool=github-actions \
    --attribute-condition="attribute.repository=='${REPO}'" \
  || gcloud iam workload-identity-pools providers create-oidc github \
    --location=global \
    --workload-identity-pool=github-actions \
    --display-name="GitHub" \
    --issuer-uri="https://token.actions.githubusercontent.com" \
    --attribute-mapping="google.subject=assertion.sub,attribute.repository=assertion.repository,attribute.owner=assertion.repository_owner" \
    --attribute-condition="attribute.repository=='${REPO}'"

# REPO を空のまま作ってしまった場合の古い binding を消す。無ければ無視される。
gcloud iam service-accounts remove-iam-policy-binding \
  "${DEPLOYER_SA}@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/iam.workloadIdentityUser" \
  --member="principalSet://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/github-actions/attribute.repository/" \
  || true

gcloud iam service-accounts add-iam-policy-binding \
  "${DEPLOYER_SA}@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/iam.workloadIdentityUser" \
  --member="principalSet://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/github-actions/attribute.repository/${REPO}"

echo "GCP_PROJECT_ID=${PROJECT_ID}"
echo "GCP_WORKLOAD_IDENTITY_PROVIDER=projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/github-actions/providers/github"
echo "GCP_SERVICE_ACCOUNT=${DEPLOYER_SA}@${PROJECT_ID}.iam.gserviceaccount.com"
```

最後の `echo` で出た値を GitHub に登録します。

GitHub Variables:

```text
GCP_PROJECT_ID=osolab
GCP_REGION=us-west1
ARTIFACT_REGISTRY_REPOSITORY=auth
CLOUD_RUN_SERVICE=authfoundation-api
CLOUD_RUN_IMAGE_NAME=authfoundation-api
AUTH_ISSUER=https://auth.osolab-auth.jp/
```

GitHub Secrets:

```text
GCP_WORKLOAD_IDENTITY_PROVIDER=projects/210279746180/locations/global/workloadIdentityPools/github-actions/providers/github
GCP_SERVICE_ACCOUNT=github-auth-deployer@osolab.iam.gserviceaccount.com
```

JSON で一括投入する場合:

```powershell
# 初回だけ GitHub CLI を入れてログインする
winget install --id GitHub.cli
gh auth login

# CLOUD_RUN_NETWORK / CLOUD_RUN_SUBNET が分かったら JSON に入れる
notepad .\deploy\github-actions.variables.json

# secrets は repo に commit しない。example からローカルファイルを作る
Copy-Item .\deploy\github-actions.secrets.example.json .\deploy\github-actions.secrets.json
notepad .\deploy\github-actions.secrets.json

# Variables と Secrets を GitHub Actions に投入する
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\set-github-actions-config.ps1
```

`gh` が見つからない場合は、インストール先を明示します。

```powershell
& "C:\Program Files\GitHub CLI\gh.exe" auth login

powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\set-github-actions-config.ps1 `
  -GhPath "C:\Program Files\GitHub CLI\gh.exe"
```

`deploy/github-actions.variables.json` は commit してよい非秘密値です。
`deploy/github-actions.secrets.json` は `.gitignore` 済みのローカル専用ファイルです。
この script は GitHub の `Variables` タブと `Secrets` タブに値を設定します。

実際に設定せず、投入されるコマンドだけ見る場合:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\set-github-actions-config.ps1 -DryRun
```

## 3. VM の network/subnet を取得する

Cloud Run から `data-server` VM の SQL Server / Redis に内部 IP で接続するために、VM と同じ VPC/subnet を GitHub Variables に入れます。

Cloud Shell で実行:

```bash
gcloud compute instances describe data-server \
  --zone=us-west1-b \
  --format="value(networkInterfaces[0].network.basename(),networkInterfaces[0].subnetwork.basename(),networkInterfaces[0].networkIP)"
```

出力例:

```text
default default 10.138.0.2
```

この場合、GitHub Variables にこう設定します。

```text
CLOUD_RUN_NETWORK=default
CLOUD_RUN_SUBNET=default
CLOUD_RUN_VPC_EGRESS=private-ranges-only
```

最後の `10.138.0.2` は VM の内部 IP です。
この IP は DB/Redis の接続文字列で使います。

## 4. Runtime secrets を Secret Manager に作る

DB password、Redis 接続先、Gmail SMTP 設定、`PasswordHashKey`、`JwkPrivateKeyEncryptionKey` は GitHub Secrets ではなく GCP Secret Manager に置きます。

Cloud Shell で実行例:

```bash
PROJECT_ID=osolab
DATA_SERVER_INTERNAL_IP=<data-server-internal-ip>
MSSQL_PASSWORD='<sqlserver-password>'
PASSWORD_HASH_KEY='<production-password-hash-key>'
JWK_PRIVATE_KEY_ENCRYPTION_KEY='<production-jwk-encryption-key>'
MAIL_FROM_EMAIL='<sender-email>'
GMAIL_SMTP_USERNAME='<smtp-username>'
GMAIL_SMTP_APP_PASSWORD='<gmail-app-password>'

printf 'Server=%s,1433;Database=OsolabAuth;User ID=sa;Password=%s;TrustServerCertificate=True' \
  "${DATA_SERVER_INTERNAL_IP}" \
  "${MSSQL_PASSWORD}" \
  | gcloud secrets create auth-db-connection \
    --project="${PROJECT_ID}" \
    --replication-policy=automatic \
    --data-file=-

printf '%s:6379' "${DATA_SERVER_INTERNAL_IP}" \
  | gcloud secrets create auth-redis-connection \
    --project="${PROJECT_ID}" \
    --replication-policy=automatic \
    --data-file=-

printf '%s' "${PASSWORD_HASH_KEY}" \
  | gcloud secrets create auth-password-hash-key \
    --project="${PROJECT_ID}" \
    --replication-policy=automatic \
    --data-file=-

printf '%s' "${JWK_PRIVATE_KEY_ENCRYPTION_KEY}" \
  | gcloud secrets create auth-jwk-encryption-key \
    --project="${PROJECT_ID}" \
    --replication-policy=automatic \
    --data-file=-

printf '%s' "${MAIL_FROM_EMAIL}" \
  | gcloud secrets create auth-mail-from-email \
    --project="${PROJECT_ID}" \
    --replication-policy=automatic \
    --data-file=-

printf '%s' "${GMAIL_SMTP_USERNAME}" \
  | gcloud secrets create auth-gmail-smtp-username \
    --project="${PROJECT_ID}" \
    --replication-policy=automatic \
    --data-file=-

printf '%s' "${GMAIL_SMTP_APP_PASSWORD}" \
  | gcloud secrets create auth-gmail-smtp-app-password \
    --project="${PROJECT_ID}" \
    --replication-policy=automatic \
    --data-file=-
```

既に secret を作っていて値だけ更新する場合は `create` ではなく `versions add` を使います。

```bash
printf '<new-value>' \
  | gcloud secrets versions add auth-db-connection \
    --project=osolab \
    --data-file=-
```

Cloud Run の runtime service account に Secret Manager 読み取り権限を付けます。
`CLOUD_RUN_SERVICE_ACCOUNT` を GitHub Variables に設定しない場合、通常は Compute Engine default service account が使われます。

```bash
PROJECT_ID=osolab
RUNTIME_SA=210279746180-compute@developer.gserviceaccount.com

gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
  --member="serviceAccount:${RUNTIME_SA}" \
  --role="roles/secretmanager.secretAccessor"
```

GitHub Variables に `CLOUD_RUN_UPDATE_SECRETS` を追加します。
ここには secret の値ではなく、Secret Manager の secret 名を書きます。

```text
CLOUD_RUN_UPDATE_SECRETS=ConnectionStrings__DefaultConnection=auth-db-connection:latest,ConnectionStrings__Redis=auth-redis-connection:latest,PasswordHashKey=auth-password-hash-key:latest,JwkPrivateKeyEncryptionKey=auth-jwk-encryption-key:latest,Mail__FromEmail=auth-mail-from-email:latest,GmailSmtp__Username=auth-gmail-smtp-username:latest,GmailSmtp__AppPassword=auth-gmail-smtp-app-password:latest
```

## 5. Firewall

VM 側で SQL Server と Redis を受けるため、Cloud Run が使う subnet から VM への `1433` と `6379` を許可します。

まず VM の network/subnet/IP を確認します。

```bash
gcloud compute instances describe data-server \
  --zone=us-west1-b \
  --format="value(networkInterfaces[0].network.basename(),networkInterfaces[0].subnetwork.basename(),networkInterfaces[0].networkIP)"
```

subnet の CIDR を確認します。

```bash
gcloud compute networks subnets describe <subnet-name> \
  --region=us-west1 \
  --format="value(ipCidrRange)"
```

例:

```bash
gcloud compute firewall-rules create allow-cloud-run-to-auth-data-server \
  --network=<network-name> \
  --allow=tcp:1433,tcp:6379 \
  --source-ranges=<subnet-cidr> \
  --target-tags=auth-data-server
```

この firewall rule を使う場合、`data-server` VM に network tag `auth-data-server` を付けます。

```bash
gcloud compute instances add-tags data-server \
  --zone=us-west1-b \
  --tags=auth-data-server
```

## 6. GitHub Actions で deploy

GitHub Actions の `Build and Deploy Auth to Cloud Run` を手動実行します。

```text
Actions
-> Build and Deploy Auth to Cloud Run
-> Run workflow
```

入力値:

```text
deploy=true
image_tag=<空でよい。空なら commit SHA>
```

workflow は次を実行します。

```text
dotnet test
docker build
Artifact Registry push
gcloud run deploy
```

Cloud Run のコンテナポートは `8080` です。
`DisableHttpsRedirection=true` は workflow 側で常に入れます。

## 7. 手元で image だけ作る

GitHub Actions を待たず、手元の gcloud から Artifact Registry に image を作る場合:

```powershell
.\scripts\build-cloud-run-image.ps1 `
  -ProjectId osolab `
  -Region us-west1 `
  -Repository auth `
  -ImageName authfoundation-api
```

出力された image URI を Cloud Run のコンテナイメージ欄に入れます。

## 8. 確認

Cloud Run URL:

```bash
gcloud run services describe authfoundation-api \
  --region=us-west1 \
  --format="value(status.url)"
```

Version endpoint:

```bash
curl "$(gcloud run services describe authfoundation-api --region=us-west1 --format='value(status.url)')/Version"
```

Workload Identity の repository condition:

```bash
gcloud iam workload-identity-pools providers describe github \
  --location=global \
  --workload-identity-pool=github-actions \
  --format="value(attributeCondition)"
```

期待値:

```text
attribute.repository=='Takeru-k7a/Auth'
```

## 9. Custom domain

`auth.osolab-auth.jp` を Cloud Run に割り当てる手順です。

まず、Cloud Run service が最新 revision で Ready になっていることを確認します。

```bash
gcloud run services describe authfoundation-api \
  --region=us-west1 \
  --format="table(status.url,status.latestReadyRevisionName,status.latestCreatedRevisionName,status.conditions[0].status)"
```

`latestReadyRevisionName` と `latestCreatedRevisionName` が同じで、`STATUS` が `True` なら進めます。

既存の簡易疎通確認:

```bash
URL=$(gcloud run services describe authfoundation-api \
  --region=us-west1 \
  --format="value(status.url)")

curl -i "${URL}/Version"
```

### Console で設定する場合

1. GCP Console で `Cloud Run` を開く
2. `ドメイン マッピング` を開く
3. `マッピングを追加` を選ぶ
4. service に `authfoundation-api` を選ぶ
5. domain に `auth.osolab-auth.jp` を入力する
6. 所有権確認が出たら `osolab-auth.jp` を verify する
7. 表示された DNS record を DNS 管理画面に設定する

DNS が Cloudflare の場合は、証明書発行が完了するまで該当 record を `DNS only` にしておくと切り分けしやすいです。

### gcloud で設定する場合

Domain mapping を作ります。

```bash
PROJECT_ID=osolab
REGION=us-west1
SERVICE=authfoundation-api
DOMAIN=auth.osolab-auth.jp

gcloud config set project "${PROJECT_ID}"

gcloud beta run domain-mappings create \
  --service="${SERVICE}" \
  --domain="${DOMAIN}" \
  --region="${REGION}"
```

所有権確認が未完了の場合は、指示された domain verification を完了してから再実行します。

DNS に入れる record を確認します。

```bash
gcloud beta run domain-mappings describe "${DOMAIN}" \
  --region="${REGION}" \
  --format="yaml(resourceRecords,status.conditions)"
```

表示された `resourceRecords` を DNS 管理画面に設定します。
反映と Google managed certificate の発行には時間がかかることがあります。

状態確認:

```bash
gcloud beta run domain-mappings describe auth.osolab-auth.jp \
  --region=us-west1 \
  --format="table(status.conditions.type,status.conditions.status,status.conditions.reason,status.conditions.message)"
```

疎通確認:

```bash
curl -i https://auth.osolab-auth.jp/Version
```

`HTTP/2 200` と `{"statusCode":"00000","message":"OK",...}` が返れば、domain mapping は動作しています。

Cloud Run domain mapping は手軽ですが、Google は production workload では External Application Load Balancer の利用も推奨しています。
Cloud CDN、Cloud Armor、細かい TLS 制御が必要になったら Load Balancer 構成へ移行します。

## 10. Cloudflare を使う場合

Cloudflare は使えます。
ただし最初は Cloudflare の proxy を切った `DNS only` で Cloud Run domain mapping と Google managed certificate を安定させます。

推奨する初期構成:

```text
User
  -> Cloudflare DNS only
  -> auth.osolab-auth.jp
  -> Cloud Run domain mapping
  -> authfoundation-api
  -> VM: SQL Server / Redis
```

Cloudflare で proxy を有効化する場合:

```text
User
  -> Cloudflare proxy
  -> auth.osolab-auth.jp
  -> Cloud Run domain mapping
  -> authfoundation-api
```

### 現在の構成での注意点

`asia-northeast1` へ寄せる案は、DB VM も同じ region へ移す場合だけ採用します。
現在は Cloud Run、Artifact Registry、VM が `us-west1` なので、このまま `us-west1` で揃えます。

```text
Cloud Run: us-west1
Artifact Registry: us-west1
VM: us-west1
```

GitHub Actions の GCP 認証は JSON key ではなく Workload Identity Federation を使います。
JSON key は漏えい時の影響が大きいので、この repo では使いません。

VM の private IP へ接続するため、Cloud Run には VPC 接続が必要です。
この手順では Serverless VPC Access connector ではなく Direct VPC egress を使っています。

```text
CLOUD_RUN_NETWORK=default
CLOUD_RUN_SUBNET=default
CLOUD_RUN_VPC_EGRESS=private-ranges-only
```

Cloud NAT はこの構成では不要です。
Cloudflare Tunnel も Cloud Run を公開するだけなら不要です。

### Cloudflare DNS の設定

Cloud Run domain mapping 作成後に表示される DNS record を Cloudflare に入れます。
subdomain の場合は通常 CNAME が表示されます。

例:

```text
Type: CNAME
Name: auth
Target: ghs.googlehosted.com
Proxy status: DNS only
```

実際の値は必ず次のコマンドの `resourceRecords` に合わせます。

```bash
gcloud beta run domain-mappings describe auth.osolab-auth.jp \
  --region=us-west1 \
  --format="yaml(resourceRecords,status.conditions)"
```

### Cloudflare proxy を ON にするタイミング

まず DNS only のまま確認します。

```bash
curl -i https://auth.osolab-auth.jp/Version
```

`HTTP/2 200` が返り、Cloud Run 側の certificate が Ready になってから、Cloudflare の proxy status を `Proxied` に変更します。

Cloudflare proxy を使う場合の推奨:

```text
SSL/TLS encryption mode: Full (strict)
Always Use HTTPS: Off
DNS record: Proxied
```

Google の Cloud Run domain mapping docs では、Cloudflare CDN を使う場合は Cloudflare の `Always Use HTTPS` を無効化するよう案内されています。
証明書発行や更新で詰まる場合は、いったん `DNS only` に戻して certificate が Ready になるまで待ちます。

### Cloudflare を使っても残る注意

Cloudflare proxy を ON にしても、Cloud Run の `run.app` URL は別経路として残ります。
完全に Cloudflare 経由だけに寄せたい場合は、External Application Load Balancer、serverless NEG、Cloud Armor などを使う構成に切り替えます。

まずは次の順で進めます。

```text
1. Cloud Run domain mapping を作る
2. Cloudflare DNS に DNS only で record を入れる
3. https://auth.osolab-auth.jp/Version が 200 になることを確認する
4. 必要なら Cloudflare proxy を ON にする
```

## 11. Other Cloud Run apps

AuthFoundation 以外の静的 UI も同じ Artifact Registry / Cloud Run / GitHub Actions 構成で deploy できます。

対象:

```text
D:\portfolio\oidc-sample-client
D:\portfolio\osolab-inner-client-ui
```

追加済みのファイル:

```text
.github/workflows/deploy-cloud-run.yml
.dockerignore
deploy/github-actions.variables.json
deploy/github-actions.secrets.example.json
```

想定する Cloud Run service:

```text
oidc-sample-client
osolab-inner-client-ui
```

### GCP Workload Identity に repo を追加する

`github-auth-deployer` は現在 `Takeru-k7a/Auth` だけ許可しています。
別 repo から deploy する場合は、対象 repo も許可します。

Cloud Shell:

```bash
PROJECT_ID=osolab
PROJECT_NUMBER=210279746180
DEPLOYER_SA=github-auth-deployer

gcloud iam workload-identity-pools providers update-oidc github \
  --location=global \
  --workload-identity-pool=github-actions \
  --attribute-condition="attribute.repository=='Takeru-k7a/Auth' || attribute.repository=='Takeru-k7a/oidc-sample-client' || attribute.repository=='Takeru-k7a/osolab-inner-client-ui'"

for repo in Takeru-k7a/oidc-sample-client Takeru-k7a/osolab-inner-client-ui; do
  gcloud iam service-accounts add-iam-policy-binding \
    "${DEPLOYER_SA}@${PROJECT_ID}.iam.gserviceaccount.com" \
    --role="roles/iam.workloadIdentityUser" \
    --member="principalSet://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/github-actions/attribute.repository/${repo}"
done
```

`osolab-inner-client-ui` がまだ GitHub repo になっていない場合は、先に repo を作って push します。

### GitHub Variables / Secrets を投入する

Auth repo の script を使って、別 repo にも一括投入できます。

OIDC sample client:

```powershell
cd D:\portfolio\Auth

Copy-Item D:\portfolio\oidc-sample-client\deploy\github-actions.secrets.example.json `
  D:\portfolio\oidc-sample-client\deploy\github-actions.secrets.json

powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\set-github-actions-config.ps1 `
  -Repo Takeru-k7a/oidc-sample-client `
  -VariablesFile D:\portfolio\oidc-sample-client\deploy\github-actions.variables.json `
  -SecretsFile D:\portfolio\oidc-sample-client\deploy\github-actions.secrets.json `
  -GhPath "C:\Program Files\GitHub CLI\gh.exe"
```

Inner client UI:

```powershell
cd D:\portfolio\Auth

Copy-Item D:\portfolio\osolab-inner-client-ui\deploy\github-actions.secrets.example.json `
  D:\portfolio\osolab-inner-client-ui\deploy\github-actions.secrets.json

powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\set-github-actions-config.ps1 `
  -Repo Takeru-k7a/osolab-inner-client-ui `
  -VariablesFile D:\portfolio\osolab-inner-client-ui\deploy\github-actions.variables.json `
  -SecretsFile D:\portfolio\osolab-inner-client-ui\deploy\github-actions.secrets.json `
  -GhPath "C:\Program Files\GitHub CLI\gh.exe"
```

### Deploy

各 repo の GitHub Actions から実行します。

```text
Actions
-> Build and Deploy OIDC Sample Client to Cloud Run
-> Run workflow
```

```text
Actions
-> Build and Deploy Inner Client UI to Cloud Run
-> Run workflow
```

### API route の注意

この手順で Cloud Run に静的ファイルは deploy できます。
ただし API 呼び出しは別途整理が必要です。

```text
oidc-sample-client:
  デフォルト値が local URL 前提です。
  auth.osolab-auth.jp 向けに入力値を変えるか、nginx proxy / CORS を設定します。

osolab-inner-client-ui:
  /inner-api/... を reverse proxy で AuthFoundation の /inner/... に中継する前提です。
  単体 Cloud Run では nginx proxy 設定を追加するか、API URL と CORS を整理します。
```
