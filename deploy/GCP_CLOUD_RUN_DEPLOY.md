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

DB password、Redis 接続先、Brevo API key、`PasswordHashKey` は GitHub Secrets ではなく GCP Secret Manager に置きます。

Cloud Shell で実行例:

```bash
PROJECT_ID=osolab
DATA_SERVER_INTERNAL_IP=<data-server-internal-ip>
MSSQL_PASSWORD='<sqlserver-password>'
PASSWORD_HASH_KEY='<production-password-hash-key>'
BREVO_API_KEY='<brevo-api-key>'
BREVO_SENDER_EMAIL='<sender-email>'

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

printf '%s' "${BREVO_API_KEY}" \
  | gcloud secrets create brevo-api-key \
    --project="${PROJECT_ID}" \
    --replication-policy=automatic \
    --data-file=-

printf '%s' "${BREVO_SENDER_EMAIL}" \
  | gcloud secrets create brevo-sender-email \
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
CLOUD_RUN_UPDATE_SECRETS=ConnectionStrings__DefaultConnection=auth-db-connection:latest,ConnectionStrings__Redis=auth-redis-connection:latest,PasswordHashKey=auth-password-hash-key:latest,Brevo__ApiKey=brevo-api-key:latest,Brevo__SenderEmail=brevo-sender-email:latest
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
