# GCP Cloud Run Deploy

AuthFoundation を Cloud Run に載せるための build/deploy 手順です。
RDB は SQL Server on VM、MDB は Redis on VM として扱い、Cloud Run には AuthFoundation のコンテナだけを置きます。

## 1. 初回だけ作る GCP リソース

```bash
PROJECT_ID=<your-project-id>
REGION=us-west1
REPOSITORY=auth

gcloud config set project "${PROJECT_ID}"

gcloud services enable \
  run.googleapis.com \
  artifactregistry.googleapis.com \
  cloudbuild.googleapis.com \
  secretmanager.googleapis.com \
  iamcredentials.googleapis.com \
  sts.googleapis.com

gcloud artifacts repositories create "${REPOSITORY}" \
  --repository-format=docker \
  --location="${REGION}" \
  --description="AuthFoundation container images"
```

## 2. GitHub Actions 用サービスアカウント

```bash
PROJECT_ID=<your-project-id>
PROJECT_NUMBER=$(gcloud projects describe "${PROJECT_ID}" --format="value(projectNumber)")
DEPLOYER_SA=github-auth-deployer
REPO=<github-owner>/<auth-repo-name>

gcloud iam service-accounts create "${DEPLOYER_SA}" \
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
```

Workload Identity Federation:

```bash
gcloud iam workload-identity-pools create github-actions \
  --location=global \
  --display-name="GitHub Actions"

gcloud iam workload-identity-pools providers create-oidc github \
  --location=global \
  --workload-identity-pool=github-actions \
  --display-name="GitHub" \
  --issuer-uri="https://token.actions.githubusercontent.com" \
  --attribute-mapping="google.subject=assertion.sub,attribute.repository=assertion.repository,attribute.owner=assertion.repository_owner" \
  --attribute-condition="attribute.repository=='${REPO}'"

gcloud iam service-accounts add-iam-policy-binding \
  "${DEPLOYER_SA}@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/iam.workloadIdentityUser" \
  --member="principalSet://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/github-actions/attribute.repository/${REPO}"
```

GitHub Secrets:

```text
GCP_WORKLOAD_IDENTITY_PROVIDER=projects/<project-number>/locations/global/workloadIdentityPools/github-actions/providers/github
GCP_SERVICE_ACCOUNT=github-auth-deployer@<project-id>.iam.gserviceaccount.com
```

GitHub Variables:

```text
GCP_PROJECT_ID=<project-id>
GCP_REGION=us-west1
ARTIFACT_REGISTRY_REPOSITORY=auth
CLOUD_RUN_SERVICE=authfoundation-api
CLOUD_RUN_IMAGE_NAME=authfoundation-api
AUTH_ISSUER=https://auth.osolab-auth.jp/
```

VM の内部 IP に Cloud Run から接続する場合は Direct VPC egress も指定します。

```text
CLOUD_RUN_NETWORK=<vpc-name>
CLOUD_RUN_SUBNET=<subnet-name>
CLOUD_RUN_VPC_EGRESS=private-ranges-only
```

## 3. Runtime secrets

DB/Redis/Brevo/PasswordHashKey は Secret Manager に置き、GitHub Variables の `CLOUD_RUN_UPDATE_SECRETS` に Cloud Run 用のマッピングを入れます。

例:

```text
CLOUD_RUN_UPDATE_SECRETS=ConnectionStrings__DefaultConnection=auth-db-connection:latest,ConnectionStrings__Redis=auth-redis-connection:latest,PasswordHashKey=auth-password-hash-key:latest,Brevo__ApiKey=brevo-api-key:latest,Brevo__SenderEmail=brevo-sender-email:latest
```

Secret の中身の例:

```text
auth-db-connection:
Server=<data-server-internal-ip>,1433;Database=OsolabAuth;User ID=sa;Password=<password>;TrustServerCertificate=True

auth-redis-connection:
<data-server-internal-ip>:6379
```

Cloud Run の runtime service account には Secret Manager Secret Accessor を付けます。
`CLOUD_RUN_SERVICE_ACCOUNT` を指定しない場合は、Cloud Run が使うデフォルトの service account に付けます。

```bash
PROJECT_ID=<your-project-id>
RUNTIME_SA=<runtime-service-account>@${PROJECT_ID}.iam.gserviceaccount.com

gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
  --member="serviceAccount:${RUNTIME_SA}" \
  --role="roles/secretmanager.secretAccessor"
```

## 4. Deploy

GitHub Actions の `Build and Deploy Auth to Cloud Run` を手動実行します。

- `deploy=true`: build, push, Cloud Run deploy
- `deploy=false`: build, push のみ
- `image_tag`: 空なら commit SHA

Cloud Run のコンテナポートは `8080` です。
`DisableHttpsRedirection=true` は workflow 側で常に入れます。

## 5. 手元で image だけ作る

GitHub Actions を待たず、手元の gcloud から Artifact Registry に image を作る場合:

```powershell
.\scripts\build-cloud-run-image.ps1 `
  -ProjectId <project-id> `
  -Region us-west1 `
  -Repository auth `
  -ImageName authfoundation-api
```

出力された image URI を Cloud Run のコンテナイメージ欄に入れます。

## 6. 確認

```bash
gcloud run services describe authfoundation-api \
  --region=us-west1 \
  --format="value(status.url)"

curl "$(gcloud run services describe authfoundation-api --region=us-west1 --format='value(status.url)')/Version"
```

VM 側の firewall は Cloud Run が使う subnet から `1433` と `6379` だけ許可します。
