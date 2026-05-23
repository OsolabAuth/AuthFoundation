# Gmail SMTP Runbook

Last updated: 2026-05-23
Related issues: #15, #13

## Purpose

- Keep Gmail SMTP settings consistent across local / Cloud Run.
- Rotate app password safely when leakage or auth failure is suspected.
- Provide a fixed verification procedure after secret updates.

## Runtime config keys

AuthFoundation reads these keys:

- `Mail:FromEmail`
- `GmailSmtp:Host` (default: `smtp.gmail.com`)
- `GmailSmtp:Port` (default: `587`)
- `GmailSmtp:Username`
- `GmailSmtp:AppPassword`
- `GmailSmtp:EnableSsl` (default: `true`)

Cloud Run secret mapping (recommended):

```text
Mail__FromEmail=auth-mail-from-email:latest
GmailSmtp__Username=auth-gmail-smtp-username:latest
GmailSmtp__AppPassword=auth-gmail-smtp-app-password:latest
```

## Rotation procedure

1. Generate a new Gmail app password in Google Account security settings.
2. Add a new Secret Manager version:

```bash
printf '%s' '<new-app-password>' \
  | gcloud secrets versions add auth-gmail-smtp-app-password \
    --project=osolab \
    --data-file=-
```

3. Trigger Cloud Run deploy workflow (or `gcloud run deploy`) with unchanged `CLOUD_RUN_UPDATE_SECRETS`.
4. Verify signup mail delivery (`POST /signup/email`) on production-like environment.
5. Disable the old Gmail app password in Google Account.

## Verification checklist

1. API response for `POST /signup/email` is `200` + `StatusCode=00000`.
2. Mail is actually delivered to a non-dummy address.
3. Cloud Run logs do not contain `GmailSmtpMail.SendMailFailed`.
4. No `90000` internal errors are returned by signup flow.

## Incident triage

When mail sending fails:

1. Check recent API logs for send failures:

```bash
gcloud logging read \
  'resource.type="cloud_run_revision" AND resource.labels.service_name="authfoundation-api" AND textPayload:"GmailSmtpMail.SendMailFailed"' \
  --project=osolab \
  --limit=50 \
  --format='value(timestamp,textPayload)'
```

2. Confirm secret mapping exists in Cloud Run service:

```bash
gcloud run services describe authfoundation-api \
  --region=us-west1 \
  --format='yaml(spec.template.spec.containers[0].env)'
```

3. Verify the referenced secret name/version exists.
4. If app password was rotated recently, redeploy to ensure latest revision picks the new version.
