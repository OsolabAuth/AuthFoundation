# Redirect URI Policy

Last updated: 2026-05-23
Related issue: #9

## Scope

- Endpoint: `GET /authorize`
- Validation implementation: `Helper.CertAuthorizeClient`

## Allowed URI rules

`redirect_uri` must satisfy all of the following:

1. Absolute URI.
2. No fragment (`#...`) is allowed.
3. Scheme/host constraints:
   - `https://` is allowed for normal environments.
   - `http://` is allowed only for local development hosts:
     - `localhost`
     - `osolab-*-local` (hyphen style only)
4. The exact URI must be pre-registered in `auth.client_redirect_uri` as active.

## Explicitly rejected examples

- `http://evil.example.com/callback`
- `https://client.example.com/callback#token`
- `http://osolab-portal.local:5173/callback` (`.local` style is not allowed)
- Any unregistered URI even if format looks valid

## Operational notes

1. Register local dev URIs explicitly per client.
2. Do not loosen `http` allowance beyond the two host patterns above.
3. Use HTTPS URI for staging/production clients.
4. If new local host patterns are required, update both:
   - `Code.HttpQueries.REDIRECT_URI` regex
   - `Helper.CertAuthorizeClient` host validation
   - related unit tests
