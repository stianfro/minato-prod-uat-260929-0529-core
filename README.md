# Production UAT core fixture

A dependency-free, synthetic Node.js web app. The source marker is baked as
`source-v2`. It listens on `PORT` (default 8080) and binds `0.0.0.0`.
The package selects Node 22.x, supported by the documented Node builder.

## Local checks

```sh
just check
PORT=8080 just run
```

`/healthz` answers only `ok`. All other routes require an `x-auth-oid` or
`x-auth-subject` header supplied by the authenticated gateway. These headers
are trusted only in that deployment context. This fixture does not turn off
platform SSO. Tests inject synthetic identities directly into the handler.

Routes return HTML for browser navigation or JSON for `Accept: application/json`:

- `/` and `/status`: baked source revision, `UAT_RELEASE` (default `env-v1`),
  identity-present boolean, and synthetic secret presence/equality booleans.
- `/probe`: exactly one GET to `https://example.com/`, a three-second abort,
  no redirect following, no request-header forwarding, no arbitrary URL inputs.
  Returns only reachability, HTTP status and a generic outcome. One in-flight
  probe per process is permitted. Other requests trigger no outbound activity.
- `/log-canary`: emits one fixed useful marker and fixed synthetic
  `Authorization`/`Cookie` canaries once per process. GET is intentional for
  this disposable UAT fixture. Repeating GET does not repeat logs on the same
  process. Real request headers and environment values are never logged.

The synthetic secret keys are `UAT_260929_CLI` and `UAT_260929_UI`.
Supply their expected SHA256 digests separately through harmless test env
`UAT_CLI_SHA256` and `UAT_UI_SHA256`. The app returns only `present` and
`matchesExpected` booleans. It never returns values or digests. No actual
secret values or expected digests are committed in this repository.

The app has no database, external package dependencies, background work,
analytics, arbitrary network fetch, or authorization-management functionality.
No real credentials, customer data, private code or internal URLs belong here.
