# Fork Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **OIDC org/role gate never ran in production:** `validate_user_info` looked for an
  `api` segment in the request path to find the target organisation, but axum strips
  the `/api` nest prefix before the auth middleware sees the request. The path the
  middleware actually sees starts at the organisation (`/<org_id>/...`), so the gate
  silently never fired and every OIDC user was allowed to write. The organisation is
  now resolved from the path the middleware really gets: the first segment for the
  ordinary API routes, the second for `/v2/<org_id>/...`.
  The authorisation tests now use those real paths instead of a `/api`-prefixed
  fixture that does not exist in production.
- **OIDC org/role gate now covers short paths too:** the gate used to need three
  path segments, so `/<org_id>/streams` and the one-segment paths fell through
  unchecked. It now applies to every path that names an organisation, whatever
  its length.
- **OIDC logout landed on the callback URL:** `post_logout_redirect_uri` pointed at
  `OIDC_CALLBACK_URL`, which is the OIDC callback route. The provider sent the
  browser there after the logout, and the callback rejected the request with
  `OIDC state cookie missing` because a logout round trip carries no state cookie.
  The new `OIDC_LOGOUT_REDIRECT_URL` names the landing page instead; it defaults to
  `/web/` and may be given as an absolute URL, which some providers (Keycloak)
  require.
- **An unknown role in an OIDC claim became `admin`:** a role name the identity
  provider sent that is not a known role was silently upgraded to `admin` in the
  database, while the request gate rejected the same claim with `403`. Such a role
  now lands on `user` in the database; `OIDC_DEFAULT_ROLE` applies only when the
  claim carries no role at all.
- **OIDC start-up ignored a broken configuration:** an invalid `OIDC_DEFAULT_ROLE`,
  an unparsable `OIDC_ORG_CLAIM_PATTERN` or a malformed `OIDC_SESSION_KEY` was
  logged and the node kept running, so the operator saw "OIDC does not work"
  instead of a failed start. A configuration error now stops the node. An identity
  provider that cannot be reached still does not: the OIDC login stays unavailable
  and the native login keeps working.
- **OIDC sessions in a cluster:** a request proxied from a router node to a querier
  no longer comes back unauthorized. The OIDC session was kept in a `tower-sessions`
  store inside the process that performed the login, so any other node of the
  cluster could not resolve it. The session now lives in the shared meta store
  (the `sessions` table), which every node reads, and the cookie carries only the
  session id — the same arrangement the upstream Dex login already uses. The
  backend is picked from the existing configuration: `OIDC_SESSION_NAME` without
  `OIDC_REDIS_URL` selects the meta store, `OIDC_REDIS_URL` still selects Redis,
  and a configuration with neither still uses the self-contained cookie.
- **OIDC token refresh:** a refreshed token set is now the one that gets stored.
  The previous code stored the tokens the session already had, so a provider that
  rotates the refresh token left the session holding a token it had already
  invalidated. The refresh also keeps the session id the browser holds, instead of
  minting a new one and orphaning the old row.
- **OIDC logout left the session alive:** the logout endpoint cleared only the
  native `auth_tokens` and `auth_ext` cookies, so the OIDC session row stayed in the
  meta store and its cookie stayed in the browser. The next request was still
  authenticated as the OIDC user, even after signing in as root. The logout now
  drops the OIDC session and expires its cookie.
- **OIDC start-up with a shared-meta-store session:** the node no longer panics
  with `oidc::session::init_layer must be awaited before get_layer`. The SSO
  routes asked for the `tower-sessions` layer unconditionally, but that layer is
  only built for the Redis store — the meta store keeps the session in the
  database and needs no layer.
- **OIDC cookies were readable and forgeable:** the self-contained token cookie
  carried the access, refresh and id tokens as plain base64, so anybody with the
  browser could read them and tamper with them. The cookie payload is now sealed
  with authenticated encryption (AES-256-GCM) and the `tower-sessions` cookie
  uses the same private (encrypted) mode instead of plaintext. The key is 64
  bytes: `OIDC_SESSION_KEY` may still supply it, and when it is unset one key is
  generated and stored in the shared meta db so every node of the cluster seals
  and opens the same cookies. The dead `SessionConfig.session_key` field and the
  all-zero default key are gone.

### Added

- **`OIDC_ENABLE_RP_LOGOUT`:** a logout can end the session at the identity provider
  as well. Off by default: a provider may share one session across the applications
  of a realm, so ending it can sign the operator out of the other ones too.

- **CI publishes one image per commit:** the build now pushes only the immutable
  `:sha-<short>` tag, and the moving tags (`latest`, `dev`, `nightly`) and the release
  tag are attached to that same image afterwards. A release tag therefore no longer
  rebuilds the image, and pushing the same commit to `master`, `eo-dev` and a release
  tag costs one build instead of three. A `concurrency` group cancels an outdated
  build of the same branch instead of queueing it behind the new one.
- **`eo-dev-*` branches stay for intermediate builds:** they publish only the
  `:sha-<short>` tag, so a work-in-progress branch can be tried out without touching
  `latest` or `dev`.

### Fixed

- **OIDC release builds failed with the `redis-session` feature:** the error
  constructor takes an `impl Into<String>`, and the explicit `.into()` on a string
  literal became ambiguous once `cookie` pulled in `unicase`, which has a second
  `Into<String>` implementation. The release build of the `sso-redis` feature
  therefore did not compile.
- **`OIDC_SESSION_KEY` of an existing length no longer breaks the start:** the key
  has to provide the 64 bytes `cookie` needs, and a shorter configured secret was
  refused outright. A secret of at least 32 bytes is now stretched to the required
  length, so a deployment that already had a key keeps working.

- **`OIDC_DEFAULT_ROLE`:** the role an OIDC user gets when the claim carries none.
  A claim pattern without a `role` capture group is now a valid configuration
  instead of one that silently downgraded every user to `User`; such a pattern
  gives every organisation the default role, and a pattern with a `role` group
  still wins. An unknown role name is a configuration error at start-up.
- **RP-initiated logout:** `/auth/sso/logout` now ends the session at the identity
  provider as well, so the next `/auth/sso/login` does not silently log the user
  back in. The `end_session_endpoint` is read from the discovery document and
  called with `id_token_hint` and `post_logout_redirect_uri`. `OIDC_LOGOUT_URL`
  overrides the discovered endpoint.
- **`OIDC_LOGOUT_REDIRECT_URL`:** the landing page the provider sends the browser
  back to after the logout. It defaults to `/web/`; a relative value is resolved
  against the origin of `OIDC_REDIRECT_URL`, an absolute one is used as is.
- **`infra::table::sessions::create_table`:** creates the `sessions` table when it
  is missing, for setups that do not run the migration chain.

## [eo-v1.1.2] - 2026-10-30

**Upstream Baseline:** `v1.1.2`

Fork rebased onto upstream `v1.1.2`. The fork history was rebuilt as four canonical
layers so future upstream syncs stay reviewable:

1. `feat(fork)` — isolated fork modules, brand config, changelog
2. `feat(integration)` — fork features wired into the upstream server and UI
3. `chore(rebrand)` — ExposedObserve branding, vendor promo stripped
4. `chore(lock)` — dependency lockfiles regenerated

### Changed

- **Upstream sync:** the fork stack was rebased from `v1.1.0-rc2` onto `v1.1.2`
  and re-split into the four layers above. Upstream code, workflows and assets
  are otherwise unchanged from the tag.
- **Fork modules (`src/oidc/`, brand config, fork tooling):** carried over unchanged.
- **Feature integration:** OIDC routes, SSO middleware, `sso_enabled` bootstrap flag
  and the CE login SSO button are wired against the `v1.1.2` server and router.
- **Rebrand:** `[[bin]]` target `exposedobserve`, package metadata, CLI help, startup
  logs, telemetry event names and synthetics alert subjects.
- **License attribution:** every upstream file modified by the fork now carries a
  `Modifications Copyright` line under the untouched upstream copyright. The
  `scripts/check-license-headers.py` tool audits and repairs those headers.

### Removed

- Upstream enterprise upgrade CTA, `EnterpriseUpgradeDialog` and its spec.
- Upstream CI/CD workflows, issue templates and GitHub automation under `.github/`
  (replaced by the fork's own Docker publish workflow).
- Upstream vendor logo, banner and wordmark assets; `download.sh` / `downloadO2.sh`.

## [eo-v1.1.0-rc2] - 2026-10-23
**Upstream Baseline:** `v1.1.0-rc2`

### Added (New Fork Functionality — not in upstream tag)

- **OIDC / SSO (`src/oidc/`):** standalone OIDC crate with provider discovery, PKCE
  authorization-code flow, id_token verification, claim-to-user mapping, and
  token persistence. Routes: `/auth/sso/login`, `/auth/sso/callback`, `/auth/sso/logout`.
- **OIDC session backends (`src/oidc/src/store.rs`, `src/oidc/src/session.rs`):** cookie
  store by default, Redis store behind the `redis-session` Cargo feature; the backend is
  selected from a non-empty `OIDC_REDIS_URL`.
- **OIDC config (`src/oidc/src/config.rs`):** `OIDC_ISSUER_URL`, `OIDC_CLIENT_ID`,
  `OIDC_CLIENT_SECRET`, `OIDC_REDIRECT_URL`, `OIDC_CALLBACK_URL`, `OIDC_LOGOUT_URL`,
  `OIDC_SESSION_NAME`, `OIDC_REDIS_URL`, `OIDC_ORG_CLAIM`, `OIDC_ORG_CLAIM_PATTERN`,
  `OIDC_DEFAULT_ROLE`, `OIDC_EMAIL_CLAIM`,
  `OIDC_SUBJECT_CLAIM`, `OIDC_ORG_BLACKLIST`, `OIDC_COOKIE_*`, `OIDC_TIMEOUT`,
  `OIDC_INSECURE` and the Redis pool/timeout knobs.
- **SSO middleware (`src/api/http/src/handler/http/router/middlewares/sso.rs`):** OIDC-aware
  auth wrapper that falls back to the upstream `auth_middleware` for non-OIDC requests.
- **OIDC integration tests (`src/oidc/tests/`):** `oidc_flow` (in-process `wiremock`
  provider), `authorization`, `session`, `token_store`, plus shared fixtures in `common/`.
- **Brand Config (`web/src/constants/brand.ts`):** configurable product name and logo via
  `VITE_APP_NAME`, `VITE_LOGO_LIGHT`, `VITE_LOGO_DARK`; consumed through `aws-exports.ts`.
- **Fork assets:** `eo_logo_light.svg`, `eo_logo_dark.svg`, `favicon.svg`.
- **Fork tooling:** `Dockerfile`, `docker-compose.yml`, `docker/docker-compose.dev.yml`,
  `scripts/build/build-image.sh`, `.github/workflows/docker-publish.yml`, `FORK.md`,
  and the `fork-rebrand` / `fork-sync` / `fork-commit-prep` skills.

### Changed (Modified from upstream tag)

- **Feature Integration:** OIDC routes mounted on `/auth`, `oidc::init()` called at server
  startup, session layer attached to the HTTP router, `sso_enabled` surfaced through
  `zo_config_bootstrap` so the CE login screen can render the SSO button.
- **Cargo features:** `sso` (default) and `sso-redis`; new `oidc` workspace member and
  optional dependency wired through `openobserve-api-http`, `-api-common`, `-api-management`
  and `openobserve-core`.
- **Rebrand & Build:** `[[bin]]` target renamed to `exposedobserve`; package metadata,
  CLI help, startup logs, telemetry event names and synthetics alert subjects now say
  ExposedObserve; `document.title` and the HTML `<title>` follow the configured brand.
- **Build reproducibility (`src/config/build.rs`):** `GIT_VERSION` / `GIT_COMMIT_HASH`
  can be injected via the environment, so Docker builds work without `.git` in the context.
- **Docs:** `README.md`, `CONTRIBUTING.md` and `SECURITY.md` rewritten for the fork.

### Removed (Deleted from upstream tag)

- Stripped upstream enterprise upgrade CTA, the `EnterpriseUpgradeDialog` component and
  its spec, and the vendor trial/promo copy in the login onboarding screen.
- Removed upstream CI/CD workflows, issue templates and GitHub automation under
  `.github/` (replaced by the fork's own Docker publish workflow).
- Removed the upstream vendor logo, banner and wordmark assets, and the upstream
  `download.sh` / `downloadO2.sh` scripts.

[Unreleased]: https://github.com/ExposedObserve/ExposedObserve/compare/v0.0.1...HEAD
[0.0.1]: https://github.com/ExposedObserve/ExposedObserve/releases/tag/v0.0.1
[eo-v1.1.2]: https://github.com/ExposedObserve/ExposedObserve/compare/eo-v1.1.0-rc2...eo-v1.1.2
[eo-v1.1.0-rc2]: https://github.com/ExposedObserve/ExposedObserve/compare/v0.0.1...eo-v1.1.0-rc2

