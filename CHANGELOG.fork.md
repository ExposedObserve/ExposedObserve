# Fork Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
  `OIDC_CLIENT_SECRET`, `OIDC_REDIRECT_URL`, `OIDC_CALLBACK_URL`, `OIDC_SESSION_KEY`,
  `OIDC_SESSION_NAME`, `OIDC_REDIS_URL`, `OIDC_ORG_CLAIM`, `OIDC_EMAIL_CLAIM`,
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

