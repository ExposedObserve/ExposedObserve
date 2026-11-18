# OIDC backlog

OIDC/SSO capabilities deferred to a future iteration of the ExposedObserve fork. Each
item lists the problem it addresses, the effort it requires, and the files it touches.

## 1. Token revocation and introspection

**Problem.** Session revocation is local only: the session row is deleted from
`sessions`. If the IdP revokes an access or refresh token, the application does not
learn about it until the `id_token` expires. The discovery document advertises
`revocation_endpoint` and `introspection_endpoint`, but the fork does not use them.

**Precedent in the code.** `HasRevocationUrl` and `HasIntrospectionUrl` in
`src/oidc/src/models.rs` are already parameterized as `EndpointNotSet`, so the
`openidconnect` crate supports these endpoints; the fork simply does not enable them.

**Affected files.** `src/oidc/src/client.rs`, `src/oidc/src/models.rs`,
`src/oidc/src/handlers.rs`, `src/oidc/src/store.rs`.

**Effort.** M

## 2. Background reconciliation of users and groups

**Problem.** Organization membership is synchronized only at login time
(`src/oidc/src/ext_users.rs`). If a user loses access in the IdP, they remain active
in the database until their next login. There is no background reconciliation, no
deactivation of external users, and no user deletion.

**Affected files.** `src/oidc/src/ext_users.rs`, `src/db/src/user.rs`,
`src/db/src/org_users.rs`, `src/jobs/` (schedule), `src/oidc/src/client.rs` (use
`retrieve_user_info_from_endpoint`, which is currently never called).

**Effort.** M

## 3. Multiple IdPs (several issuers)

**Problem.** There is one IdP per process: `static CONFIG: ArcSwap<OidcConfig>` in
`src/oidc/src/config.rs`, one `issuer_url`, one discovery cache `METADATA` in
`src/oidc/src/client.rs`, and one `OIDC_STORE` in `src/oidc/src/store.rs`. There is no
provider selection in the UI or in the login URL.

**Affected files.** `src/oidc/src/config.rs`, `src/oidc/src/client.rs`,
`src/oidc/src/store.rs`, `src/oidc/src/handlers.rs`,
`src/api/management/src/request/status/mod.rs`, `web/src/components/login/Login.vue`,
`web/src/utils/oidcutils.ts`.

**Effort.** L

## 4. User deletion when access is revoked

**Problem.** `db::org_users::remove_by_user` (`src/db/src/org_users.rs`) is not called
from the OIDC code. Removing a user from an organization when a claim disappears does
exist (`src/oidc/src/ext_users.rs`), but deleting the user itself does not. There is
no `disabled`/`deactivated` flag for external users.

**Affected files.** `src/oidc/src/ext_users.rs`, `src/db/src/user.rs`,
`src/db/src/org_users.rs`.

**Effort.** S

## Already implemented

A short list of what is implemented, to avoid duplicating work:

- Sessions live in the shared meta database (`sessions`) and are shared between the
  nodes of a cluster — `src/oidc/src/store.rs`
- Three backends: meta database (default), Redis, and a self-contained cookie —
  selected through `OIDC_SESSION_NAME` / `OIDC_REDIS_URL`
- Refresh token: the refreshed set is persisted and the session id does not change
- Fail-fast on startup when the store turns out to be process-local in a cluster —
  `src/api/http/src/server.rs`
