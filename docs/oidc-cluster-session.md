# OIDC session store in a cluster

## What changed

The OIDC session used to live in a `tower-sessions` store inside the process that
performed the login. In a cluster that breaks: a request that reaches a router node
is proxied to a querier, and the querier cannot resolve a session that only exists in
another process — the request comes back `401 Unauthorized`.

The session now lives in the shared meta store (the `sessions` table), and the cookie
carries only the session id. Every node reads the same table, so a session created on
one node resolves on any other. This is the same arrangement the upstream Dex login
already uses, so the two authentication paths now share one session mechanism.

## Backend selection

No new environment variable was introduced. The backend follows the configuration that
already exists:

| `OIDC_SESSION_NAME` | `OIDC_REDIS_URL` | Backend | Cluster-safe |
|---|---|---|---|
| set | set | Redis | yes |
| set | not set | shared meta store | yes |
| not set | — | self-contained cookie | yes (no server-side session) |

Every backend is shared between the nodes of a cluster, so no configuration can leave a
session stranded in one process. A node that somehow ended up with a process-local
store refuses to start rather than serving requests it cannot authenticate.

## What to configure

Set `OIDC_SESSION_NAME` to the name of the session cookie, for example:

```
OIDC_SESSION_NAME=oidc_session
```

The value is also the cookie name, so it has to be a valid cookie name and the same on
every node.

The meta store must be reachable from every node — in a cluster that is already
required, since `ZO_META_POSTGRES_DSN` is what the cluster coordinator runs on.

To use Redis instead, set `OIDC_REDIS_URL` as well. It must be the same URL on every
node, and the `redis-session` Cargo feature must be enabled.

## The `sessions` table

The table is created by the migration chain, so a normal deployment needs no extra
step. `infra::table::sessions::create_table` creates it directly for setups that do
not run the migrations.

OIDC session rows are prefixed with `oidc_`, which keeps them apart from the Dex
session rows the enterprise build writes to the same table.

## The cookie key (`OIDC_SESSION_KEY`)
The OIDC cookies are sealed with a 64-byte key. Which key the nodes use depends on
`OIDC_SESSION_KEY`:

- **Unset:** the first node that starts generates one key and stores it in the
  shared meta db. Every node of the cluster reads that row, so all nodes seal and
  open the same cookies without any configuration.
- **Set:** the value must be the **same on every node**. It is base64 and has to
  decode to at least 32 bytes; a longer key is stretched to the 64 bytes the
  sealing needs. Anything shorter is a configuration error and stops the node at
  start-up.

A node that uses a different key than the others cannot read the cookies the others
issued, so its users look logged out and land on the login page.

Rotating the key is allowed: the old cookies stop being readable, so every user is
logged out once and has to sign in again.

## Behaviour notes

- The cookie holds a session id, never the tokens themselves.
- The session expires with the provider's `expires_in`, or with the cookie's max age
  when the provider does not state one.
- Logging out deletes the row, and the cluster coordinator propagates the deletion to
  the other nodes. The native logout endpoint does this too, so the session ends with
  the native one and a following native login is not shadowed by it.
- A token refresh rotates the row in place; the refreshed cookie is returned to the
  browser in the `Set-Cookie` header of the response.

## Ending the session at the provider

The session can also be ended at the identity provider, which sends the browser to the
provider's `end_session_endpoint`. This is **off by default** (`OIDC_ENABLE_RP_LOGOUT`),
because a provider may share one session across the applications of a realm: ending it
can sign the operator out of the other applications too. That decision belongs to the
administrator of the provider.

With `OIDC_ENABLE_RP_LOGOUT` set, the logout redirects to the provider's endpoint with
the `id_token_hint` of the current session and `post_logout_redirect_uri`
(`OIDC_LOGOUT_REDIRECT_URL`, default `/web/`). The hint identifies the one session that
belongs to this application, so the other applications of the realm keep theirs unless
the provider is configured to end all of them.
