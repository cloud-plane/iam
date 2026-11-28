# 49. OAuth2 JWT as a Keystone token format

**Date:** 2026-11-26

## Status

Proposed

## Reference

Amends ADR 0026 (section 10 phase 0, section 13 stages 2 and 5). Related: ADR
0036 (service delegation), ADR 0041 (OAuth2 sessions), ADR 0043 (DPoP), ADR 0045
(global IAM mesh), ADR 0047 (table version watermarks),
`doc/src/contributor/security-model.md`.

## Context

Keystone has two token systems that do not know each other:

- The token provider (`[token] provider = fernet | jws`) issues and validates
  the tokens of the v3 API. Both formats are _references_: they carry the user,
  the scope and the audit chain, and Keystone resolves everything else on every
  request. The token travels in `X-Auth-Token`.
- The OAuth2 provider (ADR 0026) issues signed JWT access tokens with per-domain
  keys from the `oauth2-key` driver. Keystone itself accepts such a token only
  at `/userinfo`, `/introspect` and as an SVID-bound bearer on the internal
  interface (ADR 0036 section 8.1). Everywhere else the `Auth` extractor reads
  `X-Auth-Token` through the token provider only.

ADR 0026 section 13 plans a migration to JWT, but it leaves Keystone's own API
out and relies on a downstream middleware that is not in this repository. A
deployment therefore cannot move to OAuth2 tokens without changing every client
at once. ADR 0045 adds a second reason to change: a user is authenticated by the
authority they belong to, not by the scope of the token. A token that says who
the user is (`iss`, `sub`) fits that; a format that only works with a local user
record does not.

## Decision

The OAuth2 JWT becomes the third token format Keystone issues and accepts. The
switch is seamless: clients keep sending `X-Auth-Token`, and the password and
every other v3 authentication method keep working and return the new format.

### 1. Three formats, one entry point

`X-Auth-Token` may carry a Fernet token, a legacy JWS token or an OAuth2 JWT.
`Authorization: Bearer <OAuth2 JWT>` is accepted in addition and never instead
of `X-Auth-Token`. The SVID-bound bearer path of ADR 0036 is unchanged.

The format is detected from the shape of the credential, without trusting it:

| Credential                                          | Format |
| --------------------------------------------------- | ------ |
| no `.`                                              | Fernet |
| three segments, header without `typ: at+jwt`        | JWS    |
| three segments, header `typ: at+jwt`, payload `iss` | OAuth2 |

The detected format selects exactly one verifier. There is no fallthrough from
one format to the next, and the OAuth2 verifier pins the algorithm to the
domain's configured one (ADR 0026 section 3). A credential that is detected as a
format that is not accepted is rejected as an unauthorized token.

### 2. Issuing and accepting are configured separately

```ini
[token]
provider = oauth2        # fernet | jws | oauth2 (issuing)
accepted = fernet, jws, oauth2   # validating, default: the provider only
```

Default `accepted` is the issuing `provider` plus the formats whose key
repository is configured, so an existing deployment behaves exactly as before. A
staged migration is `provider = oauth2` with `accepted` listing all three, then
removing `fernet` and `jws` once no old token can be alive (ADR 0026 stage 5).
Removing a format is a pure configuration change.

### 3. The JWT is an anchor, not a bag of roles

Like a Fernet token, the OAuth2 token for Keystone's own API names the user, the
scope and the authentication chain; it does not embed roles. Keystone resolves
the effective roles, the enabled state and the revocation on every request. A
token issued for downstream offline verification (ADR 0026 section 6) keeps its
roles; the two are told apart by the audience (`keystone`, exact).

The format has its own compact claim set. It is not the Python-compatible JWS
layout (`openstack_*` names), which stays the wire format of the JWS driver
only. The claims are `iss`, `sub`, `aud`, `exp`, `iat`, `jti`, `amr` (the
authentication methods), `aid` (the audit ids), the optional `ks_scope`, `chain`
and `cnf`. There is no `nbf` (it would equal `iat`) and no `token_use`:
the exact `aud` and the `typ: at+jwt` header tell the token from the other
tokens of the OAuth2 provider.

`ks_scope` and `chain` are enums with exactly one variant on the wire, so a
token cannot name two scopes or two chain kinds, and a chain fact cannot be read
as a scope:

| Claim      | Wire                                                           |
| ---------- | -------------------------------------------------------------- |
| `ks_scope` | `{"project": id}`, `{"domain": id}` or `{"system": id}`        |
| `chain`    | `{"trust": id}`, `{"app_cred": id}`, `{"restricted": {...}}`, `{"federated": {...}}` |

The chain is how the user got the token. Absent means a plain authentication.

- `trust` and `app_cred` need a project scope.
- `restricted` is `{"id": id, "renew": true, "rescope": true}` (the flags are
  omitted when false) and needs a project scope. It is the keystone-rs only token
  restriction; its roles are resolved live from `id`.
- `federated` is `{"idp": id, "proto": id, "grp": [group ids]}` and takes no
  scope, a project scope or a domain scope. Only identifiers travel in the
  token, never IdP attributes (ADR 0045 keeps the same line across authorities).
  The groups are the mapping result at login and are frozen for the life of the
  token, as in Fernet; their role assignments are resolved live. A login that
  resolves more than `[token] max_federation_groups` (default 50) fails: the
  list is never truncated, because a dropped group silently drops its roles. A
  server-side session reference (ADR 0041) for large group sets is an open item.
- A federated chain counts as a plain authentication for the on-behalf-of
  exchange of ADR 0036 section 6.2: the user authenticated, nothing was
  delegated.

The scope is an anchor kept for the gradual migration of v3 clients, which
expect a scoped token. It is optional: the unscoped token has no `ks_scope`, and
the scope-less token of the vision document (section 5) is this same format
without it. The claim is not named `scope`, which RFC 9068 reserves for the
space-delimited OAuth2 scopes.

Security decisions are keyed on the authentication chain in the claims
(`DelegationContext`), never on the scope, as the security model requires.

### 4. The `TokenPayload` is what the token resolves to

`TokenPayload` stays the result of decoding, whatever the wire format. The
OAuth2 format adds two things to it, both optional and absent for Fernet and
JWS:

- `cnf` (the DPoP thumbprint, ADR 0043). Decoding puts it on the
  `SecurityContext` (`confirmation`), next to the token it belongs to. The
  extractor enforces the binding exactly as it does for the v4 endpoints; a
  bound token without a matching proof is rejected. A bound token is accepted
  in `X-Auth-Token` or `Authorization: DPoP`, which carries no scheme to
  tell it apart, with a valid proof in both cases. An unbound token cannot
  be presented as `DPoP`. Validating a token with `GET /v3/auth/tokens`
  carries no proof of the subject token, so the response exposes `cnf.jkt` for
  a bound token and the validating service must treat it as usable only with
  a proof of that key.
- the issuing domain (`iss`), needed to pick the verification key.

The binding is a property of the presented token, not of the user's session.
Every path that takes a Keystone token as a credential value (the `token`
authentication method of `POST /v3/auth/tokens`, the `subject_token` of the
token exchange and of the on-behalf-of exchange of ADR 0036) carries it where
no proof of it exists, so each refuses a bound token through one helper
(`token::ensure_unbound`): the exchange would otherwise hand an unbound token
or credential to anyone holding the bytes. Showing or revoking a token by
`X-Subject-Token` mints nothing and is not affected.
A token issued from a bound one is bound only by a proof sent with the issuing
request, and a proof sent to a deployment that does not issue OAuth2 tokens is
refused instead of ignored. Re-scoping a bound token is an open item.

### 5. Which key signs a token issued by the v3 API

The issuer is a domain (`/v4/oauth2/{domain_id}`). A token issued by the v3 API
is signed with the key of the **user's domain**: it always exists and is
deterministic, unlike a scope domain, which a system or unscoped token does not
have. The verifier selects the key by `iss` and `kid`, so a token from another
domain, or from another authority in the mesh (ADR 0045 section 5), is checked
against the keys of its own issuer. The domain must have signing keys; domain
creation provisions them (ADR 0026 section 3) and the `default` domain is
provisioned at bootstrap. Issuing fails closed when the keys are missing.

Keys are provisioned lazily. The `default` domain is seeded at bootstrap, not
created through the API, and the provisioning of a new domain is asynchronous,
so a domain may have no keys when its first user logs in. Issuing then
provisions them (idempotent) and signs, instead of failing the login.
Verification never provisions: no keys for an `iss` is an invalid token.

The verifier pins the algorithm to the configured `[oauth2] signing_algorithm`
(ADR 0026 section 3). Changing it invalidates the live tokens of the previous
algorithm, so it is a migration step like removing a format from `accepted`.

Errors keep their meaning: a token that does not verify is an unauthorized
token, while a key store outage is a server error, not an invalid token.

### 6. Validation order

1. Detect the format and check it is accepted.
2. Verify signature, `iss`, `aud`, `exp`/`nbf` and the algorithm.
3. Check the `jti` against the revoked-`jti` set and the audit chain against the
   revocation provider, as for Fernet (ADR 0047 watermarks keep this cheap).
4. Build the `SecurityContext` from the authentication chain and resolve the
   user, scope and roles live.

### 7. Revocation and expiry

Because roles and state are resolved live (section 3), the revocation semantics
of Fernet are preserved on Keystone's own API, and no revocation window is
introduced there. The window of ADR 0026 section 11 applies to downstream
services that verify offline, as before.

### 8. Deprecation of JWS and Fernet

Neither format is converted: they stay as separate drivers behind the
`TokenBackend` trait. They are retired by removing them from `accepted`, after
the last token has expired. JWS keeps being the Python-parity format and nothing
more.

## Implementation plan

1. **Config and detection.** Add `oauth2` to `TokenProviderDriver`, the
   `accepted` list, and a format sniffer in the token service. `TokenService`
   holds a backend per accepted format instead of a single driver.
2. **Async OAuth2 backend.** The `TokenBackend` trait is synchronous and
   stateless; the OAuth2 keys are neither (per-domain, raft backed). The format
   is a driver of its own, `token-driver-oauth2`, behind a dedicated async
   trait `TokenFormatBackend` (`decode` and `encode` take the service state;
   `decode` returns the token and the `cnf` of the verified claims, so the
   sender constraint is never re-read from the credential). `TokenService`
   holds it next to the sync backends, so the trait and the drivers of Fernet
   and JWS are not changed. A JWKS cache over the `oauth2-key` provider is
   open item 2.
3. **Issuing.** `issue_token_context` mints the OAuth2 JWT for
   `provider = oauth2`; every authentication method that returns a token keeps
   doing so.
4. **Extractor.** `X-Auth-Token` and `Authorization: Bearer` route to the token
   service; the DPoP check moves in.
5. **Docs and metrics.** The format label on the token metrics (ADR 0031), the
   admin guide and the migration runbook.

## Consequences

### Positive

- One switch (`provider = oauth2`) moves a deployment to OAuth2 tokens with no
  client change; the old tokens keep working until they expire.
- The same token is usable by Keystone and, with the downstream audience, by
  services that verify it offline.
- Fits the mesh: a token names its issuer, so a foreign authority's token is not
  a special case.

### Negative

- A JWT is larger than a Fernet token; the sizes against typical header limits
  must be measured and documented.
- Two key lifecycles (OAuth2 per-domain and Fernet/JWS filesystem) run during
  the migration, as in ADR 0026 section 11.
- Token validation by the extractor becomes async in the key lookup; the JWKS
  cache must be invalidated on rotation and on emergency rotation.

## Open items

1. Token size against header limits of the common services.
2. A JWKS and revocation cache for validation. Every validation reads the
   domain's keys and revoked `jti` set, and a forged `iss` costs a lookup. A
   cache must be dropped on rotation and, at once on every node, on emergency
   rotation, which needs a cross-node signal (ADR 0047 watermarks) and a
   negative cache for unknown issuers. A point lookup of the `jti` replaces
   loading the set.
3. Re-scoping of a DPoP-bound token (the `token` method refuses it).
4. Server-side session reference for federated logins with many groups.
5. Mesh: the issuer registry for foreign `iss` (ADR 0045 section 5).
