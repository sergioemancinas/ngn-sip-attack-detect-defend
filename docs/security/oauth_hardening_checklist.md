# OAuth / Keycloak Hardening Checklist

Project-specific application of standard OAuth 2.0 / OIDC hardening principles (RFC 6749, RFC 7636 PKCE, RFC 8705 mTLS-bound tokens, RFC 9449 DPoP, OAuth 2.0 Security BCP draft-ietf-oauth-security-topics). Lab is dev-mode today; this list captures the gap between current state and a defensible production posture on the campus VM.

## 1. Secrets: per-client, rotated, never in repo

| Item | Current state | Hardening | Target |
|---|---|---|---|
| Per-client `client_secret` | All 4 app clients share `change-me-local-only` | Generate a unique 32-byte random secret per OIDC client (`wazuh-dashboard`, `grafana`, `shuffle`, `homer`); store in `.env` (gitignored) or sealed-secrets on VM | NGN-SSO.4 |
| Secret rotation | Manual / never | Quarterly rotation runbook; Keycloak supports rotation without client downtime if the client supports two-active-secrets window | open |
| KEYCLOAK_ADMIN password | `change-me-local-only` | Replace with 24-char generated on first boot; store hash in sealed-secret | open |
| Repo scan | Gitleaks live on CI | Keep `.gitleaks.toml` allowlist tight; no real secrets should hit `main` | live ✓ |

## 2. Token lifetimes: short, scoped, revocable

| Item | Current state | Hardening | Target |
|---|---|---|---|
| Access token TTL | Keycloak default 5 min | Keep at 5 min for browser flows; 1 min for high-value backchannel | configurable per client |
| Refresh token TTL | Default 30 min | 8h max for browser, 7 days for service accounts (none of my clients use SA today) | per-client tuning |
| ID token TTL | Default 5 min | Tied to access token | OK |
| Grafana session lifetime | Hardened in `docker-compose.observability.yml` to 2h inactive / 8h max | Mirror across Wazuh dashboard once OIDC backend supports it | done for Grafana ✓ |
| Token revocation | Not used | Add UI / runbook for forced session logout via Keycloak admin API on incident | open |

## 3. Audience + issuer binding

| Item | Current state | Hardening |
|---|---|---|
| `aud` claim per token | Keycloak default emits the requesting `client_id` as `aud` | Validate `aud` on every resource server side (Wazuh indexer's OIDC backend already does this via `openid_connect_url` mapping) |
| `iss` claim validation | Wazuh + Grafana enforce against the metadata `issuer` field | Keep `KC_HOSTNAME_BACKCHANNEL_DYNAMIC=true` so issuer matches the request Host |
| Multi-tenant binding | No tenant claim today (single-tenant lab) | If multi-tenant later, add `realm_access.roles` + tenant claim per realm |

## 4. Replay protection + state cookies

| Item | Current state | Hardening |
|---|---|---|
| OAuth `state` parameter | All clients use OpenSearch / Grafana plugin defaults (random per request) | OK, verified in the Grafana OAuth state-cookie incident earlier today |
| State-cookie scope | Aligned to one origin (`localhost` only) | Document: always reach apps via `localhost`, never `127.0.0.1`. Cookie scope mismatch was the cause of the "Missing saved oauth state" error |
| `nonce` (ID token) | Plugin default | Verify in Wazuh dashboard logs |
| DPoP / proof-of-possession | Not in use; would require app-side library changes | Out of scope for now; future work |

## 5. Transport + reverse-proxy posture

| Item | Current state | Hardening |
|---|---|---|
| TLS for all browser endpoints | Wazuh dashboard yes (self-signed). Grafana, Keycloak, Shuffle all plain HTTP on loopback. | On campus VM: front everything with Traefik or nginx terminating step-CA certificate; OpenID `redirect_uri` must be the public FQDN, not `localhost` |
| `KC_HOSTNAME_STRICT` | `false` (dev mode) | Flip to `true` once `KC_HOSTNAME` points at the FQDN |
| `KC_PROXY=edge` | Not set | Set when behind a reverse proxy terminating TLS so Keycloak builds correct external URLs |
| Cookie flags | Grafana sets `SameSite=lax` + `Secure=false` (loopback) | Set `Secure=true` once HTTPS is end-to-end |

## 6. Edge controls + rate limiting

| Item | Current state | Hardening |
|---|---|---|
| Rate limit on `/realms/*/protocol/openid-connect/token` | None (dev) | Per Keycloak's adaptive brute-force-detector: enable in realm `Authentication → Bruteforce Detection`; tune for normal API-client burst |
| Account lockout | Disabled | Enable for `lab-admin` and any future user (5 failed → 15min lock) |
| Audit logging | Default Keycloak event types | Enable `LOGIN_ERROR`, `CODE_TO_TOKEN_ERROR`, `TOKEN_EXCHANGE`, `REVOKE_GRANT` events; ship to Vector → ClickHouse `ngn_sip.keycloak_events` (new table) |

## 7. Backend / JWKS handling

| Item | Current state | Hardening |
|---|---|---|
| JWKS cache | Default 10-min cache in OpenSearch Security plugin | Keep; rotate signing keys quarterly and ensure cache TTL < key rotation window |
| Signature algorithm | RS256 (Keycloak default) | OK, do not allow `none` or HS256 with shared secret |
| Key rotation | Manual via Keycloak admin | Document: rotate on a fixed schedule; verify clients re-fetch JWKS after rotation |

## 8. Gateway-trust boundaries

| Item | Current state | Hardening |
|---|---|---|
| Wazuh manager API behind dashboard | Dashboard calls manager API on behalf of OIDC user using `wazuh-wui` API account | OK pattern but lab-admin's UI calls always run as wazuh-wui; document this in the threat model |
| Indexer direct REST | Authenticates against OpenSearch Security with the OIDC subject's mapped roles | Working, confirmed via `/authinfo` test |
| Shuffle service-to-service calls | Shuffle workers call ClickHouse and kamcmd relay with org-scoped API keys, NOT user OAuth context | Acceptable for the lab; on the VM, swap to short-lived service-account token issued by Keycloak where supported |

## 9. Observability + detection

| Item | Current state | Hardening |
|---|---|---|
| Failed-login alerts | None | Add Wazuh rule SID 100150+ for `LOGIN_ERROR` from Keycloak events (requires event shipping) |
| Replay / nonce-mismatch detection | None | Once Vector ships Keycloak events to ClickHouse, add a query/Grafana panel for `error == 'invalid_request'` clusters |
| Token-issuance velocity | Not measured | Same, add `count() by client_id, hour` on Keycloak event table |

## 10. Disable + cleanup before campus-VM rollout

- [ ] Remove all `change-me-local-only` literals from compose env and `application.conf` files; substitute env from sealed-secret.
- [ ] Disable basic-auth fallback on every OIDC-enabled app (Wazuh: done ✓; Grafana: keep local admin as break-glass only).
- [ ] Reset `lab-admin` password to a strong value (the debug-era value was rotated out; never reuse documented passwords).
- [ ] Rotate every Keycloak client secret.
- [ ] Switch Keycloak from `start-dev` to `start` with `KC_HOSTNAME_STRICT=true`, `KC_HTTP_ENABLED=false`, `KC_PROXY=edge`.

## References

- RFC 6749: OAuth 2.0 framework.
- RFC 7636: PKCE.
- RFC 8705: OAuth 2.0 mTLS-bound access tokens.
- RFC 9449: OAuth 2.0 DPoP.
- IETF draft-ietf-oauth-security-topics: Security BCP.
- Keycloak Server Administration Guide (26.0): "Securing applications and services".
- OpenSearch Security plugin: OpenID Connect provider docs.
