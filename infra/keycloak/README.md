# Keycloak (infra)

Runtime Keycloak image pin and compose wiring live in `docker-compose.keycloak.yml`. Realm exports, OIDC clients, and the `ngn-sip-lab` realm configuration are maintained under `identity/keycloak/` (not this directory).

This `infra/keycloak/` path holds service-level Dockerfile or runtime overrides when present. For SSO architecture, client matrix, and hardening gaps see `docs/sso/keycloak_architecture.md` and `docs/security/oauth_hardening_checklist.md`.
