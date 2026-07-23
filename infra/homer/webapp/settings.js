{
  "_ngn_note": "Template (not strict JSON) rendered by docker-compose.homer.yml via sed into /tmp/webapp_config.json. The double-underscore-wrapped tokens are substituted from env at container start; do not hand-parse this file as JSON.",
  "_sso_note": "Keycloak OIDC is prepared in oauth2 below and is inert by default (HOMER_OIDC_ENABLE=false). To enable, set the HOMER_OIDC_* vars in .env and run scripts/setup_keycloak_sso_clients.sh. See docs/sso/sso_runbook.md.",
  "database_data": {
    "LocalNode": {
      "help": "Settings for PGSQL Database (data)",
      "node": "LocalNode",
      "user": "homer_user",
      "pass": "__HOMER_DB_PASSWORD__",
      "name": "homer_data",
      "keepalive": true,
      "host": "homer-postgres"
    }
  },
  "database_config": {
    "help": "Settings for PGSQL Database (settings)",
    "node": "LocalConfig",
    "user": "homer_user",
    "pass": "__HOMER_DB_PASSWORD__",
    "name": "homer_config",
    "keepalive": true,
    "host": "homer-postgres"
  },
  "hep_relay": {
    "help": "UDP socket to send HEP data on",
    "host": "heplify-server",
    "port": 9060
  },
  "prometheus_config": {
    "help": "HEPlify-server Prometheus metrics endpoint",
    "user": "",
    "pass": "",
    "host": "http://heplify-server:9090",
    "api": "api/v1"
  },
  "http_settings": {
    "help": "Settings for the Homer webapp server",
    "host": "0.0.0.0",
    "port": 80,
    "root": "/usr/local/homer/dist",
    "gzip": true,
    "gzip_static": true,
    "debug": false
  },
  "https_settings": {
    "help": "TLS is terminated outside this local-only compose stack",
    "enable": false,
    "host": "0.0.0.0",
    "port": 443,
    "cert": "/usr/local/homer/tls/cert.pem",
    "key": "/usr/local/homer/tls/key.pem"
  },
  "system_settings": {
    "help": "Settings for Homer logs",
    "logpath": "/usr/local/homer/log",
    "logname": "homer-app.log",
    "_loglevels": "can be: fatal, error, warn, info, debug, trace",
    "loglevel": "warn",
    "logstdout": true
  },
  "auth_settings": {
    "_comment": "Internal DB auth stays the primary/fallback login. When oauth2.enable=true Homer additionally shows a Keycloak SSO button; internal auth keeps working until SSO is verified end-to-end.",
    "type": "internal",
    "token_expire": 1200
  },
  "local_admin": {
    "user": "admin",
    "pass": "__HOMER_ADMIN_PASSWORD__"
  },
  "oauth2": {
    "_comment": "Keycloak OIDC for Homer 7 (homer-app oauth2 block). Inert until __HOMER_OIDC_ENABLE__ renders true. Split-horizon mirrors the dashboard: auth_uri is browser-facing (__HOMER_OIDC_BROWSER_BASE_URL__, default http://localhost:8080) while token/userinfo/certs use the in-cluster backchannel (__HOMER_OIDC_BACKEND_BASE_URL__, default http://keycloak:8080). All values are sed-substituted from HOMER_OIDC_* env in docker-compose.homer.yml.",
    "enable": __HOMER_OIDC_ENABLE__,
    "client_id": "__HOMER_OIDC_CLIENT_ID__",
    "client_secret": "__HOMER_OIDC_CLIENT_SECRET__",
    "project_id": "Homer NGN-SIP",
    "auth_uri": "__HOMER_OIDC_BROWSER_BASE_URL__/realms/__HOMER_OIDC_REALM__/protocol/openid-connect/auth",
    "token_uri": "__HOMER_OIDC_BACKEND_BASE_URL__/realms/__HOMER_OIDC_REALM__/protocol/openid-connect/token",
    "auth_provider_x509_cert_url": "__HOMER_OIDC_BACKEND_BASE_URL__/realms/__HOMER_OIDC_REALM__/protocol/openid-connect/certs",
    "redirect_uri": "__HOMER_OIDC_REDIRECT_URI__",
    "service_redirect": "/api/v3/oauth2/redirect",
    "profile_url": "__HOMER_OIDC_BACKEND_BASE_URL__/realms/__HOMER_OIDC_REALM__/protocol/openid-connect/userinfo",
    "provider_name": "oidc",
    "grant_type": "authorization_code",
    "response_type": "code",
    "auth_style": 1,
    "use_pkce": true,
    "user_token": "__HOMER_OIDC_USER_TOKEN__",
    "scope": ["openid", "email", "profile"],
    "provider_image": ""
  },
  "decoder_shark": {
    "_comment": "Disabled in local Docker Desktop profile; packet drill-down can be enabled on the campus VM if tshark is present.",
    "active": false,
    "bin": "/usr/bin/tshark",
    "protocols": [
      "1_call",
      "1_registration",
      "1_default"
    ]
  }
}
