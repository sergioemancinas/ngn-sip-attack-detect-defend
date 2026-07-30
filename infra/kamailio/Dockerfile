FROM --platform=linux/amd64 debian:13-slim@sha256:020c0d20b9880058cbe785a9db107156c3c75c2ac944a6aa7ab59f2add76a7bd

ARG KAMAILIO_VERSION=5.8.8+bpo12
ARG KAMAILIO_GPG_FINGERPRINT=E79ACECB87D8DCD23A20AD2FFB40D3E6508EA4C8

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates gnupg wget procps netcat-openbsd \
    && export GNUPGHOME="$(mktemp -d)" \
    && wget -qO /tmp/kamailiodebkey.gpg https://deb.kamailio.org/kamailiodebkey.gpg \
    && gpg --batch --show-keys --with-colons /tmp/kamailiodebkey.gpg \
        | awk -F: '/^fpr:/ { print $10; exit }' \
        | grep -Fx "${KAMAILIO_GPG_FINGERPRINT}" \
    && gpg --batch --dearmor -o /usr/share/keyrings/kamailio.gpg /tmp/kamailiodebkey.gpg \
    && rm -rf "${GNUPGHOME}" /tmp/kamailiodebkey.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/kamailio.gpg] https://deb.kamailio.org/kamailio58 bookworm main" > /etc/apt/sources.list.d/kamailio.list \
    && apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends \
        kamailio=${KAMAILIO_VERSION} \
        kamailio-extra-modules=${KAMAILIO_VERSION} \
        kamailio-postgres-modules=${KAMAILIO_VERSION} \
        kamailio-tls-modules=${KAMAILIO_VERSION} \
        kamailio-utils-modules=${KAMAILIO_VERSION} \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/kamailio \
    && chown -R kamailio:kamailio /run/kamailio /var/run/kamailio

EXPOSE 5060/udp 5060/tcp

USER kamailio
CMD ["kamailio", "-DD", "-E", "-f", "/etc/kamailio/kamailio.cfg"]
