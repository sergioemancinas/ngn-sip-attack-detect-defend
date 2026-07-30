# SIPPTS is installed from GitHub at an explicit tag because the PyPI package
# named sippts/SIPPTS is a fake single-release fork, not the upstream tool.
FROM debian:13-slim@sha256:020c0d20b9880058cbe785a9db107156c3c75c2ac944a6aa7ab59f2add76a7bd AS build

ARG SIPPTS_VERSION=v4.1.2
ARG SCAPY_VERSION=2.6.1

ENV VIRTUAL_ENV=/opt/sippts
ENV PATH="${VIRTUAL_ENV}/bin:${PATH}"

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        git \
        libpcap-dev \
        python3 \
        python3-dev \
        python3-venv \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv "${VIRTUAL_ENV}" \
    && pip install --no-cache-dir --upgrade pip setuptools wheel \
    # httpx + structlog are required by attacks/orchestrator/label_emitter.py so
    # the attack scripts can emit ground-truth attack_labels rows directly.
    && pip install --no-cache-dir "httpx==0.27.2" "structlog==24.4.0"

RUN git clone --branch "${SIPPTS_VERSION}" --depth 1 https://github.com/Pepelux/sippts.git /usr/src/sippts \
    && test "$(cat /usr/src/sippts/version)" = "${SIPPTS_VERSION#v}" \
    && printf 'scapy==%s\n' "${SCAPY_VERSION}" > /tmp/sippts-constraints.txt \
    && pip install --no-cache-dir --constraint /tmp/sippts-constraints.txt /usr/src/sippts \
    && SCAPY_VERSION="${SCAPY_VERSION}" python - <<'PY'
import os
import scapy

assert scapy.__version__ == os.environ["SCAPY_VERSION"], scapy.__version__
PY

FROM debian:13-slim@sha256:020c0d20b9880058cbe785a9db107156c3c75c2ac944a6aa7ab59f2add76a7bd

ARG SCAPY_VERSION=2.6.1

ENV VIRTUAL_ENV=/opt/sippts
ENV PATH="${VIRTUAL_ENV}/bin:/usr/local/bin:${PATH}"
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        iproute2 \
        libpcap0.8 \
        python3 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10002 attacker \
    && useradd --uid 10002 --gid attacker --home-dir /work --create-home --shell /usr/sbin/nologin attacker

COPY --from=build /opt/sippts /opt/sippts

RUN set -eux; \
    ln -s /opt/sippts/bin/sippts /usr/local/bin/sippts; \
    for spec in \
        "sipscan scan" \
        "sipexten exten" \
        "sipcrack rcrack" \
        "sipinvite invite" \
        "sipsend send"; do \
        set -- ${spec}; \
        printf '#!/bin/sh\nexec /opt/sippts/bin/sippts %s "$@"\n' "$2" > "/usr/local/bin/$1"; \
        chmod 0755 "/usr/local/bin/$1"; \
    done; \
    command -v sippts; \
    for cmd in sipscan sipexten sipcrack sipinvite sipsend; do \
        command -v "${cmd}"; \
        "${cmd}" -h >/dev/null; \
    done; \
    SCAPY_VERSION="${SCAPY_VERSION}" python3 - <<'PY'
import os
import scapy

assert scapy.__version__ == os.environ["SCAPY_VERSION"], scapy.__version__
PY

WORKDIR /work
USER 10002:10002
ENTRYPOINT ["/usr/local/bin/sippts"]
CMD ["-h"]
