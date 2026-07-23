FROM debian:13-slim@sha256:020c0d20b9880058cbe785a9db107156c3c75c2ac944a6aa7ab59f2add76a7bd

RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends rtpengine-daemon=10.5.3.5-1 procps \
    && rm -rf /var/lib/apt/lists/* \
    && getent passwd rtpengine >/dev/null \
    && getent group rtpengine >/dev/null

EXPOSE 2223/udp 9900/tcp 30000-30100/udp
USER rtpengine
CMD ["rtpengine", "--foreground", "--log-stderr", "--log-level=5", "--interface=0.0.0.0", "--listen-ng=0.0.0.0:2223", "--listen-http=0.0.0.0:9900", "--table=0"]
