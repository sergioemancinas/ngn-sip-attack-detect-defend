FROM debian:12-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818

RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends rtpengine-daemon=10.5.3.5-1 procps \
    && rm -rf /var/lib/apt/lists/* \
    && getent passwd rtpengine >/dev/null \
    && getent group rtpengine >/dev/null

EXPOSE 2223/udp 9900/tcp 30000-30100/udp
USER rtpengine
CMD ["rtpengine", "--foreground", "--log-stderr", "--log-level=5", "--interface=0.0.0.0", "--listen-ng=0.0.0.0:2223", "--listen-http=0.0.0.0:9900", "--table=0"]
