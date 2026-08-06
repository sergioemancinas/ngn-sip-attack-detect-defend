FROM debian:13-slim@sha256:3a39a0592364683e6bab97937b72cad5a8fa6dcbbee90edb3bb48c7f8e94f258

RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends rtpengine-daemon=10.5.3.5-1 procps \
    && rm -rf /var/lib/apt/lists/* \
    && getent passwd rtpengine >/dev/null \
    && getent group rtpengine >/dev/null

EXPOSE 2223/udp 9900/tcp 30000-30100/udp
USER rtpengine
CMD ["rtpengine", "--foreground", "--log-stderr", "--log-level=5", "--interface=0.0.0.0", "--listen-ng=0.0.0.0:2223", "--listen-http=0.0.0.0:9900", "--table=0"]
