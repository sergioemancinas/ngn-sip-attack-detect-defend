FROM debian:13-slim@sha256:020c0d20b9880058cbe785a9db107156c3c75c2ac944a6aa7ab59f2add76a7bd AS build

ARG ASTERISK_VERSION=20.19.0
ARG ASTERISK_COMMIT=f66917fe6da487155f80ab50403bf3d7bdc86183

RUN apt-get update \
    && apt-get dist-upgrade -y \
    && apt-get install -y --no-install-recommends \
        autoconf \
        automake \
        build-essential \
        ca-certificates \
        file \
        git \
        libedit-dev \
        libjansson-dev \
        libsqlite3-dev \
        libssl-dev \
        libtool \
        libuuid1 \
        libxml2-dev \
        pkg-config \
        procps \
        python3 \
        uuid-dev \
        wget \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --branch "${ASTERISK_VERSION}" --depth 1 https://github.com/asterisk/asterisk.git /usr/src/asterisk \
    && test "$(git -C /usr/src/asterisk rev-parse HEAD)" = "${ASTERISK_COMMIT}"

WORKDIR /usr/src/asterisk
RUN ./configure --with-jansson-bundled --with-pjproject-bundled \
    && make menuselect.makeopts \
    && menuselect/menuselect --disable BUILD_NATIVE menuselect.makeopts \
    && make -j"$(nproc)" \
    && make install

RUN groupadd --system asterisk \
    && useradd --system --gid asterisk --home-dir /var/lib/asterisk asterisk \
    && mkdir -p /etc/asterisk /var/log/asterisk /var/run/asterisk /var/spool/asterisk \
    && chown -R asterisk:asterisk /etc/asterisk /var/lib/asterisk /var/log/asterisk /var/run/asterisk /var/spool/asterisk

RUN apt-mark manual \
        ca-certificates \
        libbsd0 \
        libedit2 \
        libjansson4 \
        libmd0 \
        libsqlite3-0 \
        libssl3 \
        libstdc++6 \
        libtinfo6 \
        libuuid1 \
        libxml2 \
        procps \
        zlib1g \
    && apt-get purge -y --auto-remove \
        autoconf \
        automake \
        build-essential \
        file \
        git \
        libedit-dev \
        libjansson-dev \
        libsqlite3-dev \
        libssl-dev \
        libtool \
        libxml2-dev \
        pkg-config \
        python3 \
        uuid-dev \
        wget \
    && rm -rf /usr/src/asterisk /var/lib/apt/lists/*

FROM debian:13-slim@sha256:020c0d20b9880058cbe785a9db107156c3c75c2ac944a6aa7ab59f2add76a7bd

COPY --from=build / /

ENV PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
EXPOSE 5060/udp 5060/tcp 8088/tcp 10000-10100/udp
USER asterisk
CMD ["/usr/sbin/asterisk", "-f", "-U", "asterisk", "-G", "asterisk", "-vvv"]
