FROM debian:13-slim@sha256:020c0d20b9880058cbe785a9db107156c3c75c2ac944a6aa7ab59f2add76a7bd AS build

ARG SIPP_VERSION=v3.7.3
ARG SIPP_COMMIT=11b51748b274d24ac156ac40216600aca0f352a7

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        cmake \
        git \
        libncurses-dev \
        libpcap-dev \
        libssl-dev \
        libsctp-dev \
        lksctp-tools \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --branch "${SIPP_VERSION}" --depth 1 https://github.com/SIPp/sipp.git /usr/src/sipp \
    && test "$(git -C /usr/src/sipp rev-parse HEAD)" = "${SIPP_COMMIT}"

WORKDIR /usr/src/sipp
RUN cmake . -DUSE_SSL=1 -DUSE_PCAP=1 -DUSE_SCTP=1 \
    && make -j"$(nproc)" \
    && install -m 0755 sipp /usr/local/bin/sipp

FROM debian:13-slim@sha256:020c0d20b9880058cbe785a9db107156c3c75c2ac944a6aa7ab59f2add76a7bd

RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends libncurses6 libpcap0.8 libssl3 libsctp1 procps iproute2 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /usr/local/bin/sipp /usr/local/bin/sipp
RUN groupadd --gid 10001 sipp \
    && useradd --uid 10001 --gid sipp --home-dir /work --create-home --shell /usr/sbin/nologin sipp
WORKDIR /work
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/sipp"]
