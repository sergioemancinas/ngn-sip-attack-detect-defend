FROM debian:12-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818 AS build

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

FROM debian:12-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818

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
