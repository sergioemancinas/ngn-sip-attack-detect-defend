ARG POSTGRES_IMAGE=postgres:16-alpine@sha256:4e6e670bb069649261c9c18031f0aded7bb249a5b6664ddec29c013a89310d50
ARG ALPINE_IMAGE=alpine:3.23@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11
FROM ${POSTGRES_IMAGE} AS pgvector-build

ARG PGVECTOR_VERSION=v0.8.0
ARG PGVECTOR_COMMIT=2627c5ff775ae6d7aef0c430121ccf857842d2f2

RUN set -eux; \
    apk update; \
    apk upgrade --no-cache; \
    apk add --no-cache su-exec; \
    apk add --no-cache --virtual .build-deps \
        build-base \
        ca-certificates \
        clang19 \
        git \
        llvm19-dev; \
    git clone --branch "${PGVECTOR_VERSION}" --depth 1 https://github.com/pgvector/pgvector.git /usr/src/pgvector; \
    test "$(git -C /usr/src/pgvector rev-parse HEAD)" = "${PGVECTOR_COMMIT}"; \
    cd /usr/src/pgvector; \
    make clean; \
    make OPTFLAGS=""; \
    make install; \
    mkdir -p /usr/share/doc/pgvector; \
    cp LICENSE README.md /usr/share/doc/pgvector; \
    cd /; \
    rm -rf /usr/src/pgvector; \
    sed -i 's/exec gosu postgres/exec su-exec postgres/' /usr/local/bin/docker-entrypoint.sh; \
    rm -f /usr/local/bin/gosu /usr/local/bin/su-exec; \
    apk del .build-deps; \
    rm -rf /var/cache/apk/*

FROM ${ALPINE_IMAGE}

COPY --from=pgvector-build / /

ENV LANG=en_US.utf8 \
    PG_MAJOR=16 \
    PG_VERSION=16.13 \
    PG_SHA256=dc2ddbbd245c0265a689408e3d2f2f3f9ba2da96bd19318214b313cdd9797287 \
    PGDATA=/var/lib/postgresql/data

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["postgres"]
EXPOSE 5432
VOLUME ["/var/lib/postgresql/data"]
