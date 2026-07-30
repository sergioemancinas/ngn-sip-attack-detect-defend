# kamcmd-relay: HTTP ban enforcement endpoint for the Shuffle SOAR workflow.
# Pure Python stdlib (no pip installs at build time); talks to the Docker
# Engine API over the read-only docker.sock mount and to ClickHouse over HTTP.
# Runs as root INSIDE the container only because /var/run/docker.sock is
# root-owned on the Colima VM; the compose service compensates with
# cap_drop: [ALL], no-new-privileges, read_only rootfs, pids/mem limits.
FROM python:3.14-slim@sha256:cea0e6040540fb2b965b6e7fb5ffa00871e632eef63719f0ea54bca189ce14a6

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app
COPY requirements.txt relay.py ./

EXPOSE 8099

ENTRYPOINT ["python3", "/app/relay.py"]
