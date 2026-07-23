# kamcmd-relay: HTTP ban enforcement endpoint for the Shuffle SOAR workflow.
# Pure Python stdlib (no pip installs at build time); talks to the Docker
# Engine API over the read-only docker.sock mount and to ClickHouse over HTTP.
# Runs as root INSIDE the container only because /var/run/docker.sock is
# root-owned on the Colima VM; the compose service compensates with
# cap_drop: [ALL], no-new-privileges, read_only rootfs, pids/mem limits.
FROM python:3.11-slim@sha256:db3ff2e1800a8581e2c48a27c3995339d47bdf046da21c7627accd3d51053a93

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app
COPY requirements.txt relay.py ./

EXPOSE 8099

ENTRYPOINT ["python3", "/app/relay.py"]
