FROM python:3.14-slim-bookworm@sha256:86f975aca15cf04a40b399eebede9aea7c82eae084d1f1a0a6ef6bcaae871a30

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY bridge.py .

# Runs as root (uid 0): the rootfs is read_only and caps are dropped in compose,
# and root can write the shared hep_bridge volumes. The bridge writes events.ndjson
# world-readable so Vector (uid 65534) can ingest it. Avoids the uid-65534/nobody
# useradd collision in the base image.
ENTRYPOINT ["python", "/app/bridge.py"]
