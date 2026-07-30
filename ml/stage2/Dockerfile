FROM python:3.14-slim@sha256:cea0e6040540fb2b965b6e7fb5ffa00871e632eef63719f0ea54bca189ce14a6

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# /state holds the alerts.json read offset; owning it here means the named
# volume mounted at /state inherits stage2 ownership on first use, so the
# worker can persist its offset without running as root.
RUN groupadd --system stage2 \
    && useradd --system --gid stage2 --home-dir /app --shell /usr/sbin/nologin stage2 \
    && mkdir -p /state \
    && chown -R stage2:stage2 /app /state

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY worker.py .
COPY prompts/ prompts/
RUN chown -R stage2:stage2 /app

USER stage2
ENTRYPOINT ["python", "-u", "worker.py"]
CMD ["poll", "--interval-seconds", "5"]
