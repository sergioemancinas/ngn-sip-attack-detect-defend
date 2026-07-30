FROM python:3.14-slim@sha256:cea0e6040540fb2b965b6e7fb5ffa00871e632eef63719f0ea54bca189ce14a6

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN groupadd --system scorer \
    && useradd --system --gid scorer --home-dir /app --shell /usr/sbin/nologin scorer \
    && mkdir -p /models /var/ossec/logs/ml \
    && chown -R scorer:scorer /app /models /var/ossec/logs/ml

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY scorer.py .
RUN chown scorer:scorer scorer.py

USER scorer
ENTRYPOINT ["python","-u","scorer.py"]
