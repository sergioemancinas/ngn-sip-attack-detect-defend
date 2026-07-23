FROM python:3.11-slim@sha256:db3ff2e1800a8581e2c48a27c3995339d47bdf046da21c7627accd3d51053a93

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
