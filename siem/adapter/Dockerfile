FROM python:3.14-slim@sha256:cea0e6040540fb2b965b6e7fb5ffa00871e632eef63719f0ea54bca189ce14a6
# Kamailio -> Wazuh NGN-SEC event adapter. No third-party deps (urllib only).
# Runs as root so it can write into the wazuh-owned manager log volume with
# DAC_OVERRIDE only (all other caps dropped in compose), matching the
# kamailio-sec-relay sidecar's security posture.
COPY kamailio_wazuh_adapter.py /app/kamailio_wazuh_adapter.py
ENTRYPOINT ["python3", "/app/kamailio_wazuh_adapter.py"]
