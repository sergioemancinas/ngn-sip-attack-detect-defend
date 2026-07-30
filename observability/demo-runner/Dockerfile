# Demo runner: docker CLI + python3, talks to the mounted Docker socket to launch
# ONE fixed bounded SIP demo burst. Internal (sip_lab) only; never host-published.
FROM docker:29-cli@sha256:be132a9f282288de4afaf63379dff75711fda0147c6b72a9df44e51841402144

RUN apk add --no-cache python3

WORKDIR /app
COPY app.py .

EXPOSE 8088
ENTRYPOINT ["python3", "/app/app.py"]
