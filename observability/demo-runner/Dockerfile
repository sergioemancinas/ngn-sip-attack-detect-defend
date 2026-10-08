# Demo runner: docker CLI + python3, talks to the mounted Docker socket to launch
# ONE fixed bounded SIP demo burst. Internal (sip_lab) only; never host-published.
FROM docker:28-cli@sha256:625d9431a9f54c5a2bc90f24f0e1c3d55b1349fd857dd85035f98c2c9acbdd4d

RUN apk add --no-cache python3

WORKDIR /app
COPY app.py .

EXPOSE 8088
ENTRYPOINT ["python3", "/app/app.py"]
