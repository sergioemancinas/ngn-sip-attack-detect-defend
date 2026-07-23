# Demo runner: docker CLI + python3, talks to the mounted Docker socket to launch
# ONE fixed bounded SIP demo burst. Internal (sip_lab) only; never host-published.
FROM docker:27-cli@sha256:851f91d241214e7c6db86513b270d58776379aacc5eb9c4a87e5b47115e3065c

RUN apk add --no-cache python3

WORKDIR /app
COPY app.py .

EXPOSE 8088
ENTRYPOINT ["python3", "/app/app.py"]
