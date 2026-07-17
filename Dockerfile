FROM python:3.11-slim

# gosu lets the entrypoint drop from root to the non-root user after fixing the
# output-volume permissions (see docker-entrypoint.sh).
RUN apt-get update && apt-get install -y --no-install-recommends gosu \
    && rm -rf /var/lib/apt/lists/*

# Non-root runtime user (defense in depth: the app never needs root).
RUN useradd -r -u 10001 -m -d /home/appuser appuser

WORKDIR /srv
COPY requirements.txt /srv/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY . /srv
RUN chmod +x /srv/docker-entrypoint.sh

# /data is the output-folder mount point. The user maps their host folder here,
# and the UI writes ledgers, activity logs, slice cache, results, and manifests
# under it. S1IE_OUTPUT_DIR points the app at it.
RUN mkdir -p /data && chown -R appuser:appuser /srv /data

# The app binds 0.0.0.0 INSIDE the container (required for Docker port publishing
# to reach it). It is NOT authenticated by default, so publish only to the host
# loopback (see run commands below), or expose with a token.
# Build version surfaced in the UI (CI passes the git sha; defaults to the package version).
ARG S1IE_VERSION=""
ENV S1IE_PORT=8801 \
    S1IE_HOST=0.0.0.0 \
    S1IE_OUTPUT_DIR=/data \
    S1IE_VERSION=${S1IE_VERSION} \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 8801
VOLUME ["/data"]

# NOTE: we intentionally do NOT set `USER appuser` here. The container starts as
# root so the entrypoint can make a host-owned /data bind mount writable, then it
# drops privileges to appuser (uid 10001) via gosu before running the app. The
# app therefore still runs unprivileged; only the brief perms-fix step is root.

# Liveness: the index page needs no auth and is always served.
HEALTHCHECK --interval=30s --timeout=4s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request,sys; urllib.request.urlopen('http://127.0.0.1:8801/',timeout=3)" || exit 1

# Local use (recommended) - publish to the host loopback so only this machine can reach it,
# and mount your output folder:
#   docker run --rm -p 127.0.0.1:8901:8801 -v "$PWD/investigations:/data" --env-file .env s1-soc-investigation
# Network/shared use - require a token and opt in explicitly:
#   docker run --rm -p 8901:8801 -e S1IE_BIND_ALL=1 -e S1IE_AUTH_TOKEN=<secret> \
#     -v "$PWD/investigations:/data" --env-file .env <img>
#   then open  http://<host>:8901/?token=<secret>
ENTRYPOINT ["/srv/docker-entrypoint.sh"]
CMD ["python", "app/server.py"]
