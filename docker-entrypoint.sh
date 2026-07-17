#!/bin/sh
# Foolproof the Docker output-volume permissions.
#
# The app runs as the non-root user "appuser" (uid 10001) for defense in depth.
# But a host bind mount (-v "$PWD/investigations:/data") arrives owned by the
# HOST user, which usually is NOT uid 10001, so the app cannot write to it and
# crashes on startup. To make the common `docker run -v ...:/data` case just
# work, this entrypoint starts as root, makes the output dir writable by appuser,
# then drops privileges and runs the app as appuser.
#
# If the container was started already non-root (e.g. `docker run --user ...`),
# we cannot chown; we just exec the app, and its startup writability check will
# print clear remediation if the folder still is not writable.
set -e

DATA_DIR="${S1IE_OUTPUT_DIR:-/data}"
APP_USER="appuser"

if [ "$(id -u)" = "0" ]; then
    # Running as root: ensure the output dir exists and appuser can write to it.
    mkdir -p "$DATA_DIR" 2>/dev/null || true
    if ! su -s /bin/sh -c "test -w '$DATA_DIR'" "$APP_USER" 2>/dev/null; then
        echo "s1-soc-investigation: making $DATA_DIR writable by $APP_USER (uid 10001)..."
        # Non-recursive chown of the mount root is enough to let the app create
        # its subfolders, and is instant even on a huge existing volume.
        chown "$APP_USER" "$DATA_DIR" 2>/dev/null || \
            echo "s1-soc-investigation: WARNING could not chown $DATA_DIR; will rely on startup check."
    fi
    # Drop to the non-root user. Prefer gosu; fall back to su if unavailable.
    if command -v gosu >/dev/null 2>&1; then
        exec gosu "$APP_USER" "$@"
    fi
    exec su -s /bin/sh -c 'exec "$0" "$@"' "$APP_USER" -- "$@"
fi

# Already non-root (an explicit --user was passed). Just run; the app's own
# startup check will surface an actionable message if the folder is not writable.
exec "$@"
