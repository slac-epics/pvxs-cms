#!/bin/bash
# Start an input/output controller.
#
# Two things have to be right before supervisord starts, and both fail in ways that look
# like certificate problems when they are not:
#
#   The department's issuer id. A login shell resets the environment, so a controller
#   running authnstd under `su -` cannot see it. The image reads it back from
#   /etc/epics/issuer, so it is written here from the container's environment rather than
#   bind-mounted, because podman silently creates a directory when a bind-mount source
#   does not exist.
#
#   Ownership of the keychain directory. The volume is mounted owned by root while the
#   controller runs as its own user, so without this the certificate is issued and then
#   cannot be saved.
set -euo pipefail
user="${1:?usage: start-ioc <user>}"

if [ -n "${EPICS_PVA_AUTH_ISSUER:-}" ]; then
    mkdir -p /etc/epics
    printf '%s' "${EPICS_PVA_AUTH_ISSUER}" > /etc/epics/issuer
fi

dir="/home/${user}/.config/pva/1.5"
mkdir -p "${dir}"
chown -R "${user}" "${dir}"

exec /usr/bin/supervisord -c /etc/supervisor/supervisord.conf
