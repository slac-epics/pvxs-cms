#!/bin/bash
# Keep a shell container alive, with the department's issuer available to logins.
#
# Written here rather than bind-mounted because podman creates a directory when a
# bind-mount source does not exist, which then cannot be read as a file.
set -euo pipefail
# These images run as an ordinary user, not root, so neither of these is possible there
# and neither is required: a container that is already running as the user keeps its
# environment, and its home is already writable.
if [ -n "${EPICS_PVA_AUTH_ISSUER:-}" ] && [ -w /etc ]; then
    mkdir -p /etc/epics
    printf '%s' "${EPICS_PVA_AUTH_ISSUER}" > /etc/epics/issuer
fi
for u in "$@"; do
    dir="/home/${u}/.config/pva/1.5"
    mkdir -p "${dir}" 2>/dev/null && chown -R "${u}" "${dir}" 2>/dev/null || true
done
exec sleep infinity
