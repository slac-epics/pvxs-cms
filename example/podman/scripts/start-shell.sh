#!/bin/bash
# Keep a shell container alive, with the department's issuer available to logins.
#
# Written here rather than bind-mounted because podman creates a directory when a
# bind-mount source does not exist, which then cannot be read as a file.
set -euo pipefail
if [ -n "${EPICS_PVA_AUTH_ISSUER:-}" ]; then
    mkdir -p /etc/epics
    printf '%s' "${EPICS_PVA_AUTH_ISSUER}" > /etc/epics/issuer
fi
for u in "$@"; do
    dir="/home/${u}/.config/pva/1.5"
    mkdir -p "${dir}" && chown -R "${u}" "${dir}"
done
exec sleep infinity
