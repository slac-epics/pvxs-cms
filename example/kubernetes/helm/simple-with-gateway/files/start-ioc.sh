#!/bin/bash
# Start an IOC.
#
# Two things have to be right before supervisord starts, and both fail in ways that look
# like certificate problems when they are not:
#
#   The department's issuer id. A login shell resets the environment, so an IOC running
#   authnstd under `su -` cannot see it. The image reads it back from
#   /etc/epics/issuer, so it is written here from the container's environment rather than
#   bind-mounted, because podman silently creates a directory when a bind-mount source
#   does not exist.
#
#   Ownership of the keychain directory. The volume is mounted owned by root while the IOC
#   runs as its own user, so without this the certificate is issued and then cannot be
#   saved.
set -euo pipefail
user="${1:?usage: start-ioc <user>}"

if [ -n "${EPICS_PVA_AUTH_ISSUER:-}" ]; then
    mkdir -p /etc/epics
    printf '%s' "${EPICS_PVA_AUTH_ISSUER}" > /etc/epics/issuer
fi

dir="/home/${user}/.config/pva/1.5"
mkdir -p "${dir}"
chown -R "${user}" "${dir}"

# The trust anchors, where a laboratory hands them over rather than leaving them to be
# fetched. An IOC stands on its own department's segment and can reach nothing beyond it, so
# it cannot ask the peer department for its root; in a laboratory whose departments share no
# root it has to hold that root to verify a certificate signed under it. So the file is placed
# here before the IOC asks for an identity: what it then receives is added to a keychain that
# already holds both anchors, and asking for an identity never removes one.
if [ -r /certs/trust_anchors.p12 ] && [ ! -s "${dir}/server.p12" ]; then
    install -m 600 -o "${user}" /certs/trust_anchors.p12 "${dir}/server.p12"
fi

exec /usr/bin/supervisord -c /etc/supervisor/supervisord.conf
