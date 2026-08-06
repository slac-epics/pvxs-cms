#!/bin/bash
# Start an input/output controller, after making its keychain directory writable.
#
# The configuration volume is mounted owned by root, but the controller runs as its own
# user and writes its keychain there when it asks for a certificate. Without this the
# request succeeds at the certificate manager and then fails to save, which looks like a
# certificate problem and is not one.
set -euo pipefail
user="${1:?usage: start-ioc <user>}"
dir="/home/${user}/.config/pva/1.5"
mkdir -p "${dir}"
chown -R "${user}" "${dir}"
exec /usr/bin/supervisord -c /etc/supervisor/supervisord.conf
