#!/bin/bash
# Start a gateway, with its own department's issuer id substituted into the process
# variable list.
#
# The list names certificate process variables by issuer, so each gateway claims only
# what its own certificate manager can answer. With two certificate managers on one
# network an unqualified name would be claimed by both, and neither gateway could tell
# which department a request meant.
set -euo pipefail
var="${1:?usage: start-gateway <LAB_ISSUER|ML_ISSUER>}"
issuer="${!var:-}"
[ -n "$issuer" ] || { echo "$var is not set - is issuer_ids.env present?" >&2; exit 1; }

# The two forms are wanted for two different things, so both are read rather than one
# derived from the other. The short one names the department's certificate process
# variables, below. The whole one is what the gateway has to be given to establish trust in
# the authority the first time it asks for its own certificate; the short form is refused
# for that, being too little to decide which authority is meant.
skid_var="${var}_SKID"
skid="${!skid_var:-}"
[ -n "$skid" ] || { echo "$skid_var is not set - is issuer_ids.env up to date?" >&2; exit 1; }

# For any login shell in this container. A login shell resets the environment, so the image
# reads it back from here; without it the gateway cannot request its own certificate.
mkdir -p /etc/epics && printf '%s' "${skid}" > /etc/epics/issuer

# The gateway writes its keychain into its home when it asks for a certificate, and the
# volume is mounted owned by root.
mkdir -p /home/gateway/.config/pva/1.5 && chown -R gateway /home/gateway/.config

sed "s/__${var}__/${issuer}/g" /home/gateway/gateway.pvlist.in > /home/gateway/gateway.pvlist
cp /home/gateway/gateway.conf.in /home/gateway/gateway.conf
echo "gateway process variable list, with the issuer substituted:"
sed 's/^/    /' /home/gateway/gateway.pvlist

exec /opt/epics/p4p/bin/"$(/opt/epics/epics-base/startup/EpicsHostArch)"/pvagw /home/gateway/gateway.conf
