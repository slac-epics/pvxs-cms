#!/bin/bash
# Start a gateway, with its own department's issuer id substituted into the process
# variable list.
#
# The pvlist names certificate process variables by issuer, so each gateway claims only
# what its own PVACMS can answer. With two of them on one network an unqualified name
# would be claimed by both, and neither gateway could tell which department a request
# meant.
set -euo pipefail
var="${1:?usage: start-gateway <LAB_ISSUER|ML_ISSUER|none>}"

# 'none' is a laboratory with one PVACMS, where the certificate process variables have no
# issuer in their names and the authority is minted at that first start rather than
# beforehand. Its issuer id therefore does not exist yet when this runs: reset.sh writes it
# into /etc/epics/issuer once PVACMS has made it, and the gateway is restarted after that,
# along with the IOCs, when the certificates are issued.
if [ "${var}" = none ]; then
    issuer=
else
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
fi

# The gateway writes its keychain into its home when it asks for a certificate, and the
# volume is mounted owned by root.
mkdir -p /home/gateway/.config/pva/1.5 && chown -R gateway /home/gateway/.config

# The trust anchors, where a laboratory hands them over rather than leaving them to be
# fetched. A gateway with no path to the peer department's PVACMS cannot ask it for its root,
# and in a laboratory whose departments share no root it has to hold that root to verify
# anything signed under it. So the file is placed here before the gateway asks for
# an identity: what it then receives is added to a keychain that already holds both anchors,
# and asking for an identity never removes one.
keychain=/home/gateway/.config/pva/1.5/gateway.p12
if [ -r /certs/trust_anchors.p12 ] && [ ! -s "${keychain}" ]; then
    install -m 600 -o gateway /certs/trust_anchors.p12 "${keychain}"
fi

if [ -n "${issuer}" ]; then
    sed "s/__${var}__/${issuer}/g" /home/gateway/gateway.pvlist.in > /home/gateway/gateway.pvlist
else
    cp /home/gateway/gateway.pvlist.in /home/gateway/gateway.pvlist
fi

# Which interface the gateway serves on.
#
# Left to itself it binds every interface it has, which includes the department's own
# segment. A workstation there searching by broadcast is then answered twice for the same
# name, once by the IOC and once by the gateway forwarding to that IOC, and
# every command it runs stops with 'Duplicate PV name'.
#
# The address cannot be written into the configuration because podman assigns it at start, so
# the subnet is named instead and the address is looked up here.
if [ -n "${GATEWAY_SERVE_SUBNET:-}" ]; then
    serve_addr=$(ip -o -4 addr show \
        | awk -v p="${GATEWAY_SERVE_SUBNET}" '$4 ~ "^"p {split($4,a,"/"); print a[1]; exit}')
    [ -n "${serve_addr}" ] || {
        echo "no interface on ${GATEWAY_SERVE_SUBNET} - is this container on that segment?" >&2; exit 1; }
    echo "serving on ${serve_addr}, the ${GATEWAY_SERVE_SUBNET}0/24 segment, and on no other"
    sed "s/__SERVE_ADDR__/${serve_addr}/g" /home/gateway/gateway.conf.in > /home/gateway/gateway.conf
else
    cp /home/gateway/gateway.conf.in /home/gateway/gateway.conf
fi
echo "gateway pvlist, with the issuer substituted:"
sed 's/^/    /' /home/gateway/gateway.pvlist

exec /opt/epics/p4p/bin/"$(/opt/epics/epics-base/startup/EpicsHostArch)"/pvagw /home/gateway/gateway.conf
