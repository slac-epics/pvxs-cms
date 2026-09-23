#!/bin/bash
# Start a gateway, with its own department's issuer id substituted into the process
# variable list.
#
# The pvlist names certificate process variables by issuer, so each gateway claims only
# what its own PVACMS can answer, so each name says which department it belongs to.
set -euo pipefail
var="${1:?usage: start-gateway <LAB_ISSUER|ML_ISSUER|none>}"

# 'none' is a laboratory with one PVACMS, where the certificate process variables have no
# issuer in their names and the authority is minted at that first start. Its issuer id
# therefore does not exist yet when this runs: reset.sh writes it
# into /etc/epics/issuer once PVACMS has made it, and the gateway is restarted after that,
# along with the IOCs, when the certificates are issued.
if [ "${var}" = none ]; then
    issuer=
else
    issuer="${!var:-}"
    [ -n "$issuer" ] || { echo "$var is not set - is issuer_ids.env present?" >&2; exit 1; }

    # The two forms are wanted for two different things, so both are read. The short one
    # names the department's certificate process
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

# The trust anchors, where a laboratory hands them over. A gateway needs the peer
# department's root to verify anything signed under it, so the file is placed here before
# the gateway asks for
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

# Which interfaces the gateway serves on.
#
# Left to itself it binds every interface it has, which includes its own department's segment.
# A workstation there searching by broadcast is then answered twice for the same name, once by
# the IOC and once by the gateway forwarding to that IOC, and every command it runs stops with
# 'Duplicate PV name'. Its own department reaches its services directly and has no reason to
# ask its own gateway for them.
#
# More than one subnet may be named, separated by spaces, and the gateway serves on the address
# it holds on each. A gateway standing in the peer department's segment serves there so that
# department's servers can ask it about a certificate this one's authority issued, which is the
# question only this side can answer.
#
# The subnets are named, and the addresses looked up here at start.
if [ -n "${GATEWAY_SERVE_SUBNET:-}" ]; then
    serve_addrs=
    for subnet in ${GATEWAY_SERVE_SUBNET}; do
        addr=$(ip -o -4 addr show \
            | awk -v p="${subnet}" '$4 ~ "^"p {split($4,a,"/"); print a[1]; exit}')
        [ -n "${addr}" ] || {
            echo "no interface on ${subnet} - is this container on that segment?" >&2; exit 1; }
        if [ -z "${serve_addrs}" ]; then serve_addrs="\"${addr}\""
        else serve_addrs="${serve_addrs}, \"${addr}\""; fi
        echo "serving on ${addr}, the ${subnet}0/24 segment"
    done
    echo "and on no other"
    # The placeholder stands where a quoted address goes, so the quotes come from here when
    # there is more than one of them.
    sed "s/\"__SERVE_ADDR__\"/${serve_addrs}/g" /home/gateway/gateway.conf.in > /home/gateway/gateway.conf
else
    cp /home/gateway/gateway.conf.in /home/gateway/gateway.conf
fi
echo "gateway pvlist, with the issuer substituted:"
sed 's/^/    /' /home/gateway/gateway.pvlist

exec /opt/epics/p4p/bin/"$(/opt/epics/epics-base/startup/EpicsHostArch)"/pvagw /home/gateway/gateway.conf
