#!/bin/bash
# Open the certificate administration display against one department.
#
# The display names exactly one certificate manager per session, by building every channel name
# from the issuer id. That id is not baked into the image: the pod carries both departments' ids
# and the shell profile of the user running the session picks one, so which department this
# opens against is decided by who is running it.
set -e

: "${CERT_PREFIX:=CERT}"

# Which department. EPICS_PVA_AUTH_ISSUER is what the user's profile set, so the display and the
# certificate tools in the same shell always address the same certificate manager.
ISSUER="${1:-${EPICS_PVA_AUTH_ISSUER}}"

if [ -z "${ISSUER}" ]; then
    echo "No issuer id, so there is no way to tell which department to open." >&2
    echo >&2
    echo "Pass one as the first argument, or run as a user whose profile sets" >&2
    echo "EPICS_PVA_AUTH_ISSUER (certadmin for the laboratory, mlcertadmin for" >&2
    echo "machine learning). The ids of both departments are in this pod as" >&2
    echo "\$LAB_ISSUER and \$ML_ISSUER." >&2
    exit 2
fi
shift 2>/dev/null || true

# Whether this session carries decisions. The internet zone reaches a certificate manager only
# through a gateway, which makes its upstream connection as itself, so the certificate manager
# would see the gateway rather than the administrator: the view of certificates awaiting a
# decision is refused there and so is a decision write. Such a session opens with decisions off
# and the display leaves those controls out rather than showing ones that come back refused.
: "${DECISIONS:=yes}"

export DISPLAY=${DISPLAY:-:99}

exec java \
    --enable-native-access=ALL-UNNAMED \
    -Dprism.order=sw \
    -Dprism.forceGPU=false \
    -Dfile.encoding=UTF-8 \
    -jar /opt/phoebus/product-*.jar \
    -settings /opt/phoebus/phoebus-settings.ini \
    -resource "/opt/phoebus/displays/pvxs-lab-certificate-administration.bob?ISSUER=${ISSUER}&CERT_PREFIX=${CERT_PREFIX}&DECISIONS=${DECISIONS}" \
    "$@"
