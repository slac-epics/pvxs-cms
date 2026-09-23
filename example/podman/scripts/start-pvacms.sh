#!/bin/bash
# Start one department's certificate manager.
#
# Takes the department (lab|ml). The intermediate certificate authority for that
# department, and the facility root, were minted by bootstrap.sh into /certs.
set -euo pipefail
dept="${1:?usage: start-pvacms <lab|ml|own>}"

# 'own' is a laboratory with one certificate manager and no minted authorities: pvacms finds
# no keychain where it is told to look, mints a self-signed authority there, and issues every
# certificate under it. The departmental cases are the opposite - their authority was minted
# before anything started, because two managers on one laboratory have to be told apart.
case "${dept}" in
  lab) ca=/certs/lab_intermediate.p12 ;;
  ml)  ca=/certs/ml_intermediate.p12 ;;
  own) ca= ;;
  *)   echo "unknown department: ${dept}" >&2; exit 2 ;;
esac

if [ -n "${ca}" ]; then
    [ -r "${ca}" ] || { echo "no intermediate certificate authority at ${ca} - run ./reset.sh <topology> first" >&2; exit 1; }
fi

arch="$(/opt/epics/epics-base/startup/EpicsHostArch)"
PVACMS="/opt/epics/pvxs-cms/bin/${arch}/pvacms"
ADMIN=/home/idm/.config/pva/1.5/admin.p12

# The certificate manager wants its authority where it expects it, and a place to
# keep the database that survives a restart.
if [ -n "${ca}" ]; then
    # Minted before anything started, and reinstalled on every start: the copy under /etc is
    # the container's own and may go with it, because the authority itself lives in certs/.
    CA_KEYCHAIN=/etc/pvacms/cert_auth.p12
    install -D -m 600 "${ca}" "${CA_KEYCHAIN}"
else
    # pvacms mints its own here the first time it starts, so this has to be somewhere that
    # survives a restart. Under /etc it would be minted again on every start, and every
    # certificate issued before it would be left under an authority nothing can establish.
    CA_KEYCHAIN=$(dirname "${EPICS_PVACMS_DB}")/cert_auth.p12
fi
mkdir -p "$(dirname "${EPICS_PVACMS_DB}")" "$(dirname "${ADMIN}")"

# The department's issuer id, for any login shell in this container. A login shell resets
# the environment, so the image reads it back from here.
if [ -n "${EPICS_PVA_AUTH_ISSUER:-}" ]; then
    mkdir -p /etc/epics && printf '%s' "${EPICS_PVA_AUTH_ISSUER}" > /etc/epics/issuer
fi

# An administrator identity, signed by this department's own authority, created once.
# Without it there is nobody who may approve a certificate on this certificate manager.
if [ ! -s "${ADMIN}" ]; then
    echo "==> creating the administrator keychain for the ${dept} department"
    "${PVACMS}" --cert-auth-keychain "${CA_KEYCHAIN}" \
                --admin-keychain "${ADMIN}" \
                --acf /etc/pvacms/pvacms.acf \
                --admin-keychain-new admin
fi

# Let the admin user reach it, and put the tools on every login shell's path.
chown -R admin /home/admin 2>/dev/null || true
install -D -m 600 -o admin "${ADMIN}" /home/admin/.config/pva/1.5/client.p12 2>/dev/null || true
printf 'export PATH=/opt/epics/pvxs-cms/bin/%s:/opt/epics/pvxs/bin/%s:$PATH\n' "${arch}" "${arch}" \
    > /etc/profile.d/epics-tools.sh

exec "${PVACMS}" --cert-auth-keychain "${CA_KEYCHAIN}" \
                 --acf /etc/pvacms/pvacms.acf \
                 --admin-keychain "${ADMIN}" \
                 -v
