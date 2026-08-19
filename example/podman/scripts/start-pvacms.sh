#!/bin/bash
# Start one department's certificate manager.
#
# Takes the department (lab|ml). The intermediate certificate authority for that
# department, and the facility root, were minted by bootstrap.sh into /certs.
set -euo pipefail
dept="${1:?usage: start-pvacms <lab|ml>}"

case "${dept}" in
  lab) ca=/certs/lab_intermediate.p12 ;;
  ml)  ca=/certs/ml_intermediate.p12 ;;
  *)   echo "unknown department: ${dept}" >&2; exit 2 ;;
esac

[ -r "${ca}" ] || { echo "no intermediate certificate authority at ${ca} - run ./bootstrap.sh first" >&2; exit 1; }

arch="$(/opt/epics/epics-base/startup/EpicsHostArch)"
PVACMS="/opt/epics/pvxs-cms/bin/${arch}/pvacms"
ADMIN=/home/idm/.config/pva/1.5/admin.p12

# The certificate manager wants its authority where it expects it, and a place to
# keep the database that survives a restart.
install -D -m 600 "${ca}" /etc/pvacms/cert_auth.p12
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
    "${PVACMS}" --cert-auth-keychain /etc/pvacms/cert_auth.p12 \
                --admin-keychain "${ADMIN}" \
                --acf /etc/pvacms/pvacms.acf \
                --admin-keychain-new admin
fi

# Let the admin user reach it, and put the tools on every login shell's path.
chown -R admin /home/admin 2>/dev/null || true
install -D -m 600 -o admin "${ADMIN}" /home/admin/.config/pva/1.5/client.p12 2>/dev/null || true
printf 'export PATH=/opt/epics/pvxs-cms/bin/%s:/opt/epics/pvxs/bin/%s:$PATH\n' "${arch}" "${arch}" \
    > /etc/profile.d/epics-tools.sh

exec "${PVACMS}" --cert-auth-keychain /etc/pvacms/cert_auth.p12 \
                 --acf /etc/pvacms/pvacms.acf \
                 --admin-keychain "${ADMIN}" \
                 -v
