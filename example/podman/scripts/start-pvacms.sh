#!/bin/bash
# Start one department's certificate manager.
#
# Takes the department (lab|ml). The intermediate certificate authority for that
# department, and the facility root, were minted by bootstrap.sh into /certs.
set -euo pipefail
dept="${1:?usage: start-pvacms <lab|ml>}"

case "$dept" in
  lab) ca=/certs/lab_intermediate.p12 ;;
  ml)  ca=/certs/ml_intermediate.p12 ;;
  *)   echo "unknown department: $dept" >&2; exit 2 ;;
esac

[ -r "$ca" ] || { echo "no intermediate certificate authority at $ca - run ./bootstrap.sh first" >&2; exit 1; }

# The certificate manager wants its authority where it expects it, and a place to
# keep the database that survives a restart.
install -D -m 600 "$ca" /etc/pvacms/cert_auth.p12
mkdir -p "$(dirname "${EPICS_PVACMS_DB}")"

exec /opt/epics/pvxs-cms/bin/"$(/opt/epics/epics-base/startup/EpicsHostArch)"/pvacms \
     --cert-auth-keychain /etc/pvacms/cert_auth.p12 \
     --acf /etc/pvacms/pvacms.acf \
     -v
