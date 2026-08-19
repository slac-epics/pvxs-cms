#!/bin/bash
# Mint this topology's certificate authorities: two roots that share nothing.
#
# Run by reset.sh, into this topology's own certs/ directory. Each laboratory needs
# authorities of a different shape, so each mints its own rather than sharing one set.
#
# Nothing stands above these two roots, and neither signs the other, so the two departments
# are free to differ in how deep they go - and here they do, because that is the clearest way
# to show that neither root constrains the other:
#
#   the lab department    a root that signs an intermediate, and the certificate manager
#                         signs with the intermediate
#   the machine learning  a root held by the certificate manager itself, which signs every
#   department            certificate directly
#
# The lab root is written without its key, as the record of the authority: it is a trust
# anchor, and the key that would let anything be signed with it is not wanted on a running
# service. The machine learning root is written with its key, because that department's
# certificate manager is what signs with it.
#
# There is no responder here. A responder answers for a root's own standing, and revoking a
# root is the shared-root laboratory's demonstration, shown once where it has the most to
# stop. Withdrawing a department here is rotating its root away, on that department's own
# schedule.
set -euo pipefail
cd "$(dirname "$0")"

: "${DOCKER_REGISTRY:=localhost}"
: "${DOCKER_USERNAME:=spva}"

LAB_ROOT_CN='EPICS Lab Root Certificate Authority'
LAB_CN='EPICS Controls Intermediate CA'
ML_ROOT_CN='EPICS ML Root Certificate Authority'

echo "==> minting the lab root and the intermediate beneath it"
rm -rf certs && mkdir -p certs
podman run --rm -v "$(pwd)/certs:/certs:Z" \
    "${DOCKER_REGISTRY}/${DOCKER_USERNAME}/idm:latest" bash -c "
        set -e
        arch=\$(/opt/epics/epics-base/startup/EpicsHostArch)
        /opt/epics/pvxs-cms/test/O.\$arch/gen_lab_certs \
            -O /certs -R '${LAB_ROOT_CN}' -L '${LAB_CN}'
        mv /certs/cert_auth.p12 /certs/lab_root.p12
        # The tool mints a root with two intermediates beneath it, which is the shape the
        # shared-root laboratory wants. Here the second department has a root of its own, so
        # the second intermediate is removed rather than left in certs/ to be taken for
        # something in use.
        rm -f /certs/ml_intermediate.p12" >/dev/null

LAB_ISSUER=$(sed -n 's/^LAB_ISSUER=//p' certs/issuer_ids.env)
LAB_ISSUER_SKID=$(sed -n 's/^LAB_ISSUER_SKID=//p' certs/issuer_ids.env)

# The machine learning root is minted by pvacms itself, which is the same code that would
# mint one on a first start, run once here so that the identifier exists before anything is
# started. Everything that has to be told which authority to trust is told before it runs,
# and a certificate manager that made its own would not be able to say so until afterwards.
echo "==> minting the machine learning root, which that department's manager signs with"
podman run --rm \
    -v "$(pwd)/certs:/certs:Z" \
    -v "$(pwd)/config/pvacms-ml.acf:/tmp/pvacms.acf:ro,z" \
    -e EPICS_PVACMS_DB=/tmp/certs.db \
    -e "EPICS_CERT_AUTH_NAME=${ML_ROOT_CN}" \
    -e EPICS_CERT_AUTH_ORGANIZATION=certs.epics.org \
    -e "EPICS_CERT_AUTH_ORGANIZATIONAL_UNIT=epics.org Certificate Authority" \
    "${DOCKER_REGISTRY}/${DOCKER_USERNAME}/ml:latest" bash -c '
        set -e
        arch=$(/opt/epics/epics-base/startup/EpicsHostArch)
        /opt/epics/pvxs-cms/bin/${arch}/pvacms \
            --cert-auth-keychain /certs/ml_root.p12 \
            --admin-keychain /tmp/admin.p12 \
            --acf /tmp/pvacms.acf \
            --admin-keychain-new admin' >/dev/null 2>&1

# An authority is named by its subject key identifier, and this root is its own authority, so
# its identifier is what every machine learning certificate will carry.
ML_ISSUER_SKID=$(podman run --rm -v "$(pwd)/certs:/certs:ro,Z" \
    "${DOCKER_REGISTRY}/${DOCKER_USERNAME}/ml:latest" bash -c '
        openssl pkcs12 -in /certs/ml_root.p12 -passin pass: -nokeys 2>/dev/null \
        | openssl x509 -noout -ext subjectKeyIdentifier \
        | tail -1 | tr -d " :" | tr "A-F" "a-f"')
ML_ISSUER=${ML_ISSUER_SKID:0:8}

# The trust anchors, as a keychain holding the two roots and no identity.
#
# This is the file a site hands to a machine out of band, and it is what makes the laboratory
# work at all: a controller stands on its own department's segment and can reach nothing
# beyond it, so it can never ask the department next door for its root. It is given both roots
# here instead, before it asks for an identity, and what it is issued is added to the anchors
# the file already holds rather than replacing them.
#
# A workstation is left out on purpose. A person establishing trust by hand is the
# demonstration this laboratory exists for, and a workstation that already held both anchors
# would have nothing left to show.
echo "==> writing the trust anchors both departments have to hold"
podman run --rm -v "$(pwd)/certs:/certs:Z" \
    "${DOCKER_REGISTRY}/${DOCKER_USERNAME}/idm:latest" bash -c '
        set -e
        openssl pkcs12 -in /certs/lab_root.p12 -passin pass: -nokeys >  /tmp/roots.pem
        openssl pkcs12 -in /certs/ml_root.p12  -passin pass: -nokeys >> /tmp/roots.pem
        openssl pkcs12 -export -nokeys -in /tmp/roots.pem \
            -out /certs/trust_anchors.p12 -passout pass:' >/dev/null

[ -n "${LAB_ISSUER_SKID}" ] && [ -n "${ML_ISSUER_SKID}" ] || {
    echo "one of the two authorities has no subject key identifier - nothing can be issued" >&2
    exit 1; }

# Both forms of both identifiers. The short one names an authority in a process variable
# name; the whole one is what establishes trust in it, and they are wanted in different
# places, so neither is derived from the other by whoever reads this.
{ printf 'LAB_ISSUER=%s\n' "${LAB_ISSUER}"
  printf 'ML_ISSUER=%s\n' "${ML_ISSUER}"
  printf 'LAB_ISSUER_SKID=%s\n' "${LAB_ISSUER_SKID}"
  printf 'ML_ISSUER_SKID=%s\n' "${ML_ISSUER_SKID}"; } > certs/issuer_ids.env
cp certs/issuer_ids.env issuer_ids.env
