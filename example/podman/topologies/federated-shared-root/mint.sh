#!/bin/bash
# Mint this topology's certificate authorities: one facility root, and one intermediate per
# department beneath it.
#
# Run by reset.sh, into this topology's own certs/ directory. Each laboratory needs
# authorities of a different shape, so each mints its own rather than sharing one set.
#
# The root is written without its key: it is a trust anchor for every host, and the key that
# would let anything be signed with it is not wanted on a running service. What each PVACMS
# gets is its own department's intermediate, key and all.
set -euo pipefail
cd "$(dirname "$0")"

: "${DOCKER_REGISTRY:=localhost}"
: "${DOCKER_USERNAME:=spva}"

ROOT_CN='EPICS Root Certificate Authority'
LAB_CN='EPICS Controls Intermediate CA'
ML_CN='EPICS ML Intermediate CA'

echo "==> minting the facility root and both departmental intermediates"
rm -rf certs && mkdir -p certs
podman run --rm -v "$(pwd)/certs:/certs:Z" \
    "${DOCKER_REGISTRY}/${DOCKER_USERNAME}/idm:latest" bash -c "
        set -e
        arch=\$(/opt/epics/epics-base/startup/EpicsHostArch)
        /opt/epics/pvxs-cms/test/O.\$arch/gen_lab_certs \
            -O /certs -R '${ROOT_CN}' -L '${LAB_CN}' -M '${ML_CN}' \
            -S 'http://pvxs-lab-ocsp-responder:8888'" >/dev/null

cp certs/issuer_ids.env issuer_ids.env

# What the responder needs, under the names it is started with. Kept apart from certs/
# because certs/ holds authorities and this holds one service's configuration, and because
# the file saying whether the root still stands is rewritten during a demonstration while
# nothing in certs/ is.
rm -rf ocsp && mkdir -p ocsp
cp certs/ocsp_ca.pem     ocsp/ca.pem
cp certs/ocsp_signer.pem ocsp/signer.pem
cp certs/ocsp_signer.key ocsp/signer.key
cp certs/ocsp_index.txt  ocsp/index.txt
