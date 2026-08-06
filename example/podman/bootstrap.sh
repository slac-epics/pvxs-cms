#!/bin/bash
# Build the images and mint the certificate authorities for the demonstration laboratory.
#
# Run once, before the first `podman-compose up`. Running it again mints fresh
# authorities, which invalidates every certificate already issued: use --keep-certs to
# rebuild images without touching them.
set -euo pipefail
cd "$(dirname "$0")"

ROOT_CN="${ROOT_CN:-EPICS Root Certificate Authority}"
LAB_CN="${LAB_CN:-EPICS Controls Intermediate CA}"
ML_CN="${ML_CN:-EPICS ML Intermediate CA}"
SRC="$(cd ../../.. && pwd)"          # the workspace holding pvxs-cms, pvxs, epics-base, p4p

keep_certs=no
[ "${1:-}" = "--keep-certs" ] && keep_certs=yes

echo "==> building images (podman)"
# lab_tools carries the packages, lab_base the built EPICS tree; everything else derives
# from lab_base, so this order matters.
( cd ../kubernetes/docker
  for target in lab_tools lab_base idm ml testioc tstioc ml-ioc gateway lab internet; do
      echo "    $target"
      ( cd "$target" && ./build_docker.sh >/dev/null )
  done )

if [ "$keep_certs" = yes ] && [ -s issuer_ids.env ] && [ -d certs ]; then
    echo "==> keeping the existing certificate authorities"
else
    echo "==> minting the facility root and both departmental intermediates"
    rm -rf certs && mkdir -p certs
    podman run --rm -v "$(pwd)/certs:/certs:Z" localhost/idm:latest bash -c "
        set -e
        arch=\$(/opt/epics/epics-base/startup/EpicsHostArch)
        /opt/epics/pvxs-cms/test/O.\$arch/gen_lab_certs \
            -O /certs \
            -R '${ROOT_CN}' \
            -L '${LAB_CN}' \
            -M '${ML_CN}'
        ls -la /certs"
    cp certs/issuer_ids.env issuer_ids.env
fi

echo
echo "==> issuer ids"
sed 's/^/    /' issuer_ids.env
echo
echo "Now:  podman-compose up -d"
