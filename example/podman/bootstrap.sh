#!/bin/bash
# Build the images and mint the certificate authorities for the demonstration laboratory.
#
# Run once, before the first `podman-compose up`. Running it again mints fresh
# authorities, which invalidates every certificate already issued: use --keep-certs to
# rebuild the images without touching them.
#
# JOBS controls how many compiler processes run at once. Each can take most of a
# gigabyte, so on a machine with little memory set it low:
#
#     JOBS=2 ./bootstrap.sh
#
set -euo pipefail
cd "$(dirname "$0")"

ROOT_CN="${ROOT_CN:-EPICS Root Certificate Authority}"
LAB_CN="${LAB_CN:-EPICS Controls Intermediate CA}"
ML_CN="${ML_CN:-EPICS ML Intermediate CA}"

# The build scripts shared with the Kubernetes laboratory call `docker`. On podman that
# is the podman-docker shim, so check for it early rather than failing halfway through.
command -v podman >/dev/null || { echo "podman is not installed" >&2; exit 1; }
command -v docker >/dev/null || {
    echo "no 'docker' command found. The image build scripts call it; install the shim:" >&2
    echo "    sudo apt install podman-docker        # Debian, Ubuntu" >&2
    echo "    sudo dnf install podman-docker        # Fedora, RHEL" >&2
    exit 1; }

# Built images are referenced by these names in compose.yaml.
export DOCKER_REGISTRY="${DOCKER_REGISTRY:-localhost}"
export DOCKER_USERNAME="${DOCKER_USERNAME:-spva}"

jobs_arg=()
[ -n "${JOBS:-}" ] && jobs_arg=(--build-arg "JOBS=${JOBS}")

keep_certs=no
[ "${1:-}" = "--keep-certs" ] && keep_certs=yes

# The images form a chain, each built on the one before:
#
#   ubuntu -> epics-base -> pvxs -> pvxs-cms -> lab_tools/lab_base -> the laboratory
#
# The first two live in the pvxs tree, the third in this one. Only these three are taken
# from example/docker: the Kerberos and LDAP authenticator images beside them are not used
# here, because this laboratory issues certificates with the standard authenticator, and
# the display images are left out because everything is verified from the command line.
echo "==> building epics-base and pvxs (compiles EPICS Base and pvxs)"
( cd ../../../pvxs/example/docker/epics-base && ./build_docker.sh "${jobs_arg[@]}" )
( cd ../../../pvxs/example/docker/pvxs       && ./build_docker.sh "${jobs_arg[@]}" )

echo "==> building the pvxs-cms image"
( cd ../docker/pvxs-cms && ./build_docker.sh "${jobs_arg[@]}" )

echo "==> building the laboratory images"
# lab_tools carries the operating system packages, lab_base the built EPICS tree, and
# everything else derives from lab_base. This order matters.
( cd ../kubernetes/docker
  for target in lab_tools lab_base idm ml testioc tstioc ml-ioc gateway lab internet; do
      echo "    ${target}"
      ( cd "${target}" && ./build_docker.sh "${jobs_arg[@]}" >/dev/null )
  done )

if [ "${keep_certs}" = yes ] && [ -s issuer_ids.env ] && [ -d certs ]; then
    echo "==> keeping the existing certificate authorities"
else
    echo "==> minting the facility root and both departmental intermediates"
    rm -rf certs && mkdir -p certs
    podman run --rm -v "$(pwd)/certs:/certs:Z" \
        "${DOCKER_REGISTRY}/${DOCKER_USERNAME}/idm:latest" bash -c "
            set -e
            arch=\$(/opt/epics/epics-base/startup/EpicsHostArch)
            /opt/epics/pvxs-cms/test/O.\$arch/gen_lab_certs \
                -O /certs -R '${ROOT_CN}' -L '${LAB_CN}' -M '${ML_CN}'
            ls -la /certs"
    cp certs/issuer_ids.env issuer_ids.env
fi

echo
echo "==> issuer ids"
sed 's/^/    /' issuer_ids.env
echo
echo "Now:  podman-compose up -d"
