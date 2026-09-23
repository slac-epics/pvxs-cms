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

command -v podman >/dev/null || { echo "podman is not installed" >&2; exit 1; }
command -v docker >/dev/null || {
    echo "no 'docker' command found. Install the podman-docker shim." >&2
    exit 1
}

export DOCKER_REGISTRY="${DOCKER_REGISTRY:-localhost}"
export DOCKER_USERNAME="${DOCKER_USERNAME:-spva}"

if [ -n "${JOBS:-}" ]; then
    echo "==> building with JOBS=${JOBS}"
else
    echo "==> building with one compiler process per core; set JOBS to lower it"
fi

build_image() {
    local dir="$1"; shift
    local args=()
    if [ -n "${JOBS:-}" ] && grep -q '^ARG JOBS' "${dir}/Dockerfile"; then
        args=(--build-arg "JOBS=${JOBS}")
    fi
    ( cd "${dir}" && ./build_docker.sh ${args[@]+"${args[@]}"} "$@" )
}

keep_certs=no
build_images=yes
case "${1:-}" in
    --keep-certs) keep_certs=yes ;;
    # Mint the authorities and nothing else. The images are already built and none of this
    # changes them, so rebuilding them to hand out new authorities costs many minutes and
    # recompiles EPICS Base, pvxs, pvxs-cms and p4p for no gain. reset.sh uses this.
    --certs-only) build_images=no ;;
    "") ;;
    *) echo "usage: ./bootstrap.sh [--keep-certs | --certs-only]" >&2; exit 2 ;;
esac

if [ "${build_images}" = yes ]; then

# The images form a chain, each built on the one before:
#
#   ubuntu -> epics-base -> pvxs -> pvxs-cms -> lab_tools/lab_base -> the laboratory
#
# The first two live in the pvxs tree, the third in this one. Only these three are taken
# from example/docker: the Kerberos and LDAP authenticator images beside them are not used
# here, because this laboratory issues certificates with the standard authenticator, and
# the display images are left out because everything is verified from the command line.
echo "==> building epics-base and pvxs (compiles EPICS Base and pvxs)"
build_image ../../../pvxs/example/docker/epics-base
build_image ../../../pvxs/example/docker/pvxs

echo "==> building the pvxs-cms image"
build_image ../docker/pvxs-cms

echo "==> building the laboratory images"
# lab_tools carries the operating system packages, lab_base the built EPICS tree, and
# everything else derives from lab_base. This order matters.
for target in lab_tools lab_base idm ml testioc tstioc ml-ioc gateway lab internet; do
    echo "    ${target}"
    build_image "../kubernetes/docker/${target}" >/dev/null
done

fi

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
            -O /certs \
            -R '${ROOT_CN}' \
            -L '${LAB_CN}' \
            -M '${ML_CN}' \
            -S 'http://pvxs-lab-authority-status:8888'
        ls -la /certs"
    cp certs/issuer_ids.env issuer_ids.env
    # compose substitutes ${LAB_ISSUER} and ${ML_ISSUER} in the file itself from .env,
    # which it reads before anything else. env_file only reaches the container, and by
    # then the substitution has already happened, so both are needed.
    cp certs/issuer_ids.env .env

    # What the responder needs, under the names it is started with. It is kept apart from
    # ./certs because ./certs holds authorities and this holds one service's configuration,
    # and because the file that says whether the root still stands is rewritten during a
    # demonstration while nothing in ./certs is.
    rm -rf ocsp && mkdir -p ocsp
    cp certs/ocsp_ca.pem     ocsp/ca.pem
    cp certs/ocsp_signer.pem ocsp/signer.pem
    cp certs/ocsp_signer.key ocsp/signer.key
    cp certs/ocsp_index.txt  ocsp/index.txt
fi

echo
echo "==> issuer ids"
sed 's/^/    /' issuer_ids.env
echo
echo "Now:  podman-compose up -d"
echo
echo "After 'podman-compose up -d', issue the certificates, then restart the two gateways."
echo "A gateway that starts before the controllers are serving does not retry, and nothing"
echo "reaches across a boundary until it is restarted."
