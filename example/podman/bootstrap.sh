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

if [ "$keep_certs" = yes ] && [ -s issuer_ids.env ] && [ -d certs ]; then
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
            -M '${ML_CN}'
        ls -la /certs"
    cp certs/issuer_ids.env issuer_ids.env
    # compose substitutes ${LAB_ISSUER} and ${ML_ISSUER} in the file itself from .env,
    # which it reads before anything else. env_file only reaches the container, and by
    # then the substitution has already happened, so both are needed.
    cp certs/issuer_ids.env .env
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
