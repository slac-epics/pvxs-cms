#!/bin/bash
# Build the images the demonstration laboratories are made from.
#
# Run once, before the first ./reset.sh. The images are the same whichever laboratory you
# bring up; what differs between them is their certificate authorities, and those are minted
# by ./reset.sh into the topology that owns them.
#
# JOBS controls how many compiler processes run at once. Each can take most of a
# gigabyte, so on a machine with little memory set it low:
#
#     JOBS=2 ./bootstrap.sh
#
set -euo pipefail
cd "$(dirname "$0")"

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

# An unset JOBS means "one compiler process per core". Written as an if rather than a
# short-circuit, because under set -e a trailing && that evaluates false exits the script.
if [ -n "${JOBS:-}" ]; then
    echo "==> building with JOBS=${JOBS}"
else
    echo "==> building with one compiler process per core; set JOBS to lower it"
fi

# Build one image, offering it JOBS only if it compiles something. An image is asked rather
# than listed here, so adding one that compiles needs nothing changed in this file. Offering
# it to an image that declares no such argument is not an error but is reported as a warning
# on every build, which reads like a fault in the middle of an otherwise silent hour.
build_image() {
    local dir="$1"; shift
    local args=()
    if [ -n "${JOBS:-}" ] && grep -q '^ARG JOBS' "${dir}/Dockerfile"; then
        args=(--build-arg "JOBS=${JOBS}")
    fi
    ( cd "${dir}" && ./build_docker.sh "${args[@]}" "$@" )
}

# --keep-certs is accepted and ignored: it meant "rebuild the images without reminting", and
# building no longer mints anything, so that is what it does now anyway.
case "${1:-}" in
    --keep-certs|"") ;;
    *) echo "usage: ./bootstrap.sh [--keep-certs]" >&2; exit 2 ;;
esac

if true; then

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

# Not ours, and not built: the facility load balancer is HAProxy, which is what a site would
# use for this. Pulled here so that bringing a laboratory up needs no registry.
echo "==> fetching the load balancer image"
podman pull -q docker.io/library/haproxy:lts-alpine >/dev/null 2>&1 \
    || echo "    could not fetch haproxy - ./reset.sh simple-with-gateway will need it" >&2

echo
echo "The images are built. Certificate authorities belong to a laboratory rather than to the"
echo "images, so they are minted when you bring one up:"
echo
echo "    ./reset.sh <topology>"
echo
echo "./reset.sh with no name lists the four and says what each one is."
