#!/bin/bash
# Build the images the demonstration laboratories are made from. Both laboratories use the
# same images: podman runs them directly, Kubernetes loads them into its cluster.
#
# Run through the helper of whichever laboratory you are using - build_images (podman) or
# kbuild_images (kubernetes) - or directly, once, before the first reset. What differs
# between laboratories is their certificate authorities, and those are minted at reset.
#
# JOBS controls how many compiler processes run at once. Each can take most of a
# gigabyte, so on a machine with little memory set it low:
#
#     JOBS=2 ./bootstrap.sh
#
set -euo pipefail
cd "$(dirname "$0")"

# Which engine builds. The two laboratories are separate instances with separate image
# stores, and each is tested against its own: the podman helper sets podman, the
# kubernetes helper sets whatever its cluster runs on. The inner build scripts call
# `docker` unconditionally, so a podman build puts a private docker-to-podman link first
# on PATH rather than trusting whatever `docker` happens to resolve to on this machine.
CONTAINER_ENGINE="${CONTAINER_ENGINE:-docker}"
case "${CONTAINER_ENGINE}" in
    docker)
        command -v docker >/dev/null || {
            echo "no 'docker' command found. Install Docker, or on a podman machine" >&2
            echo "install the shim:" >&2
            echo "    sudo apt install podman-docker        # Debian, Ubuntu" >&2
            echo "    sudo dnf install podman-docker        # Fedora, RHEL" >&2
            exit 1; } ;;
    podman)
        command -v podman >/dev/null || { echo "podman is not installed" >&2; exit 1; }
        _shim_dir=$(mktemp -d)
        trap 'rm -rf "${_shim_dir}"' EXIT
        ln -s "$(command -v podman)" "${_shim_dir}/docker"
        PATH="${_shim_dir}:${PATH}"; export PATH ;;
    *)  echo "CONTAINER_ENGINE must be docker or podman, not '${CONTAINER_ENGINE}'" >&2
        exit 2 ;;
esac
echo "==> building with ${CONTAINER_ENGINE} ($(command -v docker))"

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
# on every build.
build_image() {
    local dir="$1"; shift
    local args=()
    if [ -n "${JOBS:-}" ] && grep -q '^ARG JOBS' "${dir}/Dockerfile"; then
        args=(--build-arg "JOBS=${JOBS}")
    fi
    # The guarded expansion keeps bash 3.2 (macOS /bin/bash) happy: under set -u it
    # treats an empty array expanded with "${args[@]}" as an unbound variable.
    ( cd "${dir}" && ./build_docker.sh ${args[@]+"${args[@]}"} "$@" )
}

# --keep-certs is accepted and ignored: building mints nothing.
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
# here, and nor are the display images.
echo "==> building epics-base and pvxs (compiles EPICS Base and pvxs)"
build_image ../../pvxs/example/docker/epics-base
build_image ../../pvxs/example/docker/pvxs

echo "==> building the pvxs-cms image"
build_image docker/pvxs-cms

echo "==> building the laboratory images"
# lab_tools carries the operating system packages, lab_base the built EPICS tree, and
# everything else derives from lab_base. This order matters.
for target in lab_tools lab_base idm ml testioc tstioc ml-ioc gateway lab internet; do
    echo "    ${target}"
    build_image "kubernetes/docker/${target}" >/dev/null
done

fi

# Not ours, and not built: the facility load balancer is HAProxy, which is what a site would
# use for this. Pulled here so that bringing a laboratory up needs no registry.
echo "==> fetching the load balancer image"
docker pull -q docker.io/library/haproxy:lts-alpine >/dev/null 2>&1 \
    || echo "    could not fetch haproxy - the gateway laboratories will need it" >&2

echo
echo "The images are built. Certificate authorities belong to a laboratory rather than to the"
echo "images, so they are minted when you bring one up:"
echo
echo "    podman:      cd podman     && . ./helpers.sh && reset_topology <topology>"
echo "    kubernetes:  cd kubernetes && . ./helpers.sh && kload_images && kreset_topology <topology>"
