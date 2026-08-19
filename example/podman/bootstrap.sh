#!/bin/bash
set -euo pipefail

build_image() {
    local dir="$1"; shift
    local args=()
    if [ -n "${JOBS:-}" ] && grep -q '^ARG JOBS' "${dir}/Dockerfile"; then
        args=(--build-arg "JOBS=${JOBS}")
    fi
    # Bash 3.2 treats an empty array expanded under set -u as an unbound variable.
    ( cd "${dir}" && ./build_docker.sh ${args[@]+"${args[@]}"} "$@" )
}
