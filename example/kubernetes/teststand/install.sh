#!/bin/bash
# Install the teststand laboratory.
#
# Usage: ./install.sh [spva|upstream|pva] [--force-load] [--manual]
#
#   spva          this workspace's pvxs, softIocPVX and pvxmonitor
#   upstream      unmodified upstream pvxs, no TLS, softIocPVX and pvxmonitor
#   pva           the PVAccess inside EPICS Base, softIocPVA and pvmonitor
#   --force-load  load images even when the cluster already holds the same ones
#   --manual      do not start the server; the operator starts it by hand
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHART_DIR="${SCRIPT_DIR}/chart"

# Its own namespace. The four topologies in helm/ live in spva-lab and are driven by
# helpers.sh, so sharing that namespace would put two laboratories on top of each other.
NAMESPACE="${TESTSTAND_NS:-pvxs-teststand}"

VARIANT=""
FORCE_LOAD=0
EXTRA_SET=()

while [ $# -gt 0 ]; do
    case "$1" in
        spva|upstream|pva) VARIANT="$1" ;;
        --force-load)      FORCE_LOAD=1 ;;
        --manual)          EXTRA_SET+=(--set startMode=manual) ;;
        # Anything else is handed to helm, so any value can be overridden on the command line.
        --set|--set-string|--set-json)
            [ $# -ge 2 ] || { echo "$1 needs a value" >&2; exit 1; }
            EXTRA_SET+=("$1" "$2"); shift ;;
        --set=*|--set-string=*|--set-json=*) EXTRA_SET+=("$1") ;;
        *) echo "usage: $0 [spva|upstream|pva] [--force-load] [--manual] [--set k=v ...]" >&2
           exit 1 ;;
    esac
    shift
done
VARIANT="${VARIANT:-spva}"

VALUES_FILE="${SCRIPT_DIR}/values-${VARIANT}.yaml"
RELEASE_NAME="teststand-${VARIANT}"

# ---------------------------------------------------------------------------
# The container engine that owns the kind cluster.
#
# A homebrew podman install puts a `docker` symlink to podman ahead of Docker Desktop's on the
# path, so `kind` asks the wrong engine and reports no clusters while the cluster is running.
# Find the engine whose daemon actually holds the kind node.
# ---------------------------------------------------------------------------
CLUSTER="${KIND_CLUSTER:-}"
if [ -z "${CLUSTER}" ]; then
    ctx="$(kubectl config current-context 2>/dev/null || true)"
    case "${ctx}" in
        kind-*) CLUSTER="${ctx#kind-}" ;;
        *) echo "current kube context '${ctx}' is not a kind cluster; set KIND_CLUSTER" >&2
           exit 1 ;;
    esac
fi

NODE_ENGINE=""
for candidate in /usr/local/bin/docker /opt/homebrew/bin/docker docker podman; do
    command -v "${candidate}" >/dev/null 2>&1 || continue
    if "${candidate}" inspect "${CLUSTER}-control-plane" >/dev/null 2>&1; then
        NODE_ENGINE="$(command -v "${candidate}")"
        break
    fi
done
if [ -z "${NODE_ENGINE}" ]; then
    echo "no container engine holds a node for kind cluster '${CLUSTER}'" >&2
    exit 1
fi

case "$("${NODE_ENGINE}" --version 2>/dev/null)" in
    *podman*) KIND_PROVIDER=podman ;;
    *)        KIND_PROVIDER=docker ;;
esac

# kind runs `docker` from the path, so put the right engine's directory first.
kind_cmd() {
    PATH="$(dirname "${NODE_ENGINE}"):${PATH}" \
    KIND_EXPERIMENTAL_PROVIDER="${KIND_PROVIDER}" kind "$@"
}

# ---------------------------------------------------------------------------
# Which images this variant needs, read from the values file so there is one source of truth.
# ---------------------------------------------------------------------------
REGISTRY="$(grep -E '^dockerRegistry:' "${VALUES_FILE}" | awk '{print $2}')"
USERNAME="$(grep -E '^dockerUsername:' "${VALUES_FILE}" | awk '{print $2}')"
TAG="$(grep -E '^imageTag:' "${VALUES_FILE}" | awk '{print $2}')"
# Deduplicated, because both roles use the same image in the upstream variant.
# Read with a loop rather than mapfile: macOS ships bash 3.2, which has no mapfile.
ROLES=()
while IFS= read -r role; do
    [ -n "${role}" ] && ROLES+=("${role}")
done < <(awk '/^images:/{f=1;next} f&&/^[a-z]/{exit} f&&/:/{print $2}' "${VALUES_FILE}" | sort -u)
# The gateway image too, when a --set turns the gateway on.
if [[ " ${EXTRA_SET[*]:-} " == *gateway.enabled=true* ]]; then
    ROLES+=(gateway)
fi

echo "=== teststand (${VARIANT}) ==="
echo "chart      ${CHART_DIR}"
echo "values     ${VALUES_FILE}"
echo "release    ${RELEASE_NAME}"
echo "namespace  ${NAMESPACE}"
echo "cluster    ${CLUSTER} (${KIND_PROVIDER} via ${NODE_ENGINE})"
echo

# ---------------------------------------------------------------------------
# Load images, skipping any the cluster already holds byte for byte.
#
# The identifier compared is the image config digest, which both the local engine and the
# node's containerd report. Equal digests mean equal image, so the load is pure cost.
# ---------------------------------------------------------------------------
NODES=()
while IFS= read -r node; do
    [ -n "${node}" ] && NODES+=("${node}")
done < <(kind_cmd get nodes --name "${CLUSTER}" 2>/dev/null)
if [ "${#NODES[@]}" -eq 0 ]; then
    echo "kind reports no nodes for cluster '${CLUSTER}'" >&2
    exit 1
fi

local_digest() {   # engine ref -> bare hex, empty if absent
    "$1" image inspect "$2" --format '{{.Id}}' 2>/dev/null | sed 's/^sha256://'
}

node_digest() {    # node ref -> bare hex, empty if absent
    "${NODE_ENGINE}" exec "$1" crictl images -o json 2>/dev/null \
        | python3 -c "
import json,sys
ref=sys.argv[1]
try: images=json.load(sys.stdin)['images']
except Exception: sys.exit()
for i in images:
    if ref in (i.get('repoTags') or []):
        print(i['id'].removeprefix('sha256:')); break
" "$2"
}

for role in "${ROLES[@]}"; do
    ref="${REGISTRY}/${USERNAME}/${role}:${TAG}"

    src_engine=""
    for candidate in podman "${NODE_ENGINE}"; do
        command -v "${candidate}" >/dev/null 2>&1 || continue
        if [ -n "$(local_digest "${candidate}" "${ref}")" ]; then
            src_engine="$(command -v "${candidate}")"
            break
        fi
    done
    if [ -z "${src_engine}" ]; then
        echo "  ${role}: NOT FOUND locally as ${ref}" >&2
        exit 1
    fi
    want="$(local_digest "${src_engine}" "${ref}")"

    needed=()
    for node in "${NODES[@]}"; do
        have="$(node_digest "${node}" "${ref}")"
        if [ "${FORCE_LOAD}" -eq 1 ] || [ "${have}" != "${want}" ]; then
            needed+=("${node}")
        fi
    done

    if [ "${#needed[@]}" -eq 0 ]; then
        echo "  ${role}: already loaded (${want:0:12}), skipping"
        continue
    fi

    echo "  ${role}: loading ${want:0:12} onto ${needed[*]}"
    if [ "${src_engine}" = "${NODE_ENGINE}" ]; then
        kind_cmd load docker-image --name "${CLUSTER}" "${ref}" \
            --nodes "$(IFS=,; echo "${needed[*]}")"
    else
        # The image lives in a different engine's store, so it travels as an archive.
        tmpdir="$(mktemp -d)"
        trap 'rm -rf "${tmpdir}"' EXIT
        "${src_engine}" save "${ref}" -o "${tmpdir}/${role}.tar"
        kind_cmd load image-archive --name "${CLUSTER}" "${tmpdir}/${role}.tar" \
            --nodes "$(IFS=,; echo "${needed[*]}")"
        rm -rf "${tmpdir}"
        trap - EXIT
    fi
done
echo

kubectl create namespace "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f - >/dev/null

# The odd expansion keeps bash 3.2 from treating an empty array as unset under `set -u`.
helm upgrade --install "${RELEASE_NAME}" "${CHART_DIR}" \
    -n "${NAMESPACE}" -f "${VALUES_FILE}" ${EXTRA_SET[@]+"${EXTRA_SET[@]}"} \
    --wait --timeout 5m

cat <<EOF

=== installed ===

Every object is named for the release, so both variants can run side by side.

  kubectl -n ${NAMESPACE} get pods -l release=${RELEASE_NAME}

Watch the monitor:

  kubectl -n ${NAMESPACE} logs -f deployment/${RELEASE_NAME}-monitor

Replace the server pod under it:

  kubectl -n ${NAMESPACE} delete pod -l app=teststand-server,release=${RELEASE_NAME}

Uninstall:

  helm uninstall ${RELEASE_NAME} -n ${NAMESPACE}
EOF
