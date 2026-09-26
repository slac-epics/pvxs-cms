#!/bin/bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTSTAND="$(dirname "${HERE}")"
CLUSTER="cilium-repro"
CONTEXT="kind-${CLUSTER}"
REGULAR_IMAGE="docker.io/georgeleveln/pvxs-upstream:cilium-udp-port-bug"
FIXED_IMAGE="docker.io/georgeleveln/pvxs-upstream:cilium-udp-port-fixed"
LATEST_IMAGE="docker.io/georgeleveln/pvxs-upstream:latest"

usage() {
    echo "usage: $0 {1.18|1.19} {regular|fixed}" >&2
    exit 2
}

[ "$#" -eq 2 ] || usage
case "$1" in
    1.18) CILIUM_VERSION="1.18.5" ;;
    1.19) CILIUM_VERSION="1.19.7" ;;
    *) usage ;;
esac
case "$2" in
    regular) PVXS_IMAGE="${REGULAR_IMAGE}" ;;
    fixed)   PVXS_IMAGE="${FIXED_IMAGE}" ;;
    *) usage ;;
esac

NODE_ENGINE="${DOCKER_BIN:-/usr/local/bin/docker}"
[ -x "${NODE_ENGINE}" ] || { echo "Docker Desktop not found at ${NODE_ENGINE}" >&2; exit 1; }

SOURCE_ENGINE=""
for candidate in podman /opt/homebrew/bin/docker "${NODE_ENGINE}"; do
    command -v "${candidate}" >/dev/null 2>&1 || continue
    if "${candidate}" image inspect "${PVXS_IMAGE}" >/dev/null 2>&1; then
        SOURCE_ENGINE="$(command -v "${candidate}")"
        break
    fi
done
[ -n "${SOURCE_ENGINE}" ] || { echo "image not found: ${PVXS_IMAGE}" >&2; exit 1; }

ORIGINAL_CONTEXT="$(kubectl config current-context 2>/dev/null || true)"
cleanup() {
    "${SOURCE_ENGINE}" tag "${REGULAR_IMAGE}" "${LATEST_IMAGE}" >/dev/null 2>&1 || true
    if [ -n "${ORIGINAL_CONTEXT}" ]; then
        kubectl config use-context "${ORIGINAL_CONTEXT}" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

kind_cmd() {
    PATH="$(dirname "${NODE_ENGINE}"):${PATH}" KIND_EXPERIMENTAL_PROVIDER=docker kind "$@"
}

echo "=== Cilium ${CILIUM_VERSION}, PVXS ${2} ==="
kind_cmd delete cluster --name "${CLUSTER}"
kind_cmd create cluster --config "${HERE}/kind-cluster.yaml"

API_ADDRESS="$("${NODE_ENGINE}" inspect "${CLUSTER}-control-plane" \
    --format '{{.NetworkSettings.Networks.kind.IPAddress}}')"
helm repo add --force-update cilium https://helm.cilium.io/ >/dev/null
helm --kube-context "${CONTEXT}" install cilium cilium/cilium \
    --version "${CILIUM_VERSION}" -n kube-system \
    --set ipam.mode=kubernetes \
    --set operator.replicas=1 \
    --set kubeProxyReplacement=true \
    --set k8sServiceHost="${API_ADDRESS}" \
    --set k8sServicePort=6443 \
    --set socketLB.enabled=true \
    --set socketLB.terminatePodConnections=true
kubectl --context "${CONTEXT}" -n kube-system rollout status daemonset/cilium --timeout=5m
kubectl --context "${CONTEXT}" wait --for=condition=Ready node --all --timeout=5m
kubectl config use-context "${CONTEXT}" >/dev/null

# install.sh loads the latest tag, so point it at the selected image for this run.
"${SOURCE_ENGINE}" tag "${PVXS_IMAGE}" "${LATEST_IMAGE}"
KIND_CLUSTER="${CLUSTER}" "${TESTSTAND}/install.sh" upstream --force-load

OUTPUT="$("${TESTSTAND}/experiment.py" \
    --variant upstream \
    --search udp \
    --kill graceful \
    --load slow \
    --probes supervisor \
    --grace 0 \
    --observe 45 \
    --settle 0 \
    --verbose)"
printf '%s\n' "${OUTPUT}"

EXPECTED="clean"
if [ "$1" = "1.19" ] && [ "$2" = "regular" ]; then
    EXPECTED="noreconnect"
fi
if ! printf '%s\n' "${OUTPUT}" | grep -Eq "[[:space:]]${EXPECTED}[[:space:]]"; then
    echo "FAIL: expected ${EXPECTED}" >&2
    exit 1
fi
echo "PASS: observed ${EXPECTED}"
