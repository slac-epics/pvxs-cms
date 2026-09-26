#!/bin/bash
# Build the upstream pvxs image: unmodified upstream pvxs, no TLS, laid out so the teststand
# chart runs against it exactly as it runs against this repository's images.
set -e

DOCKER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

TARGET_IMAGE_NAME="pvxs-upstream"
TARGET_IMAGE_TAG="${TARGET_IMAGE_TAG:-latest}"

DOCKER_REGISTRY="${DOCKER_REGISTRY:-docker.io}"
DOCKER_USERNAME="${DOCKER_USERNAME:-georgeleveln}"
UPSTREAM_PVXS_REF="${UPSTREAM_PVXS_REF:-master}"

REF="${DOCKER_REGISTRY}/${DOCKER_USERNAME}/${TARGET_IMAGE_NAME}:${TARGET_IMAGE_TAG}"

echo "--- building ${REF} ---"
echo "    base:              ${DOCKER_REGISTRY}/${DOCKER_USERNAME}/epics-base:latest"
echo "    packages from:     ${DOCKER_REGISTRY}/${DOCKER_USERNAME}/lab_tools:latest"
echo "    upstream pvxs ref: ${UPSTREAM_PVXS_REF}"

docker build \
  --build-arg DOCKER_REGISTRY="${DOCKER_REGISTRY}" \
  --build-arg DOCKER_USERNAME="${DOCKER_USERNAME}" \
  --build-arg BASE_IMAGE=epics-base \
  --build-arg BASE_IMAGE_TAG=latest \
  --build-arg UPSTREAM_PVXS_REF="${UPSTREAM_PVXS_REF}" \
  ${JOBS:+--build-arg JOBS=${JOBS}} \
  "${@}" \
  -t "${REF}" \
  -f "${DOCKER_DIR}/Dockerfile" \
  "${DOCKER_DIR}"

echo "--- built ${REF} ---"
echo "    upstream pvxs commit: $(docker run --rm "${REF}" cat /opt/epics/pvxs-upstream-ref)"
