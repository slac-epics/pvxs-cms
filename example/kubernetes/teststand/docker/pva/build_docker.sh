#!/bin/bash
# Build the EPICS Base PVA image: softIocPVA and pvmonitor, no pvxs, laid out so the teststand
# chart runs against it exactly as it runs against the pvxs images.
set -e

DOCKER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

TARGET_IMAGE_NAME="epics-pva"
TARGET_IMAGE_TAG="${TARGET_IMAGE_TAG:-latest}"
DOCKER_REGISTRY="${DOCKER_REGISTRY:-docker.io}"
DOCKER_USERNAME="${DOCKER_USERNAME:-georgeleveln}"

REF="${DOCKER_REGISTRY}/${DOCKER_USERNAME}/${TARGET_IMAGE_NAME}:${TARGET_IMAGE_TAG}"

echo "--- building ${REF} ---"
echo "    EPICS Base from: ${DOCKER_REGISTRY}/${DOCKER_USERNAME}/epics-base:latest"
echo "    packages from:   ${DOCKER_REGISTRY}/${DOCKER_USERNAME}/lab_tools:latest"

docker build \
  --build-arg DOCKER_REGISTRY="${DOCKER_REGISTRY}" \
  --build-arg DOCKER_USERNAME="${DOCKER_USERNAME}" \
  --build-arg BASE_IMAGE=epics-base \
  --build-arg BASE_IMAGE_TAG=latest \
  "${@}" \
  -t "${REF}" \
  -f "${DOCKER_DIR}/Dockerfile" \
  "${DOCKER_DIR}"

echo "--- built ${REF} ---"
