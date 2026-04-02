#!/bin/zsh
set -e

DOCKER_DIR="$(dirname "$0")"
DOCKER_DIR=${DOCKER_DIR:A}
PROJECTS=${DOCKER_DIR}/../../../..
PROJECTS=${PROJECTS:A}

pushd "${DOCKER_DIR}"
trap "popd" EXIT

BASE_IMAGE_NAME="lab_base"
BASE_IMAGE_TAG="latest"
TARGET_IMAGE_NAME="internet"
TARGET_IMAGE_TAG="latest"

echo "--- Building ${TARGET_IMAGE_NAME} Docker image ---"

docker build \
  --build-arg DOCKER_REGISTRY="${DOCKER_REGISTRY:-ghcr.io}" \
  --build-arg DOCKER_USERNAME="${DOCKER_USERNAME:-slac-epics}" \
  --build-arg BASE_IMAGE=${BASE_IMAGE_NAME} \
  --build-arg BASE_IMAGE_TAG=${BASE_IMAGE_TAG} \
  ${*} \
  -t "${DOCKER_REGISTRY:-ghcr.io}/${DOCKER_USERNAME:-slac-epics}/${TARGET_IMAGE_NAME}:${TARGET_IMAGE_TAG}" \
  -f "${DOCKER_DIR}/Dockerfile" \
  .

echo "--- Successfully built ${TARGET_IMAGE_NAME}:${TARGET_IMAGE_TAG} ---"
