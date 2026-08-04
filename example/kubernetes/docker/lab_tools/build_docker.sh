#!/bin/zsh
set -e # Exit immediately if a command exits with a non-zero status.

DOCKER_DIR="$(dirname "$0")"
DOCKER_DIR=${DOCKER_DIR:A}

pushd "${DOCKER_DIR}"

# Add trap to ensure we return to original directory on exit
trap "popd" EXIT

TARGET_IMAGE_NAME="lab_tools"
TARGET_IMAGE_TAG="latest"

echo "--- Building ${TARGET_IMAGE_NAME} Docker image ---"

docker build \
  ${*} \
  -t "${DOCKER_REGISTRY:-ghcr.io}/${DOCKER_USERNAME:-slac-epics}/${TARGET_IMAGE_NAME}:${TARGET_IMAGE_TAG}" \
  -f "${DOCKER_DIR}/Dockerfile" \
  .

echo "--- Successfully built ${TARGET_IMAGE_NAME}:${TARGET_IMAGE_TAG} ---"
