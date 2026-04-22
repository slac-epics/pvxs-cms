#!/bin/bash
set -e

DOCKER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

DOCKER_REGISTRY="${DOCKER_REGISTRY:-docker.io}"
DOCKER_USERNAME="${DOCKER_USERNAME:-georgeleveln}"
TARGET_IMAGE_NAME="epics-pva"
TARGET_IMAGE_TAG="latest"

echo "--- Pushing ${TARGET_IMAGE_NAME}:${TARGET_IMAGE_TAG} ---"

docker push "${DOCKER_REGISTRY}/${DOCKER_USERNAME}/${TARGET_IMAGE_NAME}:${TARGET_IMAGE_TAG}"

echo "--- Successfully pushed ${TARGET_IMAGE_NAME}:${TARGET_IMAGE_TAG} ---"