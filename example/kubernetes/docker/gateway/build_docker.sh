#!/bin/zsh
set -e # Exit immediately if a command exits with a non-zero status.

DOCKER_DIR="$(dirname "$0")"
DOCKER_DIR=${DOCKER_DIR:A}

# To common root of pvxs and p4p projects
PROJECTS=${DOCKER_DIR}/../../../../..
PROJECTS=${PROJECTS:A}
pushd "${PROJECTS}"
RELATIVE_DOCKER_DIR=pvxs-cms/example/kubernetes/docker/gateway

# Add trap to ensure we return to original directory on exit
trap "popd" EXIT

BASE_IMAGE_NAME="lab_base"
BASE_IMAGE_TAG="dev"
TARGET_IMAGE_NAME="gateway"
TARGET_IMAGE_TAG="dev"

echo "--- Building ${TARGET_IMAGE_NAME} Docker image ---"

docker build \
  --build-arg DOCKER_REGISTRY=${DOCKER_REGISTRY:-ghcr.io} \
  --build-arg DOCKER_USERNAME=${DOCKER_USERNAME:-slac-epics} \
  --build-arg BASE_IMAGE=${BASE_IMAGE_NAME} \
  --build-arg BASE_IMAGE_TAG=${BASE_IMAGE_TAG} \
  --build-arg RELATIVE_DOCKER_DIR=${RELATIVE_DOCKER_DIR} \
  ${*} \
  -t "${DOCKER_REGISTRY:-ghcr.io}/${DOCKER_USERNAME:-slac-epics}/${TARGET_IMAGE_NAME}:${TARGET_IMAGE_TAG}" \
  -f "${DOCKER_DIR}/Dockerfile" \
  .

echo "--- Successfully built ${TARGET_IMAGE_NAME}:${TARGET_IMAGE_TAG} ---"
