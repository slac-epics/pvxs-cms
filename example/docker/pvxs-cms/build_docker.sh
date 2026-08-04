#!/bin/zsh
set -e # Exit immediately if a command exits with a non-zero status.

DOCKER_DIR="$(dirname "$0")"
DOCKER_DIR=${DOCKER_DIR:A}
PROJECTS=${DOCKER_DIR}/../../../..
PROJECTS=${PROJECTS:A}

pushd "${PROJECTS}/pvxs-cms"

# Add trap to ensure we return to original directory on exit
trap "popd" EXIT

BASE_IMAGE_NAME="pvxs"
BASE_IMAGE_TAG="latest"
TARGET_IMAGE_NAME="pvxs-cms"
TARGET_IMAGE_TAG="latest"

echo "--- Building ${TARGET_IMAGE_NAME} Docker image ---"

# .dockerignore keeps .git out of the build context, so the in-image build cannot
# run git describe itself. Read it here and pass it in, so `pvacms -V` in a pod
# still names the commit it was built from.
VCS_VERSION="$(git describe --tags --dirty --always 2>/dev/null || echo unknown)"

docker build \
  --build-arg DOCKER_REGISTRY="${DOCKER_REGISTRY:-ghcr.io}" \
  --build-arg DOCKER_USERNAME="${DOCKER_USERNAME:-slac-epics}" \
  --build-arg BASE_IMAGE=${BASE_IMAGE_NAME} \
  --build-arg BASE_IMAGE_TAG=${BASE_IMAGE_TAG} \
  --build-arg VCS_VERSION="${VCS_VERSION}" \
  ${*} \
  -t "${DOCKER_REGISTRY:-ghcr.io}/${DOCKER_USERNAME:-slac-epics}/${TARGET_IMAGE_NAME}:${TARGET_IMAGE_TAG}" \
  -f "${DOCKER_DIR}/Dockerfile" \
  .

echo "--- Successfully built ${TARGET_IMAGE_NAME}:${TARGET_IMAGE_TAG} ---"
