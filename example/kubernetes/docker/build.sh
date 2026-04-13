#!/bin/zsh
DOCKER_ROOT_DIR="$(dirname "$0")"
DOCKER_ROOT_DIR=${DOCKER_ROOT_DIR:A}

${DOCKER_ROOT_DIR}/lab_base/build_docker.sh ${*}
${DOCKER_ROOT_DIR}/internet/build_docker.sh ${*}
${DOCKER_ROOT_DIR}/ml-ioc/build_docker.sh ${*}

${DOCKER_ROOT_DIR}/lab/build_docker.sh ${*}
${DOCKER_ROOT_DIR}/cs-studio/build_docker.sh ${*}

${DOCKER_ROOT_DIR}/testioc/build_docker.sh ${*}
${DOCKER_ROOT_DIR}/tstioc/build_docker.sh ${*}

${DOCKER_ROOT_DIR}/idm/build_docker.sh ${*}
${DOCKER_ROOT_DIR}/ml/build_docker.sh ${*}

${DOCKER_ROOT_DIR}/gateway/build_docker.sh ${*}
