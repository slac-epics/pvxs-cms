#!/bin/zsh
DOCKER_DIR="$(dirname "$0")"
DOCKER_DIR=${DOCKER_DIR:A}

${DOCKER_DIR}/pvxs-cms/build_docker.sh ${*} && \
${DOCKER_DIR}/spva_std/build_docker.sh ${*} && \
${DOCKER_DIR}/spva_krb/build_docker.sh ${*} && \
${DOCKER_DIR}/spva_ldap/build_docker.sh ${*} && \
