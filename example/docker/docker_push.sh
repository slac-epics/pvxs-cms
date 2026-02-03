docker push ${DOCKER_REGISTRY:-ghcr.io}/${DOCKER_USERNAME:-slac-epics}/epics-base:latest
docker push ${DOCKER_REGISTRY:-ghcr.io}/${DOCKER_USERNAME:-slac-epics}/pvxs:latest
docker push ${DOCKER_REGISTRY:-ghcr.io}/${DOCKER_USERNAME:-slac-epics}/spva_std:latest
docker push ${DOCKER_REGISTRY:-ghcr.io}/${DOCKER_USERNAME:-slac-epics}/spva_krb:latest
docker push ${DOCKER_REGISTRY:-ghcr.io}/${DOCKER_USERNAME:-slac-epics}/spva_ldap:latest
docker push ${DOCKER_REGISTRY:-ghcr.io}/${DOCKER_USERNAME:-slac-epics}/spva_jwt:latest
