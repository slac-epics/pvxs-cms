docker push ${DOCKER_REGISTRY:-ghcr.io}/${DOCKER_USERNAME:-slac-epics}/lab_base:latest
docker push ${DOCKER_REGISTRY:-ghcr.io}/${DOCKER_USERNAME:-slac-epics}/lab:latest
docker push ${DOCKER_REGISTRY:-ghcr.io}/${DOCKER_USERNAME:-slac-epics}/gateway:latest
docker push ${DOCKER_REGISTRY:-ghcr.io}/${DOCKER_USERNAME:-slac-epics}/pvacms:latest
docker push ${DOCKER_REGISTRY:-ghcr.io}/${DOCKER_USERNAME:-slac-epics}/testioc:latest
docker push ${DOCKER_REGISTRY:-ghcr.io}/${DOCKER_USERNAME:-slac-epics}/tstioc:latest
