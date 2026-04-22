ARG DOCKER_REGISTRY=docker.io
ARG DOCKER_USERNAME=georgeleveln
ARG BASE_IMAGE=epics-base
ARG BASE_IMAGE_TAG=latest

FROM ${DOCKER_REGISTRY}/${DOCKER_USERNAME}/${BASE_IMAGE}:${BASE_IMAGE_TAG} AS epics-base

# lab_tools carries the packages and no EPICS, so nothing of pvxs can reach this image.
FROM ${DOCKER_REGISTRY}/${DOCKER_USERNAME}/lab_tools:latest

ENV PROJECT_HOME=/opt/epics
ENV DEBIAN_FRONTEND=noninteractive

# Copied to the same path it was built at, so the rpath in the binaries still resolves.
COPY --from=epics-base ${PROJECT_HOME}/epics-base ${PROJECT_HOME}/epics-base

# softIocPVA and pvmonitor are what this image exists for; without them it is the wrong image.
RUN arch="$(${PROJECT_HOME}/epics-base/startup/EpicsHostArch)" && \
    for tool in softIocPVA pvmonitor pvget pvinfo; do \
        test -x "${PROJECT_HOME}/epics-base/bin/${arch}/${tool}" \
            || { echo "missing ${tool}" >&2; exit 1; }; \
    done && \
    test ! -d ${PROJECT_HOME}/pvxs || { echo "pvxs present; not a Base-only image" >&2; exit 1; }

RUN useradd -m -s /bin/bash testioc && echo "testioc:secret" | chpasswd

COPY testioc_bashrc /home/testioc/.testioc_bashrc
RUN chown testioc:testioc /home/testioc/.testioc_bashrc && \
    chmod 644 /home/testioc/.testioc_bashrc && \
    echo "source ~/.testioc_bashrc" >> /home/testioc/.bashrc

COPY supervisord.conf /etc/supervisor/supervisord.conf

EXPOSE 5075 5076

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/supervisord.conf"]
