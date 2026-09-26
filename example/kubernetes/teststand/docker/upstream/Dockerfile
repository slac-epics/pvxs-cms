ARG DOCKER_REGISTRY=docker.io
ARG DOCKER_USERNAME=georgeleveln
ARG BASE_IMAGE=epics-base
ARG BASE_IMAGE_TAG=latest

# EPICS Base, already built, from the existing image.
FROM ${DOCKER_REGISTRY}/${DOCKER_USERNAME}/${BASE_IMAGE}:${BASE_IMAGE_TAG} AS epics-base

# lab_tools, not lab_base: it carries the packages and no pvxs, so nothing of this
# repository's pvxs can survive into the image and be mistaken for upstream.
FROM ${DOCKER_REGISTRY}/${DOCKER_USERNAME}/lab_tools:latest

ENV PROJECT_HOME=/opt/epics
ENV DEBIAN_FRONTEND=noninteractive

COPY --from=epics-base ${PROJECT_HOME}/epics-base ${PROJECT_HOME}/epics-base

ARG UPSTREAM_PVXS_REPO=https://github.com/epics-base/pvxs.git
ARG UPSTREAM_PVXS_REF=master
ARG JOBS

# Built at its final path. An EPICS build bakes an rpath naming the library directory it was
# built in, so a tree built elsewhere and copied here cannot find its own libraries.
RUN echo "EPICS_BASE = \$(TOP)/../epics-base" >> ${PROJECT_HOME}/RELEASE.local && \
    git clone ${UPSTREAM_PVXS_REPO} ${PROJECT_HOME}/pvxs && \
    git -C ${PROJECT_HOME}/pvxs checkout --detach ${UPSTREAM_PVXS_REF} && \
    git -C ${PROJECT_HOME}/pvxs rev-parse HEAD > ${PROJECT_HOME}/pvxs-upstream-ref && \
    make -C ${PROJECT_HOME}/pvxs -j${JOBS:-$(nproc)} all

# Refuse to ship an image whose pvxs has TLS in it, which would defeat its only purpose.
RUN if [ -e ${PROJECT_HOME}/pvxs/src/openssl.cpp ] || [ -d ${PROJECT_HOME}/pvxs/src/secure ]; then \
        echo "this pvxs tree contains TLS sources; not upstream" >&2; exit 1; \
    fi

RUN useradd -m -s /bin/bash testioc && echo "testioc:secret" | chpasswd

COPY testioc_bashrc /home/testioc/.testioc_bashrc
RUN chown testioc:testioc /home/testioc/.testioc_bashrc && \
    chmod 644 /home/testioc/.testioc_bashrc && \
    echo "source ~/.testioc_bashrc" >> /home/testioc/.bashrc

# lab_base's copy carries the display programs this laboratory does not use, so this is its
# own. The chart mounts the program file into /etc/supervisor/conf.d.
COPY supervisord.conf /etc/supervisor/supervisord.conf

EXPOSE 5075 5076

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/supervisord.conf"]
