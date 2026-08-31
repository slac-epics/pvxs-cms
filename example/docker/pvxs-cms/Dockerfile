ARG DOCKER_REGISTRY=ghcr.io
ARG DOCKER_USERNAME=slac-epics
ARG BASE_IMAGE=pvxs
ARG BASE_IMAGE_TAG=latest

FROM ${DOCKER_REGISTRY}/${DOCKER_USERNAME}/${BASE_IMAGE}:${BASE_IMAGE_TAG}

# Set environment variables
ENV PROJECT_HOME=/opt/epics
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && \
    apt-get install -y \
            openssl \
            libssl-dev \
            libevent-dev \
            libsqlite3-dev \
            libcurl4-openssl-dev \
            pkg-config

# Set up RELEASE.local
WORKDIR ${PROJECT_HOME}
RUN echo "EPICS_BASE = \$(TOP)/../epics-base" >> ${PROJECT_HOME}/RELEASE.local
RUN echo "PVXS = \$(TOP)/../pvxs"             >> ${PROJECT_HOME}/RELEASE.local

# Set up CONFIG_SITE.local
RUN echo "PVXS_ENABLE_PVACMS = YES"           >> CONFIG_SITE.local

# VCS_VERSION carries `git describe` in from the host, because .dockerignore keeps
# .git out of the build context. It is recorded in CONFIG_SITE.local, so the
# downstream images that rebuild this tree keep it.
ARG VCS_VERSION=unknown
WORKDIR ${PROJECT_HOME}
RUN echo "GENVERSIONDEFAULT = ${VCS_VERSION}" >> CONFIG_SITE.local

# build PVXS-CMS
WORKDIR ${PROJECT_HOME}/pvxs-cms
COPY . .
# How many compiler processes to run at once. Each can take most of a gigabyte,
# so a machine with little memory and no swap needs this lowered.
ARG JOBS
RUN make -j${JOBS:-$(nproc)} all

CMD ["/bin/bash"]
