ARG DOCKER_REGISTRY=ghcr.io
ARG DOCKER_USERNAME=slac-epics
ARG BASE_IMAGE=pvxs-cms
ARG BASE_IMAGE_TAG=latest

FROM ${DOCKER_REGISTRY}/${DOCKER_USERNAME}/${BASE_IMAGE}:${BASE_IMAGE_TAG}

# Set environment variables
ENV PROJECT_HOME=/opt/epics
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && \
    apt-get install -y \
            adduser \
            sudo \
            supervisor \
            libkrb5-dev \
            krb5-user \
            libgssapi-krb5-2

RUN echo "PVXS = \$(TOP)/../pvxs" >> ${PROJECT_HOME}/RELEASE.local
RUN echo "PVXS_ENABLE_KRB_AUTH = YES" >> ${PROJECT_HOME}/CONFIG_SITE.local
RUN cd ${PROJECT_HOME}/pvxs-cms && make -j$(nproc) all

# Copy user kerberos configuration
COPY krb5.conf /etc/krb5.conf

# Copy the top-level Supervisor config
COPY supervisord.conf /etc/supervisor/supervisord.conf

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/supervisord.conf"]
