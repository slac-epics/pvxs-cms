ARG DOCKER_REGISTRY=ghcr.io
ARG DOCKER_USERNAME=slac-epics
ARG BASE_IMAGE=lab_base
ARG BASE_IMAGE_TAG=latest

FROM ${DOCKER_REGISTRY}/${DOCKER_USERNAME}/${BASE_IMAGE}:${BASE_IMAGE_TAG}

# Set environment variables
ENV PROJECT_HOME=/opt/epics
ENV DEBIAN_FRONTEND=noninteractive

# Create user with pre-set password ("secret")
RUN useradd -m -s /bin/bash tstioc && echo "tstioc:secret" | chpasswd

# Copy user-specific environment settings
COPY tstioc_bashrc /home/tstioc/.tstioc_bashrc
COPY tstioc.acf    /home/tstioc/tstioc.acf

RUN chown tstioc:tstioc /home/tstioc/.tstioc_bashrc && \
    chmod 644           /home/tstioc/.tstioc_bashrc && \
    chown tstioc:tstioc /home/tstioc/tstioc.acf     && \
    chmod 644           /home/tstioc/tstioc.acf

RUN echo "source ~/.tstioc_bashrc" >> /home/tstioc/.bashrc

# Copy the tstioc Supervisor config
COPY tstioc-supervisor.conf /etc/supervisor/conf.d/tstioc.conf

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/supervisord.conf"]
