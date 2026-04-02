ARG DOCKER_REGISTRY=ghcr.io
ARG DOCKER_USERNAME=slac-epics
ARG BASE_IMAGE=lab_base
ARG BASE_IMAGE_TAG=latest

FROM ${DOCKER_REGISTRY}/${DOCKER_USERNAME}/${BASE_IMAGE}:${BASE_IMAGE_TAG}

ENV PROJECT_HOME=/opt/epics
ENV DEBIAN_FRONTEND=noninteractive

RUN useradd -m -s /bin/bash mlioc && echo "mlioc:secret" | chpasswd

COPY mlioc_bashrc /home/mlioc/.mlioc_bashrc
COPY mlioc.db     /home/mlioc/mlioc.db

RUN chown mlioc:mlioc /home/mlioc/.mlioc_bashrc && \
    chmod 644         /home/mlioc/.mlioc_bashrc && \
    chown mlioc:mlioc /home/mlioc/mlioc.db      && \
    chmod 644         /home/mlioc/mlioc.db

RUN echo "source ~/.mlioc_bashrc" >> /home/mlioc/.bashrc

COPY mlioc-supervisor.conf /etc/supervisor/conf.d/mlioc.conf

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/supervisord.conf"]
