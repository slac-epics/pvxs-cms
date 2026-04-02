ARG DOCKER_REGISTRY=ghcr.io
ARG DOCKER_USERNAME=slac-epics
ARG BASE_IMAGE_TAG=latest

FROM ${DOCKER_REGISTRY}/${DOCKER_USERNAME}/idm:${BASE_IMAGE_TAG}

ENV PROJECT_HOME=/opt/epics
ENV DEBIAN_FRONTEND=noninteractive

RUN useradd -m -s /bin/bash mloperator && echo "mloperator:secret" | chpasswd
RUN useradd -m -s /bin/bash mlsystem   && echo "mlsystem:secret"   | chpasswd

COPY mloperator_bashrc /home/mloperator/.mloperator_bashrc
COPY mlsystem_bashrc   /home/mlsystem/.mlsystem_bashrc

RUN chown mloperator:mloperator /home/mloperator/.mloperator_bashrc && \
    chown mlsystem:mlsystem     /home/mlsystem/.mlsystem_bashrc     && \
    chmod 644                   /home/mloperator/.mloperator_bashrc && \
    chmod 644                   /home/mlsystem/.mlsystem_bashrc

RUN echo "source ~/.mloperator_bashrc" >> /home/mloperator/.bashrc
RUN echo "source ~/.mlsystem_bashrc"   >> /home/mlsystem/.bashrc

# Remove inherited KDC supervisor configs — only idm should run the KDC
RUN rm -f /etc/supervisor/conf.d/kadmind.conf /etc/supervisor/conf.d/krb5kdc.conf

COPY pvacms-cluster-supervisor.conf /etc/supervisor/conf.d/pvacms.conf

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/supervisord.conf"]
