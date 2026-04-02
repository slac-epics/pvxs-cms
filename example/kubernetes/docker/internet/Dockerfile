ARG DOCKER_REGISTRY=ghcr.io
ARG DOCKER_USERNAME=slac-epics
ARG BASE_IMAGE=lab_base
ARG BASE_IMAGE_TAG=latest

FROM ${DOCKER_REGISTRY}/${DOCKER_USERNAME}/${BASE_IMAGE}:${BASE_IMAGE_TAG}

ENV PROJECT_HOME=/opt/epics
ENV DEBIAN_FRONTEND=noninteractive

RUN useradd -m -s /bin/bash operator -g operator && echo "operator:secret" | chpasswd
RUN useradd -m -s /bin/bash guest                && echo "guest:secret"    | chpasswd

COPY operator_bashrc /home/operator/.operator_bashrc
COPY guest_bashrc    /home/guest/.guest_bashrc

RUN chown operator:operator /home/operator/.operator_bashrc && \
    chown guest:guest       /home/guest/.guest_bashrc       && \
    chmod 644               /home/operator/.operator_bashrc && \
    chmod 644               /home/guest/.guest_bashrc

RUN echo "source ~/.operator_bashrc" >> /home/operator/.bashrc
RUN echo "source ~/.guest_bashrc"    >> /home/guest/.bashrc

USER guest

CMD ["sleep", "infinity"]
