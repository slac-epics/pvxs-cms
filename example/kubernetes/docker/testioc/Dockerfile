ARG DOCKER_REGISTRY=ghcr.io
ARG DOCKER_USERNAME=slac-epics
ARG BASE_IMAGE=lab_base
ARG BASE_IMAGE_TAG=latest

FROM ${DOCKER_REGISTRY}/${DOCKER_USERNAME}/${BASE_IMAGE}:${BASE_IMAGE_TAG}

# Set environment variables
ENV PROJECT_HOME=/opt/epics
ENV DEBIAN_FRONTEND=noninteractive

# Create user with pre-set password ("secret")
RUN useradd -m -s /bin/bash testioc && echo "testioc:secret" | chpasswd

# Copy user-specific environment settings
COPY testioc_bashrc /home/testioc/.testioc_bashrc
COPY testioc.acf    /home/testioc/testioc.acf
# One process variable of the laboratory's own, loaded beside the pvxs test databases.
COPY testioc-lab.db /home/testioc/testioc-lab.db

RUN chown testioc:testioc /home/testioc/.testioc_bashrc && \
    chmod 644             /home/testioc/.testioc_bashrc && \
    chown testioc:testioc /home/testioc/testioc.acf     && \
    chmod 644             /home/testioc/testioc.acf     && \
    chown testioc:testioc /home/testioc/testioc-lab.db  && \
    chmod 644             /home/testioc/testioc-lab.db

RUN echo "source ~/.testioc_bashrc" >> /home/testioc/.bashrc

# Copy the testioc Supervisor config
COPY testioc-supervisor.conf /etc/supervisor/conf.d/testioc.conf

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/supervisord.conf"]
