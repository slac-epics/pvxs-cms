ARG DOCKER_REGISTRY=ghcr.io
ARG DOCKER_USERNAME=slac-epics
ARG BASE_IMAGE=lab_tools
ARG BASE_IMAGE_TAG=latest
ARG SOURCE_IMAGE=pvxs-cms
ARG SOURCE_IMAGE_TAG=latest

# The built EPICS tree comes from the pvxs-cms image; the packages come from
# lab_tools. Split so that a source change re-runs only the copy and the make
# below, never the package download in lab_tools.
FROM ${DOCKER_REGISTRY}/${DOCKER_USERNAME}/${SOURCE_IMAGE}:${SOURCE_IMAGE_TAG} AS source

FROM ${DOCKER_REGISTRY}/${DOCKER_USERNAME}/${BASE_IMAGE}:${BASE_IMAGE_TAG}

# Set environment variables
ENV PROJECT_HOME=/opt/epics
ENV DEBIAN_FRONTEND=noninteractive

# epics-base, pvxs and pvxs-cms, already built, plus RELEASE.local and
# CONFIG_SITE.local - everything the source image keeps under /opt/epics.
COPY --from=source ${PROJECT_HOME} ${PROJECT_HOME}

RUN echo "PVXS = \$(TOP)/../pvxs" >> ${PROJECT_HOME}/RELEASE.local
RUN echo "PVXS_ENABLE_KRB_AUTH = YES" >> ${PROJECT_HOME}/CONFIG_SITE.local
# How many compiler processes to run at once. Each can take most of a gigabyte,
# so a machine with little memory and no swap needs this lowered.
ARG JOBS
RUN cd ${PROJECT_HOME}/pvxs-cms && make -j${JOBS:-$(nproc)} all

# Copy user kerberos configuration
COPY krb5.conf /etc/krb5.conf

# Copy the top-level Supervisor config
COPY supervisord.conf /etc/supervisor/supervisord.conf
COPY display-supervisor.conf /etc/supervisor/conf.d/display.conf

EXPOSE 8080 5900

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/supervisord.conf"]
