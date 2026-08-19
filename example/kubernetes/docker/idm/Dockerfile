ARG DOCKER_REGISTRY=ghcr.io
ARG DOCKER_USERNAME=slac-epics
ARG BASE_IMAGE=lab_base
ARG BASE_IMAGE_TAG=latest

FROM ${DOCKER_REGISTRY}/${DOCKER_USERNAME}/${BASE_IMAGE}:${BASE_IMAGE_TAG}

# Set environment variables
ENV PROJECT_HOME=/opt/epics
ENV DEBIAN_FRONTEND=noninteractive

# Create users with pre-set password ("secret")
RUN useradd -m -s /bin/bash idm   && echo "idm:secret"      | chpasswd
RUN useradd -m -s /bin/bash admin && echo "admin:secret"    | chpasswd

# Copy user-specific environment settings
COPY idm_bashrc    /home/idm/.idm_bashrc
COPY admin_bashrc  /home/admin/.admin_bashrc

RUN chown idm:idm       /home/idm/.idm_bashrc && \
    chown admin:admin   /home/admin/.admin_bashrc  && \
    chmod 644           /home/idm/.idm_bashrc && \
    chmod 644           /home/admin/.admin_bashrc

RUN echo "source ~/.idm_bashrc"   >> /home/idm/.bashrc
RUN echo "source ~/.admin_bashrc" >> /home/admin/.bashrc

# Setup pvacms service
COPY pvacms-supervisor.conf /etc/supervisor/conf.d/pvacms.conf

# Add kerberos dependencies
RUN apt-get update && \
    apt-get -y install \
            --no-install-recommends \
            krb5-admin-server \
            krb5-kdc \
            libkrb5-dev

RUN mkdir -p /var/lib/krb5kdc

COPY kadm5.acl kdc.conf badpass.txt /etc/krb5kdc/

# Copy the krb5 Supervisor configs
COPY krb5-admin-server-supervisor.conf /etc/supervisor/conf.d/kadmind.conf
COPY krb5-kdc-supervisor.conf          /etc/supervisor/conf.d/krb5kdc.conf

RUN mkdir -p /home/idm/.config/krb5/

# The key distribution centre and its administration server were started here, before the
# database they read exists, so both reported that they could not open it and the build carried
# on regardless. Nothing was lost by that: each instruction runs in its own container, so a
# process started by one is gone by the next, and the database is created and filled below with
# kadmin.local, which works on the file directly and needs neither of them running. All the two
# lines did was print two failures in the middle of a build that is otherwise quiet, which reads
# like the build breaking.

# Create the principals
# - note clear passwords for testing purposes only
RUN kdb5_util create -s -P secret \
 && kadmin.local -q 'addprinc -pw secret -allow_svr admin' \
 && kadmin.local -q 'addprinc -randkey pvacms/cluster@EPICS.ORG' \
 && kadmin.local -q 'addprinc -pw secret -allow_svr testioc' \
 && kadmin.local -q 'addprinc -pw secret -allow_svr tstioc' \
 && kadmin.local -q 'addprinc -pw secret remote' \
 && kadmin.local -q 'addprinc -pw secret operator' \
 && kadmin.local -q 'addprinc -pw secret guest' \
 && kadmin.local -q 'addprinc -pw secret mloperator@EPICS.ORG' \
 && kadmin.local -q 'addprinc -pw secret mlsystem@EPICS.ORG'

# Create service keytabs
RUN kadmin.local -q 'ktadd -k /home/idm/.config/krb5/pvacms.keytab pvacms/cluster@EPICS.ORG' \
 && chown idm:idm             /home/idm/.config/krb5/pvacms.keytab \
 && chmod 600                 /home/idm/.config/krb5/pvacms.keytab

# Set up CONFIG_SITE.local
WORKDIR ${PROJECT_HOME}
RUN echo "EVENT2_HAS_OPENSSL = YES" >> CONFIG_SITE.local
RUN echo "PVXS_ENABLE_PVACMS = YES" >> CONFIG_SITE.local
RUN echo "PVXS_ENABLE_KRB_AUTH = YES" >> CONFIG_SITE.local

# How many compiler processes to run at once. Each can take most of a gigabyte,
# so a machine with little memory and no swap needs this lowered.
ARG JOBS
# Rebuild PVXS with kerberos support
RUN cd pvxs-cms && \
    make -j${JOBS:-$(nproc)} all

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/supervisord.conf"]
