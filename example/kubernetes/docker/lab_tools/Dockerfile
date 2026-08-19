# Tools-only base for the laboratory images. Deliberately built FROM ubuntu
# rather than from the pvxs-cms chain: this layer holds every apt package the
# laboratory needs (build toolchain, Kerberos, display stack, diagnostics),
# and because no source code is underneath it, source changes never
# invalidate it - the slow package download runs only when this file changes.
# lab_base then combines this image with the built EPICS tree via
# COPY --from the pvxs-cms image.
FROM ubuntu:latest

ENV PROJECT_HOME=/opt/epics
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y \
            # Build toolchain (epics-base / pvxs / pvxs-cms in-image rebuilds)
            build-essential \
            git \
            pkg-config \
            openssl \
            libssl-dev \
            libevent-dev \
            libsqlite3-dev \
            libcurl4-openssl-dev \
            # Laboratory pod basics
            adduser \
            sudo \
            supervisor \
            libkrb5-dev \
            krb5-user \
            libgssapi-krb5-2 \
            vim nano \
            # Display stack (Xvfb + VNC + noVNC)
            xvfb \
            x11vnc \
            fluxbox \
            novnc \
            python3-websockify \
            # Network diagnostic tools
            dnsutils \
            netcat-openbsd \
            telnet \
            curl \
            tcpdump \
            iproute2 \
            traceroute \
            iputils-ping \
            net-tools \
            less \
            jq \
            file \
            strace \
            procps && \
    mkdir -p ${PROJECT_HOME}
