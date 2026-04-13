ARG DOCKER_REGISTRY=ghcr.io
ARG DOCKER_USERNAME=slac-epics
ARG BASE_IMAGE=lab_base
ARG BASE_IMAGE_TAG=latest

FROM maven:3.9-eclipse-temurin-21 AS phoebus-builder
ARG TARGETARCH
COPY phoebus/ /build/
WORKDIR /build
RUN if [ "$TARGETARCH" = "arm64" ]; then \
      sed -i 's|<openjfx.version>21.0.7</openjfx.version>|<openjfx.version>23.0.2</openjfx.version>|' pom.xml; \
    fi && \
    mvn clean verify -f dependencies/pom.xml && mvn clean install -DskipTests

FROM ${DOCKER_REGISTRY}/${DOCKER_USERNAME}/${BASE_IMAGE}:${BASE_IMAGE_TAG}

ENV PROJECT_HOME=/opt/epics
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y \
            openjdk-21-jdk \
            libgtk-3-0 \
            libgl1 \
            libgl1-mesa-dri && \
    rm -rf /var/lib/apt/lists/*

COPY --from=phoebus-builder /build/phoebus-product/target/product-*.jar /opt/phoebus/
COPY --from=phoebus-builder /build/phoebus-product/target/lib/ /opt/phoebus/lib/

COPY pvxs-cms/example/kubernetes/docker/cs-studio/pvxs-lab-dashboard.bob /opt/phoebus/displays/pvxs-lab-dashboard.bob
COPY pvxs-cms/example/kubernetes/docker/cs-studio/phoebus-settings.ini /opt/phoebus/phoebus-settings.ini
COPY pvxs-cms/example/kubernetes/docker/cs-studio/cs-studio.sh /usr/local/bin/cs-studio
RUN chmod +x /usr/local/bin/cs-studio

RUN useradd -m -s /bin/bash operator -g operator && echo "operator:secret" | chpasswd
RUN useradd -m -s /bin/bash guest             && echo "guest:secret"    | chpasswd
RUN useradd -m -s /bin/bash mloperator        && echo "mloperator:secret" | chpasswd
RUN useradd -m -s /bin/bash mlsystem          && echo "mlsystem:secret"   | chpasswd

COPY pvxs-cms/example/kubernetes/docker/cs-studio/operator_bashrc            /home/operator/.operator_bashrc
COPY pvxs-cms/example/kubernetes/docker/cs-studio/guest_bashrc               /home/guest/.guest_bashrc
COPY pvxs-cms/example/kubernetes/docker/cs-studio/mloperator_bashrc          /home/mloperator/.mloperator_bashrc
COPY pvxs-cms/example/kubernetes/docker/cs-studio/mlsystem_bashrc            /home/mlsystem/.mlsystem_bashrc
COPY pvxs-cms/example/kubernetes/docker/cs-studio/internet_operator_bashrc   /home/operator/.internet_operator_bashrc
COPY pvxs-cms/example/kubernetes/docker/cs-studio/internet_guest_bashrc      /home/guest/.internet_guest_bashrc

RUN chown operator:operator     /home/operator/.operator_bashrc && \
    chown operator:operator     /home/operator/.internet_operator_bashrc && \
    chown guest:guest           /home/guest/.guest_bashrc && \
    chown guest:guest           /home/guest/.internet_guest_bashrc && \
    chown mloperator:mloperator /home/mloperator/.mloperator_bashrc && \
    chown mlsystem:mlsystem     /home/mlsystem/.mlsystem_bashrc

RUN echo "source ~/.operator_bashrc" >> /home/operator/.bashrc
RUN echo "source ~/.guest_bashrc"    >> /home/guest/.bashrc
RUN echo "source ~/.mloperator_bashrc" >> /home/mloperator/.bashrc
RUN echo "source ~/.mlsystem_bashrc"   >> /home/mlsystem/.bashrc

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/supervisord.conf"]
