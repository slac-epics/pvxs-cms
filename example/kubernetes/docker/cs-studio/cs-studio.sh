#!/bin/bash
set -e

export DISPLAY=${DISPLAY:-:99}

exec java \
    --enable-native-access=ALL-UNNAMED \
    -Dprism.order=sw \
    -Dprism.forceGPU=false \
    -Dfile.encoding=UTF-8 \
    -jar /opt/phoebus/product-*.jar \
    -settings /opt/phoebus/phoebus-settings.ini \
    -resource /opt/phoebus/displays/pvxs-lab-dashboard.bob \
    "$@"
