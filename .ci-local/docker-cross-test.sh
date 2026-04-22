#!/bin/bash
# Simulate cross-build CI locally in Docker.
# Usage: .ci-local/docker-cross-test.sh [mingw|rtems]
#
# Mirrors the cross job from ci-scripts-build.yml but runs in an Ubuntu container.
# Source tree is bind-mounted read-only; all build artifacts go to /build inside the container.

set -e

TARGET="${1:-mingw}"
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"

case "$TARGET" in
  mingw)
    CI_CROSS_TARGETS="windows-x64-mingw"
    EXTRA="PVXS_ENABLE_PVACMS=NO PVXS_ENABLE_KRB_AUTH=YES PVXS_ENABLE_LDAP_AUTH=NO"
    ;;
  rtems)
    CI_CROSS_TARGETS="RTEMS-pc686-qemu@5"
    EXTRA="PVXS_ENABLE_PVACMS=NO PVXS_ENABLE_KRB_AUTH=NO PVXS_ENABLE_LDAP_AUTH=NO"
    ;;
  *)
    echo "Usage: $0 [mingw|rtems]"
    exit 1
    ;;
esac

CONTAINER_NAME="pvxs-cross-${TARGET}-$$"

echo "=== Building cross target: $TARGET ($CI_CROSS_TARGETS) ==="
echo "=== Container: $CONTAINER_NAME ==="
echo "=== Source: $REPO_DIR ==="

docker run --rm \
  --name "$CONTAINER_NAME" \
  -v "${REPO_DIR}:/src:ro" \
  -e SETUP_PATH=".ci-local:.ci" \
  -e SET="cross" \
  -e CMP="gcc" \
  -e BCFG="default" \
  -e BASE="7.0-secure-pvaccess" \
  -e CI_CROSS_TARGETS="$CI_CROSS_TARGETS" \
  -e TEST="" \
  -e EXTRA="$EXTRA" \
  -e VV="1" \
  -e MODULES="" \
  -e OPENSSL_VERSION="3.1.4" \
  -e GITHUB_ACTIONS="true" \
  -e RUNNER_OS="Linux" \
  ubuntu:22.04 bash -c '
set -ex

export CACHEDIR=/build/.cache
export HOME=/root
mkdir -p /build "$CACHEDIR"

# Copy source (read-only mount) to writable location
cp -a /src /build/pvxs-cms
cd /build/pvxs-cms

# Install packages (mirrors CI apt-get step)
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get -y install sudo \
  python3 python-is-python3 git make perl \
  gcc g++ \
  libreadline-dev \
  g++-mingw-w64-x86-64 \
  cmake gdb \
  qemu-system-x86 \
  libssl-dev \
  libsqlite3-dev \
  mingw-w64-x86-64-dev \
  libevent-dev \
  libkrb5-dev \
  libldap2-dev \
  wget

# Install OpenSSL for MinGW (if mingw target)
if echo "$CI_CROSS_TARGETS" | grep -q mingw; then
  echo "=== Building OpenSSL for MinGW ==="
  cd /build
  wget -q https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz
  tar xzf openssl-${OPENSSL_VERSION}.tar.gz
  cd openssl-${OPENSSL_VERSION}
  ./Configure mingw64 --cross-compile-prefix=x86_64-w64-mingw32- --prefix=/usr/x86_64-w64-mingw32
  make -j$(nproc)
  make install
  SYSROOT=/usr/x86_64-w64-mingw32
  for lib in ssl crypto; do
    for kind in dll.a a; do
      tgt="$SYSROOT/lib/lib${lib}.${kind}"
      if [ ! -e "$tgt" ]; then
        cand=$(ls -1 "$SYSROOT"/lib/lib${lib}*.${kind} "$SYSROOT"/lib64/lib${lib}*.${kind} 2>/dev/null | head -n1 || true)
        if [ -n "$cand" ]; then
          ln -sf "$cand" "$tgt"
        fi
      fi
    done
  done
  cd /build
  rm -rf openssl-${OPENSSL_VERSION}*
fi

cd /build/pvxs-cms

echo "=== openssl version ==="
openssl version -a || true

echo "=== Step 1: Prepare and compile EPICS Base ==="
python .ci/cue.py prepare

echo "=== Step 2: Clone pvxs dependency ==="
PVXS_DIR=${CACHEDIR}/pvxs-tls
if [ ! -d "$PVXS_DIR" ]; then
  git clone --depth 5 --recursive --branch dev https://github.com/slac-epics/pvxs-tls.git "$PVXS_DIR"
fi
echo "-include \$(TOP)/../RELEASE.local" > "$PVXS_DIR/configure/RELEASE"

echo "=== Step 3: Build libevent for pvxs (host + cross targets) ==="
python .ci/cue.py exec python .ci-local/pvxs-libevent-hook.py ${CACHEDIR}/pvxs-tls

echo "=== Step 4: Build pvxs dependency ==="
RELEASE_LOCAL=${CACHEDIR}/RELEASE.local
if ! grep -q "^PVXS=" "$RELEASE_LOCAL" 2>/dev/null; then
  sed -i "/^EPICS_BASE=/i PVXS=$PVXS_DIR" "$RELEASE_LOCAL"
fi
cp "$RELEASE_LOCAL" configure/RELEASE.local
make -C "$PVXS_DIR" -j$(nproc)

echo "=== Step 5: Build main module ==="
python .ci/cue.py build

echo "=== SUCCESS ==="
'
