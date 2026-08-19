#!/bin/bash
# run-ci.sh - Run the CI build inside a container (or locally).
#
# This script reproduces the "Native Linux" CI matrix entry.
# It is designed to be run inside a Docker container via run-ci-docker.sh,
# but can also be run directly on a Linux host.
#
# Usage:
#   .ci-local/run-ci.sh              # run directly (builds in current tree)
#   .ci-local/run-ci-docker.sh       # run in Docker (isolated, recommended)
set -e

LOGFILE="$(pwd)/ci-build.log"
exec > >(tee -a "$LOGFILE") 2>&1

echo "========================================"
echo "Starting CI Build at $(date)"
echo "========================================"

# Use GITHUB_WORKSPACE if set (real CI), else current directory
export GITHUB_WORKSPACE="${GITHUB_WORKSPACE:-$(pwd)}"
export CACHEDIR="${CACHEDIR:-$GITHUB_WORKSPACE/.cache}"

export EPICS_PVA_ADDR_LIST="127.0.0.1"
export EPICS_PVA_AUTO_ADDR_LIST="NO"
export EPICS_PVAS_ADDR_LIST="127.0.0.1"
export EPICS_PVAS_AUTO_ADDR_LIST="NO"

export SETUP_PATH=".ci-local:.ci"
export SET="${SET:-defaults}"
export CMP="${CMP:-gcc}"
export BCFG="${BCFG:-default}"
export BASE="${BASE:-7.0-secure-pvaccess}"
export EXTRA="${EXTRA:-PVXS_ENABLE_PVACMS=YES PVXS_ENABLE_KRB_AUTH=YES PVXS_ENABLE_LDAP_AUTH=YES}"
export VV="${VV:-1}"
export GITHUB_ACTIONS="true"
export RUNNER_OS="${RUNNER_OS:-Linux}"
export CI="true"
export _PVXS_ABORT_ON_CRIT="1"
export PVXS_LOG="pvxs.*=WARN"
export OPENSSL_VERSION="3.1.4"
export TEST="${TEST:-1}"

echo ""
echo "=== Prepare and compile dependencies ==="
python3 .ci/cue.py prepare

echo ""
echo "=== Build libevent ==="
python3 .ci/cue.py exec python3 .ci-local/libevent.py

echo ""
echo "=== Build pvxs-tls tools ==="
python3 .ci/cue.py exec make -C "$CACHEDIR/pvxs-fy26-integration-testing"

echo ""
echo "=== Build main module ==="
python3 .ci/cue.py build

echo ""
echo "=== Host info ==="
python3 .ci/cue.py --add-path "$CACHEDIR/pvxs-fy26-integration-testing/bin/{EPICS_HOST_ARCH}" --add-path "{TOP}/bundle/usr/{EPICS_HOST_ARCH}/lib" exec pvxinfo -D || true

echo ""
echo "=== Run main module tests ==="
python3 .ci/cue.py -T 5M --add-path "${CACHEDIR}/pvxs-fy26-integration-testing/bundle/usr/{EPICS_HOST_ARCH}/lib" test || true

echo ""
echo "=== Collect and show test results ==="
python3 .ci/cue.py test-results || true

echo ""
echo "========================================"
echo "CI Build completed at $(date)"
echo "Log saved to: $LOGFILE"
echo "========================================"
