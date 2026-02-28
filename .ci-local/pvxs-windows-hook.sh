#!/bin/sh
# Hook for cue.py to configure pvxs-tls for Windows MSVC builds.
# Runs in the pvxs-tls source directory before compilation.
#
# 1. Adds /std:c++20 (needed for designated initializers in securitylogger.h)
# 2. Sets OPENSSL include/lib paths via CONFIG_SITE so probe-openssl.c can find headers

set -e

CONFIG_SITE="configure/CONFIG_SITE"

if [ -f "$CONFIG_SITE" ]; then
    echo "pvxs-windows-hook: Configuring pvxs-tls for Windows MSVC in $(pwd)"

    # Add /std:c++20 for MSVC (designated initializers require it)
    echo 'USR_CXXFLAGS_WIN32 += /std:c++20' >> "$CONFIG_SITE"

    # Point to OpenSSL if OPENSSL env var is set
    if [ -n "$OPENSSL" ]; then
        echo "OPENSSL = $OPENSSL" >> "$CONFIG_SITE"
        echo "pvxs-windows-hook: Set OPENSSL=$OPENSSL"
    fi
else
    echo "Warning: $CONFIG_SITE not found in $(pwd)"
fi
