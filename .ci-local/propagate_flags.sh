#!/bin/sh
# Hook for cue.py to propagate CMD_* flags into EPICS_BASE/configure/CONFIG_SITE

set -e

CONFIG_SITE="configure/CONFIG_SITE"

if [ -f "$CONFIG_SITE" ]; then
    echo "Adding CMD_* flags to $CONFIG_SITE in $(pwd)"

    if [ -n "$CMD_CPPFLAGS" ]; then
        echo "USR_CPPFLAGS += $CMD_CPPFLAGS" >> "$CONFIG_SITE"
    fi
    if [ -n "$CMD_CFLAGS" ]; then
        echo "USR_CFLAGS += $CMD_CFLAGS" >> "$CONFIG_SITE"
    fi
    if [ -n "$CMD_CXXFLAGS" ]; then
        echo "USR_CXXFLAGS += $CMD_CXXFLAGS" >> "$CONFIG_SITE"
    fi
else
    echo "Warning: $CONFIG_SITE not found in $(pwd)"
fi
