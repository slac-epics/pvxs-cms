TOP = ..

include $(TOP)/configure/CONFIG
-include $(wildcard $(TOP)/cfg/CONFIG*)

#+#+#+#+######################################
# src/Makefile
#
# This directory is responsible for building the pvacms *host executable*.
#
# Nested organization (pvacms path only):
#   TOP/Makefile
#     -> builds TOP/src/ (this file)
#     -> builds TOP/certs/ (authn code + related pieces)
#
#   TOP/src/Makefile
#     -> sets up shared include paths / flags needed by pvacms and its shared
#        sources (which live in multiple directories)
#     -> includes TOP/src/pvacms/Makefile (a Makefile *fragment*) which defines
#        the pvacms target: sources + link libraries
#
#   TOP/src/pvacms/Makefile
#     -> Makefile fragment ONLY (no CONFIG/RULES includes)
#     -> owns the pvacms target definition
#
# Note: pvacms pulls in sources from:
#   - TOP/src/common/  (shared cert/CMS implementation)
#   - TOP/certs/       (configcerts.cpp)
#   - TOP/certs/authn/ (authn plugin framework used by pvacms)
#
#----------------------------------------
#  ADD MACRO DEFINITIONS AFTER THIS LINE
#=============================

COMMON_DIR     = $(TOP)/src/common
CERTS_DIR      = $(TOP)/certs
AUTHN_DIR      = $(CERTS_DIR)/authn
AUTHN_STD_DIR  = $(AUTHN_DIR)/std
CLI11_BUNDLE   = $(TOP)/bundle/CLI11

PVACMS_DIR     = $(TOP)/src/pvacms

USR_CPPFLAGS += -I$(COMMON_DIR)
USR_CPPFLAGS += -I$(CERTS_DIR)
USR_CPPFLAGS += -I$(CLI11_BUNDLE)/include

# Source search path for pvacms and its shared sources
SRC_DIRS += $(COMMON_DIR)
SRC_DIRS += $(CERTS_DIR)

USR_CPPFLAGS += -DPVXS_ENABLE_PVACMS
USR_CPPFLAGS += -DPVXS_ENABLE_EXPERT_API

# OpenSSL is required for pvacms.
# (EVENT2_HAS_OPENSSL comes from the toolchain probe in configure/)
USR_CPPFLAGS += -DPVXS_ENABLE_OPENSSL

# SSL key log file support (debugging aid)
PVXS_ENABLE_SSLKEYLOGFILE ?= YES
PVXS_ENABLE_SSLKEYLOGFILE_YES = -DPVXS_ENABLE_SSLKEYLOGFILE
USR_CPPFLAGS += $(PVXS_ENABLE_SSLKEYLOGFILE_$(PVXS_ENABLE_SSLKEYLOGFILE))

ifdef T_A
ifneq ($(CONFIG_LOADED),YES)
$(warning Toolchain inspection failed $(MAKEFILE_LIST))
endif
endif

ifdef BASE_3_15
ifeq ($(GNUISH),YES)
USR_CFLAGS += -fvisibility=hidden
USR_CXXFLAGS += -fvisibility=hidden -fvisibility-inlines-hidden
endif
endif

# Include pvacms target definition (Makefile fragment)
include $(PVACMS_DIR)/Makefile
#===========================

include $(TOP)/configure/RULES
-include $(wildcard $(TOP)/cfg/RULES*)
#----------------------------------------
#  ADD RULES AFTER THIS LINE
