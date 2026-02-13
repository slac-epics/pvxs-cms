TOP = ..

include $(TOP)/configure/CONFIG
-include $(wildcard $(TOP)/cfg/CONFIG*)

#+#+#+#+#+######################################
# src/Makefile
#
# This directory builds host-side executables:
#   - pvacms (CMS server)
#   - tools (eg. pvxcert)
#   - authenticators (e.g. authnstd)
#
# Nested organization (src path only):
#   TOP/Makefile
#     -> builds TOP/src/   (this file)
#
#   TOP/src/Makefile
#     -> sets up shared include paths / feature flags used by pvacms, authenticators and tools
#     -> includes Makefile fragments which define concrete targets
#
#   TOP/src/pvacms/Makefile
#     -> Makefile fragment (inherits vars/flags from TOP/src/Makefile)
#     -> defines PROD += pvacms and pvacms_* settings
#
#   TOP/src/authn/Makefile
#     -> Makefile fragment (inherits vars/flags from TOP/src/Makefile)
#     -> aggregates tool fragments under TOP/src/authn/<authenticator>/Makefile
#     -> plugin architecture adds sources to pvacms_SRCS, and pvacms_LIBS,
#        to implement the selected authenticator's verify methods inside pvacms
#
#   TOP/src/tools/Makefile
#     -> Makefile fragment (inherits vars/flags from TOP/src/Makefile)
#     -> aggregates tool fragments under TOP/src/tools/<tool>/Makefile
#
# Note: pvacms/tools pull shared implementation sources from TOP/src/common/
# and some config/authn sources from TOP/certs/.
#
#----------------------------------------
#  ADD MACRO DEFINITIONS AFTER THIS LINE
#=============================

COMMON_DIR     = $(TOP)/src/common
AUTHN_DIR      = $(TOP)/src/authn
AUTHN_STD_DIR  = $(AUTHN_DIR)/std
CLI11_BUNDLE   = $(TOP)/bundle/CLI11

PVACMS_DIR     = $(TOP)/src/pvacms
TOOLS_DIR      = $(TOP)/src/tools

# Backwards-compat for existing authn Makefile fragments
AUTHN = $(AUTHN_DIR)

USR_CPPFLAGS += -I$(COMMON_DIR)
USR_CPPFLAGS += -I$(AUTHN_DIR)
USR_CPPFLAGS += -I$(AUTHN_STD_DIR)
USR_CPPFLAGS += -I$(CLI11_BUNDLE)/include

# Source search path for pvacms and its shared sources
SRC_DIRS += $(COMMON_DIR)
SRC_DIRS += $(AUTHN_DIR)

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

# Authenticators (Makefile fragment)
include $(AUTHN_DIR)/Makefile

# Host tools (Makefile fragments)
include $(TOOLS_DIR)/Makefile
#===========================

include $(TOP)/configure/RULES
-include $(wildcard $(TOP)/cfg/RULES*)
#----------------------------------------
#  ADD RULES AFTER THIS LINE
