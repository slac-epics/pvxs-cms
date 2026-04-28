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

include $(TOP)/configure/CONFIG_PVACMS_VERSION

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
USR_CPPFLAGS += -I$(PVACMS_DIR)

# Source search path for pvacms and its shared sources
SRC_DIRS += $(COMMON_DIR)
SRC_DIRS += $(AUTHN_DIR)
SRC_DIRS += $(PVACMS_DIR)

# PVXS_ENABLE_PVACMS: gate CMS-server build + sqlite3 dependency.
# Default is set in $(TOP)/configure/CONFIG_SITE so test/Makefile sees the
# same value (CI invokes `make tapfiles` without re-passing build-time flags).
# Override in EXTRA, CONFIG_SITE.local, or via the command line.
PVXS_ENABLE_PVACMS_YES = -DPVXS_ENABLE_PVACMS
USR_CPPFLAGS += $(PVXS_ENABLE_PVACMS_$(PVXS_ENABLE_PVACMS))
USR_CPPFLAGS += -DPVXS_ENABLE_EXPERT_API

# PVXS_CMS_BUILD_TEST_HARNESS: gate libpvxsCmsTestHarness.a build, subordinate to
# PVXS_ENABLE_PVACMS. When PVXS_ENABLE_PVACMS=NO the harness depends on CMS types
# that aren't compiled, so we forcibly disable it (with := not ?=) and emit a
# one-line notice only when the user explicitly asked for =YES.
ifeq ($(PVXS_ENABLE_PVACMS),YES)
PVXS_CMS_BUILD_TEST_HARNESS ?= YES
else
ifeq ($(PVXS_CMS_BUILD_TEST_HARNESS),YES)
$(info note: PVXS_CMS_BUILD_TEST_HARNESS forced to NO because PVXS_ENABLE_PVACMS=NO)
endif
override PVXS_CMS_BUILD_TEST_HARNESS := NO
endif
PVXS_CMS_BUILD_TEST_HARNESS_YES = -DPVXS_CMS_BUILD_TEST_HARNESS
USR_CPPFLAGS += $(PVXS_CMS_BUILD_TEST_HARNESS_$(PVXS_CMS_BUILD_TEST_HARNESS))

CMS_TEST_DIR   = $(TOP)/src/cms/test

INC += cms/pvacms.h

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

# Include pvacms + authenticator targets only when CMS is enabled
ifeq ($(PVXS_ENABLE_PVACMS),YES)
include $(PVACMS_DIR)/Makefile

# Authenticators (Makefile fragment)
include $(AUTHN_DIR)/Makefile
endif

# CMS test harness static library (subordinate to PVXS_ENABLE_PVACMS, gated above)
ifeq ($(PVXS_CMS_BUILD_TEST_HARNESS),YES)
include $(CMS_TEST_DIR)/Makefile
endif

# Host tools (Makefile fragments)
include $(TOOLS_DIR)/Makefile
#===========================

include $(TOP)/configure/RULES
-include $(wildcard $(TOP)/cfg/RULES*)
#----------------------------------------
#  ADD RULES AFTER THIS LINE
