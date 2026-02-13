TOP = ..

include $(TOP)/configure/CONFIG
-include $(wildcard $(TOP)/cfg/CONFIG*)

#----------------------------------------
#  ADD MACRO DEFINITIONS AFTER THIS LINE
#=============================
COMMON = $(TOP)/src/common
COMMON_CERTS = $(TOP)/certs
CLI11_BUNDLE = $(TOP)/bundle/CLI11

PVACMS = $(TOP)/src/pvacms
CMS_TOOLS = $(TOP)/src/tools
AUTHN = $(TOP)/certs/authn
AUTHN_STD = $(TOP)/certs/authn/std

USR_CPPFLAGS += -I$(COMMON)
USR_CPPFLAGS += -I$(COMMON_CERTS)
USR_CPPFLAGS += -I$(CLI11_BUNDLE)/include

# Common sources
SRC_DIRS += $(COMMON)
SRC_DIRS += $(COMMON_CERTS)

# Commong libs
SYS_LIBS += ssl crypto

USR_CPPFLAGS += -DPVXS_ENABLE_PVACMS
USR_CPPFLAGS += -DPVXS_ENABLE_EXPERT_API

# SSL key log file support
ifeq ($(EVENT2_HAS_OPENSSL),YES)
USR_CPPFLAGS += -DPVXS_ENABLE_OPENSSL
PVXS_ENABLE_SSLKEYLOGFILE ?= YES
PVXS_ENABLE_SSLKEYLOGFILE_YES = -DPVXS_ENABLE_SSLKEYLOGFILE
USR_CPPFLAGS += $(PVXS_ENABLE_SSLKEYLOGFILE_$(PVXS_ENABLE_SSLKEYLOGFILE))
endif

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

# Include pvacms subdirectory
include $(PVACMS)/Makefile

#===========================

include $(TOP)/configure/RULES
-include $(wildcard $(TOP)/cfg/RULES*)
#----------------------------------------
#  ADD RULES AFTER THIS LINE
