TOP=..

include $(TOP)/configure/CONFIG
# cfg/ sometimes isn't correctly included due to a Base bug
# so we do here (maybe again) as workaround
-include $(wildcard $(TOP)/cfg/CONFIG*)
#----------------------------------------
#  ADD MACRO DEFINITIONS AFTER THIS LINE
#=============================

ifeq ($(EVENT2_HAS_OPENSSL),YES)
USR_CPPFLAGS += -DPVXS_ENABLE_OPENSSL -I$(TOP)/bundle/CLI11/include

ifeq (WIN32,$(OS_CLASS))
# certs/ builds some PVXS implementation sources directly.
# Avoid PVXS_API resolving to dllimport for these definitions.
USR_CPPFLAGS += -DPVXS_API_BUILDING
endif

# No longer building pvxs library - include sources from pvxs repo instead

AUTHN = $(TOP)/certs/authn
# Include source files from pvxs repo
SRC_DIRS += $(TOP)/src/common
SRC_DIRS += $(TOP)/ioc

PROD_LIBS = pvxs Com

# Include paths for headers (pvxs repo headers + local headers)
USR_CPPFLAGS += -I$(TOP)/src
USR_CPPFLAGS += -I$(TOP)/ioc
USR_CPPFLAGS += -I$(TOP)/certs/authn/std

 include $(AUTHN)/Makefile

 endif # EVENT2_HAS_OPENSSL

#===========================

include $(TOP)/configure/RULES
-include $(wildcard $(TOP)/cfg/RULES*)
#----------------------------------------
#  ADD RULES AFTER THIS LINE
