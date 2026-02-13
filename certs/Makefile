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
SRC_DIRS += $(TOP)/src
SRC_DIRS += $(TOP)/ioc
SRC_DIRS += /Users/george/Projects/com/slac/pvxs/src
SRC_DIRS += /Users/george/Projects/com/slac/pvxs/ioc

PROD_LIBS = pvxs Com

# Include paths for headers (pvxs repo headers + local headers)
USR_CPPFLAGS += -I$(TOP)/src
USR_CPPFLAGS += -I$(TOP)/ioc
USR_CPPFLAGS += -I$(TOP)/certs/authn/std
USR_CPPFLAGS += -I/Users/george/Projects/com/slac/pvxs/include
USR_CPPFLAGS += -I/Users/george/Projects/com/slac/pvxs/ioc
USR_CPPFLAGS += -I/Users/george/Projects/com/slac/pvxs/src/O.Common

 ifeq ($(PVXS_ENABLE_PVACMS),YES)
 USR_CPPFLAGS += -DPVXS_ENABLE_PVACMS
 USR_CPPFLAGS += -DPVXS_ENABLE_EXPERT_API
 PROD += pvacms
 pvacms_SRCS += pvacms.cpp
 pvacms_SRCS += certstatus.cpp
 pvacms_SRCS += certstatusfactory.cpp
  pvacms_SRCS += configcms.cpp
  pvacms_SRCS += configcerts.cpp
 # credentials.cpp and securityclient.cpp removed - were pvxs library code
 # pvacms_SRCS += credentials.cpp
 # pvacms_SRCS += securityclient.cpp

  # Include source files from src/ for server functionality
  # Note: Some pvxs sources needed for linking (evhelper needs util for Timer)
  pvacms_SRCS += wildcardpv.cpp
  pvacms_SRCS += conn.cpp
  pvacms_SRCS += evhelper.cpp
  pvacms_SRCS += openssl.cpp
  pvacms_SRCS += serverev.cpp
  pvacms_SRCS += util.cpp
  # util.cpp excluded - already compiled into pvxsIoc library (requires pvxsVCS.h generated header)

  # Include source files for IdFileFactory
  pvacms_SRCS += p12filefactory.cpp
  pvacms_SRCS += certfilefactory.cpp
  pvacms_SRCS += certfactory.cpp
  # certstatusmanager.cpp already included via authn/Makefile

 # Link against pvxs libraries for server, certs, and ioc components
 pvacms_LIBS += pvxs pvxsIoc $(EPICS_BASE_IOC_LIBS)
 pvacms_SYS_LIBS += sqlite3 ssl crypto
 endif

#PROD += ocsppva
#pvaocsp_SRCS += ocsppva.cpp
#pvaocsp_SRCS += configocsp.cpp

include $(AUTHN)/Makefile

endif # EVENT2_HAS_OPENSSL

#===========================

include $(TOP)/configure/RULES
-include $(wildcard $(TOP)/cfg/RULES*)
#----------------------------------------
#  ADD RULES AFTER THIS LINE
