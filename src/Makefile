TOP=..

include $(TOP)/configure/CONFIG
-include $(wildcard $(TOP)/cfg/CONFIG*)
#----------------------------------------
#  ADD MACRO DEFINITIONS AFTER THIS LINE
#=============================
ifeq ($(EVENT2_HAS_OPENSSL),YES)
USR_CPPFLAGS += -DPVXS_ENABLE_OPENSSL
endif # EVENT2_HAS_OPENSSL

USR_CPPFLAGS += -DPVXS_ENABLE_EXPERT_API

# Access to certs specific headers
ifeq ($(EVENT2_HAS_OPENSSL),YES)
USR_CPPFLAGS += -I$(TOP)/certs
SRC_DIRS += $(TOP)/certs
endif # EVENT2_HAS_OPENSSL

# SSL key log file support
ifeq ($(EVENT2_HAS_OPENSSL),YES)
PVXS_ENABLE_SSLKEYLOGFILE ?= YES
PVXS_ENABLE_SSLKEYLOGFILE_YES = -DPVXS_ENABLE_SSLKEYLOGFILE
USR_CPPFLAGS += $(PVXS_ENABLE_SSLKEYLOGFILE_$(PVXS_ENABLE_SSLKEYLOGFILE))
endif # EVENT2_HAS_OPENSSL

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

# SSL and CMS-related sources only (no pvxs endpoint implementations)
LIB_SRCS += bitmask.cpp
LIB_SRCS += certdate.h
LIB_SRCS += certfactory.cpp
LIB_SRCS += certfilefactory.cpp
LIB_SRCS += certstatus.cpp
LIB_SRCS += certstatusmanager.cpp
LIB_SRCS += config.cpp
LIB_SRCS += conn.cpp
LIB_SRCS += data.cpp
LIB_SRCS += dataencode.cpp
LIB_SRCS += datafmt.cpp
LIB_SRCS += dataimpl.h
LIB_SRCS += describe.cpp
LIB_SRCS += describe.h
LIB_SRCS += evhelper.cpp
LIB_SRCS += log.cpp
LIB_SRCS += nt.cpp
LIB_SRCS += openssl.cpp
LIB_SRCS += openssl.h
LIB_SRCS += opensslgbl.cpp
LIB_SRCS += opensslgbl.h
LIB_SRCS += osdSockExt.cpp
LIB_SRCS += osgroups.cpp
LIB_SRCS += ownedptr.h
LIB_SRCS += p12filefactory.cpp
LIB_SRCS += pvaproto.h
LIB_SRCS += pvrequest.cpp
LIB_SRCS += pvrequest.h
LIB_SRCS += security.h
LIB_SRCS += serverev.cpp
LIB_SRCS += serverev.h
LIB_SRCS += serverget.cpp
LIB_SRCS += serversource.cpp
LIB_SRCS += type.cpp
LIB_SRCS += util.cpp
LIB_SRCS += utilpvt.h
LIB_SRCS += wildcardpv.cpp
LIB_SRCS += wildcardpv.h

LIB_LIBS += Com

# special case matching configure/RULES_PVXS_MODULE
ifeq (,$(LIBEVENT_PREFIX))
LIB_SYS_LIBS += $(LIBEVENT_BUNDLE_LIBS)
else
LIB_LIBS += $(LIBEVENT_BUNDLE_LIBS)
endif

LIB_SYS_LIBS += $(LIBEVENT_SYS_LIBS)

#===========================

include $(TOP)/configure/RULES
-include $(wildcard $(TOP)/cfg/RULES*)
#----------------------------------------
#  ADD RULES AFTER THIS LINE

describe$(DEP): describe.h
util$(DEP): util.cpp
