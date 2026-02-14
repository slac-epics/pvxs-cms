########################################################################
# src/pvacms/Makefile
#
# Makefile fragment included by TOP/src/Makefile.
#
# IMPORTANT:
#   - Do NOT include configure/CONFIG or configure/RULES here.
#   - This file defines the pvacms host executable target only.
#   - Shared include paths / feature flags belong in TOP/src/Makefile.
#
# Organization (pvacms path only):
#   TOP/Makefile        : builds TOP/src and TOP/certs
#   TOP/src/Makefile    : common build setup + includes this fragment
#   TOP/src/pvacms/*    : pvacms entrypoints/config sources
#   TOP/src/common/*    : shared CMS/cert implementation sources
#   TOP/src/authn/*     : shared config/authn sources (re-used by pvacms)
########################################################################

# Allow sources in these directories to be found by basename
SRC_DIRS += $(PVACMS_DIR)
SRC_DIRS += $(COMMON_DIR)/serverev
USR_CPPFLAGS += -I$(COMMON_DIR)/serverev

# Build pvacms host executable
PROD += pvacms

### Sources

# Entry points and pvacms-specific config
pvacms_SRCS += pvacms.cpp
pvacms_SRCS += configcms.cpp

# Shared CMS/cert implementation sources (from src/common/ and certs/)
pvacms_SRCS += certstatus.cpp
pvacms_SRCS += certstatusfactory.cpp
pvacms_SRCS += p12filefactory.cpp
pvacms_SRCS += certfilefactory.cpp
pvacms_SRCS += certfactory.cpp
pvacms_SRCS += configcerts.cpp
pvacms_SRCS += wildcardpv.cpp
pvacms_SRCS += evhelper.cpp
pvacms_SRCS += openssl.cpp
pvacms_SRCS += serverev.cpp
pvacms_SRCS += securityclient.cpp
pvacms_SRCS += util.cpp

# Authentication plugin framework (from src/authn/)
pvacms_SRCS += auth.cpp
pvacms_SRCS += configauthn.cpp
pvacms_SRCS += ccrmanager.cpp
pvacms_SRCS += certstatusmanager.cpp

### Link dependencies

pvacms_LIBS += pvxs $(EPICS_BASE_IOC_LIBS)
pvacms_SYS_LIBS += sqlite3
