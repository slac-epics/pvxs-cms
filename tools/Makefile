TOP=..

include $(TOP)/configure/CONFIG
-include $(wildcard $(TOP)/cfg/CONFIG*)
#----------------------------------------
#  ADD MACRO DEFINITIONS AFTER THIS LINE
#=============================

# access to private headers
USR_CPPFLAGS += -I$(TOP)/src

ifeq ($(EVENT2_HAS_OPENSSL),YES)
 SRC_DIRS += $(TOP)/certs
 SRC_DIRS += $(TOP)/src
 USR_CPPFLAGS += -DPVXS_ENABLE_OPENSSL
 USR_CPPFLAGS += -DPVXS_ENABLE_PVACMS
 USR_CPPFLAGS += -I$(TOP)/certs -I$(TOP)/bundle/CLI11/include
 ifeq (WIN32,$(OS_CLASS))
 # Some PVXS sources are compiled into tools (eg. certstatusmanager.cpp).
 # Ensure PVXS_API is not seen as dllimport while defining these symbols.
 USR_CPPFLAGS += -DPVXS_API_BUILDING
 endif
 SRCS += certstatus.cpp

  # Retained tools: pvxcert only (ocsppva requires pvxs client which is being removed)
 PROD += pvxcert
 pvxcert_SRCS += cert.cpp
 pvxcert_SRCS += p12filefactory.cpp
 pvxcert_SRCS += certfilefactory.cpp
 pvxcert_SRCS += certfactory.cpp
 pvxcert_SRCS += certstatusmanager.cpp

 # ocsppva removed - depends on pvxs client headers which are being removed
 # PROD += ocsppva
 # ocsppva_SRCS += ocsppva.cpp

endif # EVENT2_HAS_OPENSSL

PROD_LIBS += pvxs Com

#===========================

include $(TOP)/configure/RULES
-include $(wildcard $(TOP)/cfg/RULES*)
#----------------------------------------
#  ADD RULES AFTER THIS LINE
