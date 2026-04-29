# test/harness/Makefile — fragment included by test/Makefile.
#
# Defines variables HARNESS_SRCS and HARNESS_SYS_LIBS so each harness-using
# test pulls them into its target via:
#     <test>_SRCS += $(HARNESS_SRCS)
#     <test>_SYS_LIBS += $(HARNESS_SYS_LIBS)
# No library is produced.

USR_CPPFLAGS += -I$(HARNESS_DIR)
SRC_DIRS += $(HARNESS_DIR)

# Probe pvxs's installed config.h for tls_status_cache_dir.  This field
# is on pvxs-tls/dev but not yet merged to pvxs-tls/tls (the working
# branch the production cluster links against).  Define
# PVXS_HAS_TLS_STATUS_CACHE_DIR when the field is present so harness
# sources can opt in to per-role cache isolation; otherwise they fall
# back to the default shared cache (no isolation, but tests still work).
ifneq ($(wildcard $(PVXS)/include/pvxs/config.h),)
PVXS_HAS_TLS_STATUS_CACHE_DIR := $(shell grep -l tls_status_cache_dir $(PVXS)/include/pvxs/config.h 2>/dev/null)
ifneq ($(PVXS_HAS_TLS_STATUS_CACHE_DIR),)
USR_CPPFLAGS += -DPVXS_HAS_TLS_STATUS_CACHE_DIR
endif
endif

HARNESS_SRCS  = pkifixture.cpp
HARNESS_SRCS += initonce.cpp
HARNESS_SRCS += harness.cpp
HARNESS_SRCS += testserverbuilder.cpp
HARNESS_SRCS += observingsource.cpp
HARNESS_SRCS += clustertopology.cpp
HARNESS_SRCS += cluster.cpp
HARNESS_SRCS += statuseventcapture.cpp

# Shared CMS sources from src/. Resolved by basename via SRC_DIRS
# (test/Makefile adds COMMON_DIR, AUTHN_DIR, PVACMS_DIR).
HARNESS_SRCS += pvacms.cpp
HARNESS_SRCS += serverhandle.cpp
HARNESS_SRCS += clustertypes.cpp
HARNESS_SRCS += clustersync.cpp
HARNESS_SRCS += clusterctrl.cpp
HARNESS_SRCS += clusterdiscovery.cpp
HARNESS_SRCS += certfactory.cpp
HARNESS_SRCS += certfilefactory.cpp
HARNESS_SRCS += p12filefactory.cpp
HARNESS_SRCS += openssl.cpp
HARNESS_SRCS += auth.cpp
HARNESS_SRCS += configauthn.cpp
HARNESS_SRCS += ccrmanager.cpp

# pvxs's dep file already pulls in event_openssl/event_core/event_pthreads/
# ssl/crypto. Don't duplicate or macOS warns "ignoring duplicate libraries".
HARNESS_SYS_LIBS = sqlite3
