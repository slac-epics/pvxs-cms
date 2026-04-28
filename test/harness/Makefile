########################################################################
# test/harness/Makefile
#
# Makefile fragment included by test/Makefile.
#
# This file declares NO build target. It only:
#   1. Adds -I$(HARNESS_DIR) so the harness's local headers (testharness.h,
#      harnessimpl.h, statuseventcapture.h) are findable.
#   2. Adds $(HARNESS_DIR) to SRC_DIRS so harness .cpp files are resolvable
#      by basename.
#   3. Defines the variable HARNESS_SRCS listing every .cpp source needed
#      to compile the in-process CMS test harness (PVACMSHarness /
#      PVACMSCluster / PkiFixture / TestServerBuilder).
#   4. Defines HARNESS_SYS_LIBS listing the system libraries every harness-
#      using test executable must link against.
#
# Each harness-using test executable then pulls these into its own target:
#     <test>_SRCS += $(HARNESS_SRCS)
#     <test>_SYS_LIBS += $(HARNESS_SYS_LIBS)
#
# This is the same pattern testcluster already uses to embed cluster sources
# directly into its target — just with a larger source set hoisted into a
# named variable.
#
# IMPORTANT — this is test infrastructure only:
#   - No library is built; harness sources compile straight into each test
#     executable.
#   - testharness.h is a local header (found via -I$(HARNESS_DIR)); never
#     installed under <install>/include/.
#   - Test executables #include "testharness.h" (local-include form), not
#     <cms/testharness.h>.
#
# Subordinate to PVXS_ENABLE_PVACMS=YES (verified by the enclosing ifeq
# in test/Makefile) and to PVXS_CMS_BUILD_TEST_HARNESS=YES.
########################################################################

# Allow the test executables and the harness's own .cpp files to find
# "testharness.h", "harnessimpl.h", and "statuseventcapture.h".
USR_CPPFLAGS += -I$(HARNESS_DIR)

# Resolve harness sources by basename via SRC_DIRS (test/Makefile already
# adds COMMON_DIR, AUTHN_DIR, PVACMS_DIR for shared-CMS sources).
SRC_DIRS += $(HARNESS_DIR)

# Harness sources (live under test/harness/).
HARNESS_SRCS  = pkifixture.cpp
HARNESS_SRCS += initonce.cpp
HARNESS_SRCS += harness.cpp
HARNESS_SRCS += testserverbuilder.cpp
HARNESS_SRCS += observingsource.cpp
HARNESS_SRCS += clustertopology.cpp
HARNESS_SRCS += cluster.cpp
HARNESS_SRCS += statuseventcapture.cpp

# Shared CMS sources the harness depends on that aren't already in
# test/Makefile's top-level SRCS (configcms, certstatusfactory,
# certstatusmanager, certstatus, configcerts, serverev, wildcardpv are
# added there once and reach every test target automatically).
# Resolved by basename via SRC_DIRS (which includes COMMON_DIR, AUTHN_DIR,
# PVACMS_DIR).
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

# System libraries every harness-using test executable must link against.
# Note: pvxs's own dep file already pulls in event_openssl/event_core/
# event_pthreads/ssl/crypto, so we don't repeat them here (would cause
# "ignoring duplicate libraries" linker warnings on macOS).
HARNESS_SYS_LIBS = sqlite3
