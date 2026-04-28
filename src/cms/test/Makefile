########################################################################
# src/cms/test/Makefile
#
# Makefile fragment included by TOP/src/Makefile when the effective gate
# PVXS_CMS_BUILD_TEST_HARNESS=YES is set.
#
# Builds the static library libpvxsCmsTestHarness.a containing in-process
# test-harness facilities (PkiFixture today; PVACMSHarness/PVACMSCluster
# in subsequent change tasks).
#
# Subordinate to PVXS_ENABLE_PVACMS=YES; never built standalone.
########################################################################

# Allow sources in this directory to be found by basename
SRC_DIRS += $(CMS_TEST_DIR)

# Public headers installed only when the gate is YES
INC += cms/testharness.h

# Build a host-only static library
LIBRARY_HOST += pvxsCmsTestHarness

pvxsCmsTestHarness_SRCS += pkifixture.cpp
pvxsCmsTestHarness_SRCS += initonce.cpp
pvxsCmsTestHarness_SRCS += harness.cpp
pvxsCmsTestHarness_SRCS += testserverbuilder.cpp
pvxsCmsTestHarness_SRCS += observingsource.cpp
pvxsCmsTestHarness_SRCS += clustertopology.cpp
pvxsCmsTestHarness_SRCS += cluster.cpp
pvxsCmsTestHarness_SRCS += statuseventcapture.cpp

# Shared CMS sources the harness needs (mirror pvacms_SRCS minus pvacmsmain.cpp).
# Sources without explicit path are looked up via SRC_DIRS (set in TOP/src/Makefile),
# which already includes COMMON_DIR, AUTHN_DIR, PVACMS_DIR, and CMS_TEST_DIR.
pvxsCmsTestHarness_SRCS += pvacms.cpp
pvxsCmsTestHarness_SRCS += serverhandle.cpp
pvxsCmsTestHarness_SRCS += configcms.cpp
pvxsCmsTestHarness_SRCS += clustertypes.cpp
pvxsCmsTestHarness_SRCS += clustersync.cpp
pvxsCmsTestHarness_SRCS += clusterctrl.cpp
pvxsCmsTestHarness_SRCS += clusterdiscovery.cpp
pvxsCmsTestHarness_SRCS += certfactory.cpp
pvxsCmsTestHarness_SRCS += certfilefactory.cpp
pvxsCmsTestHarness_SRCS += p12filefactory.cpp
pvxsCmsTestHarness_SRCS += certstatus.cpp
pvxsCmsTestHarness_SRCS += certstatusfactory.cpp
pvxsCmsTestHarness_SRCS += certstatusmanager.cpp
pvxsCmsTestHarness_SRCS += configcerts.cpp
pvxsCmsTestHarness_SRCS += wildcardpv.cpp
pvxsCmsTestHarness_SRCS += openssl.cpp
pvxsCmsTestHarness_SRCS += serverev.cpp
pvxsCmsTestHarness_SRCS += auth.cpp
pvxsCmsTestHarness_SRCS += configauthn.cpp
pvxsCmsTestHarness_SRCS += ccrmanager.cpp

pvxsCmsTestHarness_LIBS += pvxs pvxsIoc $(EPICS_BASE_IOC_LIBS)
pvxsCmsTestHarness_SYS_LIBS += sqlite3
