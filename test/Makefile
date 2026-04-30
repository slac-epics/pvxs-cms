TOP=..

include $(TOP)/configure/CONFIG
-include $(wildcard $(TOP)/cfg/CONFIG*)
#----------------------------------------
#  ADD MACRO DEFINITIONS AFTER THIS LINE
#========================================
COMMON_DIR     = $(TOP)/src/common
AUTHN_DIR      = $(TOP)/src/authn
PVACMS_DIR     = $(TOP)/src/pvacms
AUTHN_STD_DIR  = $(AUTHN_DIR)/std
CLI11_BUNDLE   = $(TOP)/bundle/CLI11
HARNESS_DIR    = $(TOP)/test/harness

PROD_LIBS = pvxs Com

# Tests require PVACMS infrastructure (sqlite3, cert factories, OpenSSL).
# Skip when PVXS_ENABLE_PVACMS=NO (e.g. Windows where sqlite3 is unavailable).
ifdef BASE_3_15
ifeq ($(PVXS_ENABLE_PVACMS),YES)
USR_CPPFLAGS += -I$(COMMON_DIR)
USR_CPPFLAGS += -I$(AUTHN_DIR)
USR_CPPFLAGS += -I$(AUTHN_STD_DIR)
USR_CPPFLAGS += -I$(PVACMS_DIR)
USR_CPPFLAGS += -I$(CLI11_BUNDLE)/include

USR_CPPFLAGS += -I$(TOP)/certs -I$(TOP)/bundle/CLI11/include
USR_CPPFLAGS += -DPVXS_ENABLE_EXPERT_API
USR_CPPFLAGS += -DPVXS_ENABLE_PVACMS

SRC_DIRS += $(COMMON_DIR)
SRC_DIRS += $(AUTHN_DIR)
SRC_DIRS += $(PVACMS_DIR)

# Common sources
SRCS += configcms.cpp
SRCS += certstatusfactory.cpp
SRCS += certstatusmanager.cpp
SRCS += certstatus.cpp
SRCS += configcerts.cpp
SRCS += serverev.cpp
SRCS += wildcardpv.cpp

# Test files
TESTFILES += cert_auth.p12
TESTFILES += cert_authcert.p12
TESTFILES += client1.p12
TESTFILES += client2.p12
TESTFILES += intermediateCA.p12
TESTFILES += ioc1.p12
TESTFILES += server1.p12
TESTFILES += server2.p12
TESTFILES += superserver1.p12

TESTPROD_HOST += gen_test_certs
gen_test_certs_SRCS += gen_test_certs.cpp

# Test TLS status operations
TESTS += testtlsstatus
TESTPROD_HOST += testtlsstatus
testtlsstatus_SRCS += testtlsstatus.cpp



# Test SQLite hardening (WAL, busy_timeout, foreign_keys, schema_version)
TESTS += testsqlitehardening
TESTPROD_HOST += testsqlitehardening
testsqlitehardening_SRCS += testsqlitehardening.cpp
testsqlitehardening_SYS_LIBS += sqlite3

TESTS += testauditlogging
TESTPROD_HOST += testauditlogging
testauditlogging_SRCS += testauditlogging.cpp
testauditlogging_SYS_LIBS += sqlite3

TESTS += testratelimiting
TESTPROD_HOST += testratelimiting
testratelimiting_SRCS += testratelimiting.cpp

TESTS += testadaptivemonitor
TESTPROD_HOST += testadaptivemonitor
testadaptivemonitor_SRCS += testadaptivemonitor.cpp
testadaptivemonitor_SYS_LIBS += sqlite3

TESTS += testhealthcheck
TESTPROD_HOST += testhealthcheck
testhealthcheck_SRCS += testhealthcheck.cpp
testhealthcheck_SYS_LIBS += sqlite3

TESTS += testoperationalmetrics
TESTPROD_HOST += testoperationalmetrics
testoperationalmetrics_SRCS += testoperationalmetrics.cpp
testoperationalmetrics_SYS_LIBS += sqlite3

PROD_HOST += testdatabasebackup
testdatabasebackup_SRCS += testdatabasebackup.cpp
testdatabasebackup_SYS_LIBS += sqlite3
TESTS += testdatabasebackup

TESTS += testvalidityschedules
TESTPROD_HOST += testvalidityschedules
testvalidityschedules_SRCS += testvalidityschedules.cpp
testvalidityschedules_SYS_LIBS += sqlite3

TESTS += testsanccr
TESTPROD_HOST += testsanccr
testsanccr_SRCS += testsanccr.cpp
testsanccr_SYS_LIBS += sqlite3

# CMS test harness sources. See test/harness/Makefile.
# Harness ACF uses SPVA-extended access security keywords (AUTHORITY,
# METHOD, PROTOCOL) that are only present in Michael Davidsaver's
# secure-pvaccess EPICS Base branch.  Probe asLib.h for the SPVA-only
# typedef ASGAUTHORITY: if present, harness tests build; otherwise
# (vanilla R7.0.2, 3.15, etc.) skip them - the ACF parser would reject
# the harness's ACF and asInitFile() would return S_asLib_badConfig.
PVXS_CMS_BUILD_TEST_HARNESS ?= YES
ifeq ($(PVXS_CMS_BUILD_TEST_HARNESS),YES)
SPVA_ASLIB_AVAILABLE := $(shell grep -l ASGAUTHORITY $(EPICS_BASE)/include/asLib.h 2>/dev/null)
ifneq ($(SPVA_ASLIB_AVAILABLE),)
include $(HARNESS_DIR)/Makefile

TESTS += testclustertopology
TESTPROD_HOST += testclustertopology
testclustertopology_SRCS += testclustertopology.cpp
testclustertopology_SRCS += clustertopology.cpp

TESTS += testpkifixture
TESTPROD_HOST += testpkifixture
testpkifixture_SRCS += testpkifixture.cpp
testpkifixture_SRCS += $(HARNESS_SRCS)
testpkifixture_LIBS += pvxsIoc
testpkifixture_SYS_LIBS += $(HARNESS_SYS_LIBS)

TESTS += testharness
TESTPROD_HOST += testharness
testharness_SRCS += testharness.cpp
testharness_SRCS += $(HARNESS_SRCS)
testharness_LIBS += pvxsIoc
testharness_SYS_LIBS += $(HARNESS_SYS_LIBS)

TESTS += testtlswithcmsharness
TESTPROD_HOST += testtlswithcmsharness
testtlswithcmsharness_SRCS += testtlswithcmsharness.cpp
testtlswithcmsharness_SRCS += $(HARNESS_SRCS)
testtlswithcmsharness_LIBS += pvxsIoc
testtlswithcmsharness_SYS_LIBS += $(HARNESS_SYS_LIBS)

TESTS += testclusterharness
TESTPROD_HOST += testclusterharness
testclusterharness_SRCS += testclusterharness.cpp
testclusterharness_SRCS += $(HARNESS_SRCS)
testclusterharness_LIBS += pvxsIoc
testclusterharness_SYS_LIBS += $(HARNESS_SYS_LIBS)

TESTS += testclusterbehaviour
TESTPROD_HOST += testclusterbehaviour
testclusterbehaviour_SRCS += testclusterbehaviour.cpp
testclusterbehaviour_SRCS += $(HARNESS_SRCS)
testclusterbehaviour_LIBS += pvxsIoc
testclusterbehaviour_SYS_LIBS += $(HARNESS_SYS_LIBS)

TESTS += testtlsstaplingharness
TESTPROD_HOST += testtlsstaplingharness
testtlsstaplingharness_SRCS += testtlsstaplingharness.cpp
testtlsstaplingharness_SRCS += $(HARNESS_SRCS)
testtlsstaplingharness_LIBS += pvxsIoc
testtlsstaplingharness_SYS_LIBS += $(HARNESS_SYS_LIBS)

TESTS += testtlswithcmsmigrated
TESTPROD_HOST += testtlswithcmsmigrated
testtlswithcmsmigrated_SRCS += testtlswithcmsmigrated.cpp
testtlswithcmsmigrated_SRCS += $(HARNESS_SRCS)
testtlswithcmsmigrated_LIBS += pvxsIoc
testtlswithcmsmigrated_SYS_LIBS += $(HARNESS_SYS_LIBS)

TESTS += testdisconnectresilience
TESTPROD_HOST += testdisconnectresilience
testdisconnectresilience_SRCS += testdisconnectresilience.cpp
testdisconnectresilience_SRCS += $(HARNESS_SRCS)
testdisconnectresilience_LIBS += pvxsIoc
testdisconnectresilience_SYS_LIBS += $(HARNESS_SYS_LIBS)

TESTS += testclustergatewayresilience
TESTPROD_HOST += testclustergatewayresilience
testclustergatewayresilience_SRCS += testclustergatewayresilience.cpp
testclustergatewayresilience_SRCS += $(HARNESS_SRCS)
testclustergatewayresilience_LIBS += pvxsIoc
testclustergatewayresilience_SYS_LIBS += $(HARNESS_SYS_LIBS)
endif # SPVA_ASLIB_AVAILABLE
endif # PVXS_CMS_BUILD_TEST_HARNESS

endif # PVXS_ENABLE_PVACMS
endif # BASE_3_15

TESTSCRIPTS_HOST += $(TESTS:%=%.t)
ifdef BASE_3_15
ifneq ($(filter $(T_A),$(CROSS_COMPILER_RUNTEST_ARCHS)),)
TESTPROD = $(TESTPROD_HOST)
TESTSCRIPTS = $(TESTSCRIPTS_HOST)
endif
endif

#===========================

include $(TOP)/configure/RULES
-include $(wildcard $(TOP)/cfg/RULES*)
#----------------------------------------
#  ADD RULES AFTER THIS LINE

ifdef BASE_3_15
ifeq ($(EVENT2_HAS_OPENSSL),YES)
testtlsstatus$(EXE): | cert_auth.p12

# generate test certs only with EPICS_HOST_ARCH
ifdef T_A
cert_auth.p12 :
	$(RM) *.p12
	../O.$(EPICS_HOST_ARCH)/gen_test_certs$(HOSTEXE) -O .
ifeq ($(T_A),$(EPICS_HOST_ARCH))
cert_auth.p12 : gen_test_certs$(HOSTEXE)
endif # T_A==EPICS_HOST_ARCH
endif # T_A
endif # EVENT2_HAS_OPENSSL
endif # BASE_3_15
