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

PROD_LIBS = pvxs Com

# Tests require PVACMS infrastructure (sqlite3, cert factories, OpenSSL).
# Skip when PVXS_ENABLE_PVACMS=NO (e.g. Windows where sqlite3 is unavailable).
ifdef BASE_3_15
ifeq ($(PVXS_ENABLE_PVACMS),YES)
USR_CPPFLAGS += -I$(COMMON_DIR)
USR_CPPFLAGS += -I$(AUTHN_DIR)
USR_CPPFLAGS += -I$(AUTHN_STD_DIR)
USR_CPPFLAGS += -I$(CLI11_BUNDLE)/include

USR_CPPFLAGS += -I$(TOP)/certs -I$(TOP)/bundle/CLI11/include
USR_CPPFLAGS += -DPVXS_ENABLE_EXPERT_API

SRC_DIRS += $(COMMON_DIR)
SRC_DIRS += $(AUTHN_DIR)
SRC_DIRS += $(PVACMS_DIR)
SRC_DIRS += $(TOP)/src/tools/pvxcert

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

# Federated-lab certificate hierarchy generator (example/kubernetes federated lab).
# Mints one facility Root + a Controls (Lab) intermediate + an ML intermediate.
TESTPROD_HOST += gen_lab_certs
gen_lab_certs_SRCS += gen_lab_certs.cpp

# Test TLS with Mock CMS
TESTS += testtlswithcms
TESTPROD_HOST += testtlswithcms
testtlswithcms_SRCS += testtlswithcms.cpp


# Test TLS with Mock CMS and stapling
TESTS += testtlswithcmsandstapling
TESTPROD_HOST += testtlswithcmsandstapling
testtlswithcmsandstapling_SRCS += testtlswithcmsandstapling.cpp

# Test TLS status operations
TESTS += testtlsstatus
TESTPROD_HOST += testtlsstatus
testtlsstatus_SRCS += testtlsstatus.cpp

# Test the certificate request identifier: the identifier itself, the package built around
# it, the table it is stored in, and the substituted-key case it exists to make visible
TESTS += testcertrequestid
TESTPROD_HOST += testcertrequestid
testcertrequestid_SRCS += testcertrequestid.cpp
testcertrequestid_SRCS += certrequestid.cpp
testcertrequestid_SRCS += certfactory.cpp
testcertrequestid_SRCS += certfilefactory.cpp
testcertrequestid_SRCS += p12filefactory.cpp
testcertrequestid_SRCS += openssl.cpp
testcertrequestid_LIBS += pvxsIoc dbRecStd dbCore ca
testcertrequestid_SYS_LIBS += sqlite3

# Test the settings the certificate database is opened with. Chiefly the busy
# timeout: without it SQLite reports "database is locked" the instant it meets a
# lock instead of waiting, which stopped the certificate manager from starting.
TESTS += testsqlitehardening
TESTPROD_HOST += testsqlitehardening
testsqlitehardening_SRCS += testsqlitehardening.cpp
testsqlitehardening_SRCS += sqlitehardening.cpp
testsqlitehardening_LIBS += pvxsIoc dbRecStd dbCore ca
testsqlitehardening_SYS_LIBS += sqlite3

# Test the certificate listing: the rendering a control room display depends on, and
# that the served result really is a normative table so a display needs no support for it
TESTS += testcertlist
TESTPROD_HOST += testcertlist
testcertlist_SRCS += testcertlist.cpp
testcertlist_SRCS += certlist.cpp
testcertlist_SRCS += certlistprint.cpp
testcertlist_LIBS += pvxsIoc dbRecStd dbCore ca
testcertlist_SYS_LIBS += sqlite3

# Test the filter expression: how the words bind, what happens when the query cannot express
# a test, and what an operator is told when they get it wrong
TESTS += testcertfilter
TESTPROD_HOST += testcertfilter
testcertfilter_SRCS += testcertfilter.cpp
testcertfilter_SRCS += certfilter.cpp
testcertfilter_LIBS += pvxsIoc dbRecStd dbCore ca
testcertfilter_SYS_LIBS += sqlite3

# Test cluster functionality
TESTS += testcluster
TESTPROD_HOST += testcluster
testcluster_SRCS += testcluster.cpp
testcluster_SRCS += clustertypes.cpp
testcluster_SRCS += clustersync.cpp
testcluster_SRCS += clusterctrl.cpp
testcluster_SRCS += clusterdiscovery.cpp
testcluster_SRCS += certfactory.cpp
testcluster_SRCS += p12filefactory.cpp
testcluster_SRCS += certfilefactory.cpp
testcluster_SRCS += openssl.cpp
testcluster_LIBS += pvxsIoc dbRecStd dbCore ca
testcluster_SYS_LIBS += sqlite3

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
testtlswithcms$(EXE): | cert_auth.p12

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
