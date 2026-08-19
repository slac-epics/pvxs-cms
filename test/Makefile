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

TESTS += testpvacmsoptions
TESTPROD_HOST += testpvacmsoptions
testpvacmsoptions_SRCS += testpvacmsoptions.cpp


# Test TLS with Mock CMS and stapling
TESTS += testtlswithcmsandstapling
TESTPROD_HOST += testtlswithcmsandstapling
testtlswithcmsandstapling_SRCS += testtlswithcmsandstapling.cpp

# What a certificate manager makes of the responder its trust anchor names. The responder is
# part of the test and bound to a port the operating system chooses on loopback, so it cannot
# collide with another job or with a demonstration laboratory running on the same machine.
TESTS += testauthoritystatus
TESTPROD_HOST += testauthoritystatus
testauthoritystatus_SRCS += testauthoritystatus.cpp
testauthoritystatus_SRCS += authoritymonitor.cpp
testauthoritystatus_LIBS += pvxsIoc dbRecStd dbCore ca
testauthoritystatus_SYS_LIBS += sqlite3

# Test TLS status operations
TESTS += testtlsstatus
TESTPROD_HOST += testtlsstatus
testtlsstatus_SRCS += testtlsstatus.cpp

# Test the settings the certificate database is opened with. Chiefly the busy
# timeout: without it SQLite reports "database is locked" the instant it meets a
# lock instead of waiting, which stopped the certificate manager from starting.
TESTS += testsqlitehardening
TESTPROD_HOST += testsqlitehardening
testsqlitehardening_SRCS += testsqlitehardening.cpp
testsqlitehardening_SRCS += sqlitehardening.cpp
testsqlitehardening_LIBS += pvxsIoc dbRecStd dbCore ca
testsqlitehardening_SYS_LIBS += sqlite3

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

# Test nested organizational units: the order that carries containment, the two request fields
# that must agree or verification can be bypassed, and the subject entries they become
TESTS += testorgunits
TESTPROD_HOST += testorgunits
# Uses SQL_DUPS_SUBJECT from pvacms.h, whose sql_ptr is behind PVXS_ENABLE_PVACMS.
testorgunits_CPPFLAGS += -DPVXS_ENABLE_PVACMS
testorgunits_SRCS += testorgunits.cpp
testorgunits_SRCS += certsubjectunits.cpp
testorgunits_SRCS += auth.cpp
testorgunits_SRCS += ccrmanager.cpp
testorgunits_SRCS += configauthn.cpp
testorgunits_SRCS += certfactory.cpp
testorgunits_SRCS += certfilefactory.cpp
testorgunits_SRCS += p12filefactory.cpp
testorgunits_SRCS += certrequestid.cpp
testorgunits_SRCS += openssl.cpp
testorgunits_LIBS += pvxsIoc dbRecStd dbCore ca
testorgunits_SYS_LIBS += sqlite3

# Test the certificate listing: the rendering a control room display depends on, and
# that the served result really is a normative table so a display needs no support for it
TESTS += testcertlist
TESTPROD_HOST += testcertlist
testcertlist_SRCS += testcertlist.cpp
testcertlist_SRCS += certlist.cpp
testcertlist_SRCS += certfilter.cpp
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

# Test a keychain holding several trust anchors: which authority mints and which roots the file
# trusts decided apart, the layout the chain is written in, which anchor is the primary one, and
# when the anchors are listed
TESTS += testtrustanchors
TESTPROD_HOST += testtrustanchors
testtrustanchors_SRCS += testtrustanchors.cpp
testtrustanchors_SRCS += auth.cpp
testtrustanchors_SRCS += ccrmanager.cpp
testtrustanchors_SRCS += configauthn.cpp
testtrustanchors_SRCS += certfactory.cpp
testtrustanchors_SRCS += certfilefactory.cpp
testtrustanchors_SRCS += p12filefactory.cpp
testtrustanchors_SRCS += certrequestid.cpp
testtrustanchors_SRCS += openssl.cpp
testtrustanchors_LIBS += pvxsIoc dbRecStd dbCore ca
testtrustanchors_SYS_LIBS += sqlite3

# Test reviewing certificates one at a time: that it writes exactly what was agreed, nothing
# before the confirmation, nothing that moved underneath, and nothing after a cancel
TESTS += testcertreview
TESTPROD_HOST += testcertreview
testcertreview_SRCS += testcertreview.cpp
testcertreview_SRCS += certreview.cpp
testcertreview_SRCS += certfilter.cpp
testcertreview_SRCS += certrequestid.cpp
testcertreview_SRCS += certfactory.cpp
testcertreview_SRCS += certfilefactory.cpp
testcertreview_SRCS += p12filefactory.cpp
testcertreview_SRCS += openssl.cpp
testcertreview_LIBS += pvxsIoc dbRecStd dbCore ca
testcertreview_SYS_LIBS += sqlite3

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
testpvacmsoptions$(EXE): | cert_auth.p12
# reads client1.p12 and client2.p12, so the generated fixtures must exist first
testorgunits$(EXE): | cert_auth.p12
# reads the ta_*.p12 trust anchor fixtures, generated by the same run
testtrustanchors$(EXE): | cert_auth.p12

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
