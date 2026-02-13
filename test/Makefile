TOP=..

include $(TOP)/configure/CONFIG
-include $(wildcard $(TOP)/cfg/CONFIG*)
#----------------------------------------
#  ADD MACRO DEFINITIONS AFTER THIS LINE
#=============================

# access to private headers and source
USR_CPPFLAGS += -I$(TOP)/src
USR_CPPFLAGS += -I$(TOP)/ioc

PROD_LIBS = pvxs Com

ifdef BASE_3_15
ifeq ($(EVENT2_HAS_OPENSSL),YES)
USR_CPPFLAGS += -I$(TOP)/certs -I$(TOP)/bundle/CLI11/include
 ifeq (WIN32,$(OS_CLASS))
 # test/ builds some PVXS implementation sources directly.
 # Avoid PVXS_API resolving to dllimport for these definitions.
 USR_CPPFLAGS += -DPVXS_API_BUILDING
 endif
 SRC_DIRS += $(TOP)/certs
  SRC_DIRS += $(TOP)/src/authn
  SRC_DIRS += $(TOP)/src/authn/std
SRC_DIRS += $(TOP)/src
SRCS += configcms.cpp

USR_CPPFLAGS += -DPVXS_ENABLE_OPENSSL

# Retained tests only: testtlswithcms, testtlswithcmsandstapling, testtlsstatus

TESTPROD_HOST += testtlswithcms
testtlswithcms_SRCS += testtlswithcms.cpp
testtlswithcms_SRCS += certstatusfactory.cpp
testtlswithcms_SRCS += certstatusmanager.cpp
testtlswithcms_SRCS += certstatus.cpp
testtlswithcms_SRCS += configcerts.cpp
TESTS += testtlswithcms
TESTFILES += cert_auth.p12 cert_authcert.p12 client1.p12 client2.p12 intermediateCA.p12 ioc1.p12 server1.p12 server2.p12 superserver1.p12

TESTPROD_HOST += testtlswithcmsandstapling
testtlswithcmsandstapling_SRCS += testtlswithcmsandstapling.cpp
testtlswithcmsandstapling_SRCS += certstatusfactory.cpp
testtlswithcmsandstapling_SRCS += certstatusmanager.cpp
testtlswithcmsandstapling_SRCS += certstatus.cpp
testtlswithcmsandstapling_SRCS += configcerts.cpp
TESTS += testtlswithcmsandstapling
TESTFILES += cert_auth.p12 cert_authcert.p12 client1.p12 client2.p12 intermediateCA.p12 ioc1.p12 server1.p12 server2.p12 superserver1.p12

TESTPROD_HOST += testtlsstatus
testtlsstatus_SRCS += testtlsstatus.cpp
testtlsstatus_SRCS += certstatusfactory.cpp
testtlsstatus_SRCS += certstatusmanager.cpp
testtlsstatus_SRCS += certstatus.cpp
testtlsstatus_SRCS += configcerts.cpp
TESTS += testtlsstatus

endif # EVENT2_HAS_OPENSSL
endif

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
rtemsTestData.c : $(TESTFILES) $(TOOLS)/epicsMakeMemFs.pl
	$(PERL) $(TOOLS)/epicsMakeMemFs.pl $@ epicsRtemsFSImage $(TESTFILES)

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

endif
