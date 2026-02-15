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

ifdef BASE_3_15
USR_CPPFLAGS += -I$(COMMON_DIR)
USR_CPPFLAGS += -I$(AUTHN_DIR)
USR_CPPFLAGS += -I$(AUTHN_STD_DIR)
USR_CPPFLAGS += -I$(CLI11_BUNDLE)/include
USR_CPPFLAGS += -I$(COMMON_DIR)/serverev

USR_CPPFLAGS += -I$(TOP)/certs -I$(TOP)/bundle/CLI11/include

SRC_DIRS += $(COMMON_DIR)
SRC_DIRS += $(AUTHN_DIR)
SRC_DIRS += $(PVACMS_DIR)
SRC_DIRS += $(COMMON_DIR)/serverev

# Common sources
SRCS += configcms.cpp
SRCS += certstatusfactory.cpp
SRCS += certstatusmanager.cpp
SRCS += certstatus.cpp
SRCS += configcerts.cpp
SRCS += serverev.cpp
SRCS += wildcardpv.cpp

# Common flags
USR_CPPFLAGS += -DPVXS_ENABLE_OPENSSL

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
