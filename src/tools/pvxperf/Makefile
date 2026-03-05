########################################################################
# src/tools/pvxperf/Makefile
#
# Makefile fragment included by TOP/src/tools/Makefile.
#
# Defines the "pvxperf" host executable — a performance benchmarking
# tool for CA, PVA, SPVA, and SPVA+CERTMON protocol modes.
#
# Requires a modern EPICS Base (7.0-secure-pvaccess or similar) for
# base.dbd compatibility.  Disable on older bases by setting
# PVXS_ENABLE_PVXPERF=NO in EXTRA or CONFIG_SITE.local.
########################################################################

PVXPERF_DIR = $(TOOLS_DIR)/pvxperf

# Default to YES; older bases should override to NO.
PVXS_ENABLE_PVXPERF ?= YES

# pvxperf uses fork/exec (POSIX-only) — skip on Windows and cross targets
ifneq ($(OS_CLASS),WIN32)
ifeq ($(BUILD_CLASS),HOST)
ifeq ($(PVXS_ENABLE_PVXPERF),YES)

SRC_DIRS += $(PVXPERF_DIR)

PROD += pvxperf

# DBD processing: merge base.dbd so the build system generates
# pvxperf_registerRecordDeviceDriver.cpp with record/device/driver
# registration for the embedded CA IOC.
pvxperf_DBD += base.dbd
pvxperf_SRCS += pvxperf_registerRecordDeviceDriver.cpp

pvxperf_SRCS += pvxperf.cpp

# Bake in EPICS_BASE path for locating softIoc.dbd at runtime
pvxperf_CPPFLAGS += -DPVXPERF_EPICS_BASE=\"$(abspath $(EPICS_BASE))\"

pvxperf_LIBS += pvxs Com ca dbCore dbRecStd

endif # PVXS_ENABLE_PVXPERF
endif # HOST
endif # !WIN32
