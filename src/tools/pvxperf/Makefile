########################################################################
# src/tools/pvxperf/Makefile
#
# Makefile fragment included by TOP/src/tools/Makefile.
#
# Defines the "pvxperf" host executable — a performance benchmarking
# tool for CA, PVA, SPVA, and SPVA+CERTMON protocol modes.
########################################################################

PVXPERF_DIR = $(TOOLS_DIR)/pvxperf

# pvxperf uses fork/exec (POSIX-only) — skip on Windows and cross targets
ifneq ($(OS_CLASS),WIN32)
ifeq ($(BUILD_CLASS),HOST)

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

endif # HOST
endif # !WIN32
