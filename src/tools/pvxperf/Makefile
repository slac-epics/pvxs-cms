########################################################################
# src/tools/pvxperf/Makefile
#
# Makefile fragment included by TOP/src/tools/Makefile.
#
# Defines the "pvxperf" host executable — a performance benchmarking
# tool for CA, PVA, SPVA, and SPVA+CERTMON protocol modes.
########################################################################

PVXPERF_DIR = $(TOOLS_DIR)/pvxperf

# pvxperf uses fork/exec (POSIX-only) — skip on Windows
ifneq ($(OS_CLASS),WIN32)

SRC_DIRS += $(PVXPERF_DIR)

PROD += pvxperf

pvxperf_SRCS += pvxperf.cpp

# Bake in EPICS_BASE path for locating softIoc.dbd at runtime
pvxperf_CPPFLAGS += -DPVXPERF_EPICS_BASE=\"$(abspath $(EPICS_BASE))\"

pvxperf_LIBS += pvxs Com ca dbCore dbRecStd

endif # !WIN32
