########################################################################
# src/tools/pvxcert/Makefile
#
# Makefile fragment included by TOP/src/tools/Makefile.
#
# Defines the "pvxcert" host executable.
########################################################################

PVXCERT_DIR = $(TOOLS_DIR)/pvxcert

SRC_DIRS += $(PVXCERT_DIR)

PROD += pvxcert

# Main entrypoint for the tool
pvxcert_SRCS += pvxcert.cpp

# Shared CMS/cert implementation sources (from src/common/)
pvxcert_SRCS += p12filefactory.cpp
pvxcert_SRCS += certfilefactory.cpp
pvxcert_SRCS += certfactory.cpp
pvxcert_SRCS += certstatus.cpp
pvxcert_SRCS += certstatusmanager.cpp

# Link dependencies
pvxcert_LIBS += pvxs Com
