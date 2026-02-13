########################################################################
# src/tools/Makefile
#
# Makefile fragment included by TOP/src/Makefile.
#
# Purpose:
#   Aggregate host-side command line tools built by this module.
#   Each tool lives in its own subdirectory under src/tools/ and has its own
#   Makefile fragment which defines:
#     - PROD += <tool>
#     - <tool>_SRCS, <tool>_LIBS, <tool>_SYS_LIBS
#
# Notes:
#   - This file is a fragment: it inherits variables/flags from TOP/src/Makefile.
#   - Do NOT include configure/CONFIG or configure/RULES here.
#   - Add new tools by creating src/tools/<toolname>/Makefile and including it
#     below.
########################################################################

TOOLS_DIR = $(TOP)/src/tools

# Tool: pvxcert (certificate management utility)
include $(TOOLS_DIR)/pvxcert/Makefile
