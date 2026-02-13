# Makefile at top of application tree
TOP = .
include $(TOP)/configure/CONFIG

# Directories to build, any order
DIRS += configure

DIRS += setup
setup_DEPEND_DIRS = configure

DIRS += src
src_DEPEND_DIRS = setup

include $(TOP)/configure/RULES_TOP
