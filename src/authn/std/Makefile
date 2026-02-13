# This is a Makefile fragment, see src/authn/Makefile.

SRC_DIRS += $(AUTHN_STD_DIR)

PROD += authnstd
authnstd_SRCS += authnstd.cpp
authnstd_SRCS += authnstdmain.cpp
authnstd_SRCS += configstd.cpp
authnstd_SRCS += certstatusfactory.cpp
authnstd_SRCS += certstatus.cpp
authnstd_SRCS += certstatusmanager.cpp
authnstd_SRCS += certfactory.cpp
authnstd_SRCS += certfilefactory.cpp
authnstd_SRCS += p12filefactory.cpp
authnstd_SRCS += auth.cpp
authnstd_SRCS += configauthn.cpp
authnstd_SRCS += ccrmanager.cpp

pvacms_SRCS += authnstd.cpp
pvacms_SRCS += configstd.cpp

# Default libraries for this authenticator executable.
# (pvacms and tools have their own *_LIBS settings.)
authnstd_LIBS += pvxs Com
authnstd_SYS_LIBS +=
