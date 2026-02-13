# This is a Makefile fragment, see src/authn/Makefile.

SRC_DIRS += $(AUTHN)/krb

PROD += authnkrb
authnkrb_SRCS += authnkrb.cpp
authnkrb_SRCS += authnkrbmain.cpp
authnkrb_SRCS += configkrb.cpp
authnkrb_SRCS += certstatusfactory.cpp
authnkrb_SRCS += certstatus.cpp
authnkrb_SRCS += certstatusmanager.cpp
authnkrb_SRCS += certfactory.cpp
authnkrb_SRCS += certfilefactory.cpp
authnkrb_SRCS += p12filefactory.cpp
authnkrb_SRCS += auth.cpp
authnkrb_SRCS += configauthn.cpp
authnkrb_SRCS += ccrmanager.cpp

pvacms_SRCS += authnkrb.cpp
pvacms_SRCS += configkrb.cpp

authnkrb_LIBS += pvxs Com

# Detect the operating system
UNAME_S := $(shell uname -s)

# Set platform-specific krb libs
ifeq ($(UNAME_S), Darwin)
    # macOS
	authnkrb_LDFLAGS += -framework GSS
	pvacms_LDFLAGS += -framework GSS
else
    # MIT Kerberos
	authnkrb_SYS_LIBS += gssapi_krb5 krb5 k5crypto com_err
	pvacms_SYS_LIBS += gssapi_krb5 krb5 k5crypto com_err
endif
