# This is a Makefile fragment, see src/authn/Makefile.

SRC_DIRS += $(AUTHN)/ldap

PROD += authnldap
authnldap_SRCS += authnldap.cpp
authnldap_SRCS += authnldapmain.cpp
authnldap_SRCS += configldap.cpp
authnldap_SRCS += certstatusfactory.cpp
authnldap_SRCS += certstatus.cpp
authnldap_SRCS += certstatusmanager.cpp
authnldap_SRCS += certfactory.cpp
authnldap_SRCS += certfilefactory.cpp
authnldap_SRCS += p12filefactory.cpp
authnldap_SRCS += auth.cpp
authnldap_SRCS += configauthn.cpp
authnldap_SRCS += ccrmanager.cpp

pvacms_SRCS += authnldap.cpp
pvacms_SRCS += configldap.cpp

authnldap_LIBS += pvxs Com

authnldap_SYS_LIBS += ldap lber
pvacms_SYS_LIBS += ldap lber
